#!/usr/bin/python3
"""Owner-run read-only evidence collector. Never imports installed application code.

Only stdout is written. No service actions, migrations, backups or anchor updates.
Exit 2 means evidence is incomplete or an integrity check failed.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit, unquote

SAFE = re.compile(r"[A-Za-z0-9_.-]{1,160}\Z")
UNITS = ('serverhub-ai-api.service', 'serverhub-ai-worker.service',
         'serverhub-ai-broker.service', 'serverhub-ai-recovery.service', 'serverhub-ai-recovery.timer',
         'serverhub-broker.service', 'serverhub-docker-ro.service', 'serverhub-worker.service')
PROPERTIES = ('Id', 'User', 'Group', 'MainPID', 'ActiveState', 'SubState',
              'ExecMainStartTimestampMonotonic', 'FragmentPath', 'DropInPaths',
              'Type', 'Restart', 'Result', 'ExecMainStatus', 'TriggeredBy', 'Triggers', 'LoadState')
BASELINE_SHA256 = 'ed190340536e68d586112cf40ca84c4191d0413f62e676c53d189d0bfd44176a'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sealed(path):
    """Require root-controlled ancestors, disallow symlinks and special files."""
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsealed path')
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('special file')
    return path


def hashes(root, pattern='*'):
    sealed(root)
    result = {}
    for path in sorted(root.rglob(pattern)):
        if '__pycache__' in path.parts or path.suffix == '.pyc':
            continue
        if path.is_symlink():
            raise ValueError('tree symlink')
        if path.is_file():
            sealed(path)
            result[str(path.relative_to(root))] = digest(path)
    if not result:
        raise ValueError('empty tree')
    return result


def run(argv, env=None):
    completed = subprocess.run(argv, env=env or {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                               capture_output=True, text=True, timeout=30, check=False)
    if completed.returncode:
        # Never include stdout/stderr: database errors can disclose secrets.
        raise ValueError('read command failed')
    return completed.stdout


def services():
    result = {}
    for unit in UNITS:
        raw = run(['/usr/bin/systemctl', 'show', unit, '--no-pager',
                   '--property=' + ','.join(PROPERTIES)])
        values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
        files = {}
        for name in (values.get('FragmentPath', '') + ' ' + values.get('DropInPaths', '')).split():
            path = sealed(Path(name))
            files[name] = digest(path)
        result[unit] = {'properties': values, 'file_hashes': files}
    return result


def recovery_baseline():
    path = Path(__file__).with_name('attestation-recovery-baseline.json')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != BASELINE_SHA256:
        raise ValueError('reviewed recovery baseline digest mismatch')
    return json.loads(data)


def stable_services(before, after, baseline):
    if set(before) != set(UNITS) or set(after) != set(UNITS):
        return False
    service = 'serverhub-ai-recovery.service'
    timer = 'serverhub-ai-recovery.timer'
    for snapshot in (before, after):
        for unit in (service, timer):
            entry = snapshot[unit]
            props = entry['properties']
            fragment = props.get('FragmentPath')
            if (props.get('LoadState') != 'loaded' or props.get('DropInPaths')
                    or entry['file_hashes'] != {fragment: baseline['units'][unit]}):
                return False
        props = snapshot[service]['properties']
        if (props.get('Type') != 'oneshot' or props.get('Restart') != 'no'
                or props.get('Result') != 'success' or props.get('ExecMainStatus') != '0'
                or props.get('User') != 'root' or props.get('TriggeredBy') != timer
                or (props.get('ActiveState'), props.get('SubState')) not in
                {('inactive', 'dead'), ('activating', 'start')}):
            return False
        props = snapshot[timer]['properties']
        if (props.get('ActiveState') != 'active' or props.get('SubState') not in ('waiting', 'running')
                or props.get('Triggers') != service):
            return False
    volatile = {'MainPID', 'ExecMainStartTimestampMonotonic', 'ActiveState', 'SubState'}
    for unit in UNITS:
        if unit not in (service, timer):
            if before[unit] != after[unit]:
                return False
        else:
            for field in ('properties', 'file_hashes'):
                excluded = volatile if field == 'properties' else set()
                if ({k: v for k, v in before[unit][field].items() if k not in excluded}
                        != {k: v for k, v in after[unit][field].items() if k not in excluded}):
                    return False
    return True


def watchdog_errors(since):
    # Catch failures between two successful samples; never emit journal messages.
    raw = run(['/usr/bin/journalctl', '--unit=serverhub-ai-recovery.service',
               '--since=' + since, '--no-pager', '--output=json'])
    count = 0
    for line in raw.splitlines():
        entry = json.loads(line)
        failed = entry.get('SERVICE_RESULT', 'success') != 'success'
        failed = failed or entry.get('UNIT_RESULT', 'success') != 'success'
        priority = entry.get('PRIORITY', '6')
        if not isinstance(priority, str) or not priority.isdigit():
            raise ValueError('invalid journal priority')
        count += bool(failed or int(priority) <= 3)
    return {'errors_observed': count}


def schema():
    # Use the existing API identity, never the migration/database administrator role.
    content = sealed(Path('/etc/serverhub/api.env')).read_text()
    lines = [line.split('=', 1)[1].strip().strip("'\"") for line in content.splitlines()
             if line.startswith('SERVERHUB_DATABASE_URL=')]
    if len(lines) != 1:
        raise ValueError('database configuration unavailable')
    url = urlsplit(lines[0])
    if url.scheme != 'postgresql+psycopg' or url.username != 'serverhub_api' or url.query:
        raise ValueError('unsupported database configuration')
    if url.hostname not in ('127.0.0.1', 'localhost', '::1') or url.path != '/serverhub':
        raise ValueError('nonlocal database')
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PGHOST': url.hostname,
           'PGPORT': str(url.port or 5432), 'PGUSER': 'serverhub_api',
           'PGDATABASE': 'serverhub', 'PGPASSWORD': unquote(url.password or ''),
           'PGCONNECT_TIMEOUT': '5',
           'PGOPTIONS': '-c default_transaction_read_only=on -c statement_timeout=5000'}
    value = run(['/usr/bin/psql', '-X', '-w', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                 '-c', 'SELECT version_num FROM public.alembic_version'], env).strip()
    if not SAFE.fullmatch(value):
        raise ValueError('invalid schema result')
    return {'revision': value, 'role': 'serverhub_api', 'read_only': True}


def runtime(root, anchor):
    sites = list((root / 'venv/lib').glob('python*/site-packages'))
    if len(sites) != 1:
        raise ValueError('ambiguous runtime')
    code = hashes(sites[0] / 'serverhub', '*.py')
    expected = anchor['files']
    actual = {'serverhub/' + key: value for key, value in code.items()}
    return {'code_hashes': actual, 'matches_code_anchor': actual == expected,
            'dependency_tree_hashes': hashes(sites[0])}


def collect():
    since = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    report = {'format': 1, 'observed_at': datetime.now(timezone.utc).isoformat(),
              'production_install_authorized': False, 'errors': [],
              'limitations': ['Local root is the trust boundary; this is not remote attestation.',
                             'Control history requires comparison with an independently trusted baseline.',
                             'Dependency hashes require comparison with reviewed release artifacts.',
                             'No backup or restore was performed.']}
    def check(name, operation):
        try:
            report[name] = operation()
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            report['errors'].append(name + ': evidence unavailable or unsafe; inspect locally')
    check('recovery_baseline', recovery_baseline)
    check('services_before', services)
    check('control_tree_before', lambda: hashes(Path('/opt/serverhub-control'), '*.py'))
    def release():
        link = Path('/opt/serverhub/current')
        sealed(link.parent)
        if link.lstat().st_uid != 0:
            raise ValueError('current link ownership')
        root = link.resolve(strict=True)
        if root.parent != Path('/opt/serverhub/releases'):
            raise ValueError('release outside expected directory')
        sealed(root)
        manifest = json.loads(sealed(root / 'installed.json').read_text())['manifest']
        identity = manifest['release_id']
        if not isinstance(identity, str) or not SAFE.fullmatch(identity):
            raise ValueError('invalid release identity')
        anchor_path = sealed(Path('/etc/serverhub/trusted-code-hashes.json'))
        anchor = json.loads(anchor_path.read_text())
        if anchor.get('format') != 1 or not anchor.get('files'):
            raise ValueError('invalid code anchor')
        anchors = {}
        for name in ('trusted-code-hashes.json', 'trust-boundaries.json', 'trust-boundaries.sha256'):
            anchors[name] = digest(sealed(Path('/etc/serverhub') / name))
        trust = sealed(Path('/etc/serverhub/trust-boundaries.sha256')).read_text().strip()
        return {'path': str(root), 'release_id': identity,
                'installed_manifest_sha256': digest(root / 'installed.json'),
                'trust_hashes': anchors,
                'manifest_trust_matches_anchor': manifest.get('trust_boundary_digest') == trust,
                'directory_matches_release_id': root.name == identity,
                'active': runtime(root, anchor),
                'recovery': runtime(Path('/opt/serverhub/recovery-ai'), recovery_baseline()),
                'watchdog_sha256': digest(sealed(Path('/opt/serverhub/recovery-ai/operation_watchdog.py'))),
                'migrations': hashes(root / 'migrations'), 'web': hashes(root / 'web')}
    check('release', release)
    check('database', schema)
    check('services_after', services)
    check('control_tree_after', lambda: hashes(Path('/opt/serverhub-control'), '*.py'))
    check('watchdog_journal', lambda: watchdog_errors(since))
    report['stable_observation'] = bool(
        'services_before' in report and 'services_after' in report
        and 'recovery_baseline' in report
        and stable_services(report['services_before'], report['services_after'], report['recovery_baseline'])
        and report.get('watchdog_journal', {}).get('errors_observed') == 0
        and 'control_tree_before' in report
        and report['control_tree_before'] == report.get('control_tree_after'))
    release_result = report.get('release', {})
    report['local_integrity_checks_passed'] = bool(
        not report['errors'] and report['stable_observation']
        and release_result.get('manifest_trust_matches_anchor')
        and release_result.get('directory_matches_release_id')
        and release_result.get('active', {}).get('matches_code_anchor')
        and release_result.get('recovery', {}).get('matches_code_anchor')
        and release_result.get('watchdog_sha256') == report.get('recovery_baseline', {}).get('watchdog_sha256'))
    return report


if __name__ == '__main__':
    if os.geteuid() != 0 or len(sys.argv) != 1:
        sys.exit('Run with sudo /usr/bin/python3 -I attest-production.py (no arguments).')
    result = collect()
    print(json.dumps(result, sort_keys=True, indent=2))
    sys.exit(0 if result['local_integrity_checks_passed'] else 2)
