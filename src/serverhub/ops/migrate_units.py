"""Explicit local-root conversion of proven legacy AI OS units, with rollback.

This is deliberately not a tool exposed to AI or MCP. Control units are foreign:
matching names alone never qualify a service for migration.
"""
from __future__ import annotations

import argparse
import base64
import json
import hashlib
import os
from pathlib import Path
import subprocess
import time
import tempfile
import shutil
import pwd
import grp
import re

from .coexistence import CLAIM, ConflictError, protected, write_claim, valid_dropin
from .installer import Installer, ACCOUNTS as INSTALL_ACCOUNTS

JOURNAL = Path('/var/lib/serverhub-install/unit-migration.json')


def legacy_resources(text):
    """Reverse only identity/path tokens; unit names have a separate migration."""
    for role in ('api', 'worker', 'node', 'migrate', 'staging'):
        text = re.sub(r'serverhub-ai-' + role + r'(?![\w-]|\.service|\.timer)',
                      'serverhub-' + role, text)
    return text.replace('serverhub-ai-stage-runtime', 'serverhub-stage-runtime').replace(
        'serverhub-ai-stage-data', 'serverhub-stage-data').replace('serverhub-ai-build', 'serverhub-build')


def valid_legacy_dropin(unit, name, text):
    normalized = text
    for role in ('api', 'worker', 'node', 'migrate', 'staging'):
        normalized = re.sub(r'serverhub-' + role + r'(?![\w-]|\.service|\.timer)',
                            'serverhub-ai-' + role, normalized)
    normalized = normalized.replace('/run/serverhub-broker', '/run/serverhub-ai-broker')
    return valid_dropin(unit, name, normalized)


def previous_claim(root):
    from .coexistence import PATHS, ACCOUNTS
    path = root / CLAIM.lstrip('/')
    if not path.exists():
        return None
    protected(path)
    value = json.loads(path.read_text())
    expected = {'product': 'serverhub-ai-os', 'namespace': 2,
                'paths': [legacy_resources(x) for x in PATHS],
                'accounts': [legacy_resources(x) for x in ACCOUNTS]}
    if value != expected:
        raise ConflictError('Only exact namespace-2 ownership can be explicitly migrated; do not delete the claim')
    return value


def identity_plan(root):
    """Never usermod an old account; verify provenance and create new identities."""
    if root != Path('/'):
        return []
    result = []
    try:
        optional = pwd.getpwnam('serverhub-ai')
        if (optional.pw_dir != '/var/lib/serverhub-ai' or optional.pw_uid == 0
                or optional.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin')
                or grp.getgrnam('serverhub-ai').gr_gid != optional.pw_gid
                or set(os.getgrouplist('serverhub-ai', optional.pw_gid)) != {optional.pw_gid}):
            raise ConflictError('Foreign optional serverhub-ai identity; no adoption')
        drops = [Path('/etc/systemd/system', name + '.service.d/10-ai-identity.conf')
                 for name in ('serverhub-worker', 'serverhub-ai-worker')]
        if not any(path.is_file() and path.read_text() == '[Service]\nUser=serverhub-ai\nGroup=serverhub-worker\n' for path in drops):
            raise ConflictError('Optional serverhub-ai identity has no proven legacy worker assignment')
        optional_uids = (optional.pw_uid,)
    except KeyError:
        optional_uids = ()
    for new, home in INSTALL_ACCOUNTS.items():
        old, old_home = legacy_resources(new), legacy_resources(home)
        try:
            entry = pwd.getpwnam(old)
            group = grp.getgrnam(old)
        except KeyError as error:
            raise ConflictError('Missing legacy service identity; explicit review required: ' + old) from error
        if (entry.pw_uid == 0 or entry.pw_dir != old_home
                or entry.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin')
                or entry.pw_gid != group.gr_gid or group.gr_mem
                or set(os.getgrouplist(old, entry.pw_gid)) != {entry.pw_gid}):
            raise ConflictError('Legacy identity is foreign/shared; never modify or adopt: ' + old)
        for kind, lookup in [('user', pwd.getpwnam), ('group', grp.getgrnam)]:
            try:
                lookup(new)
            except KeyError:
                continue
            raise ConflictError('New identity namespace occupied: ' + kind + ' ' + new)
        if Path(home).exists() or Path(home).is_symlink():
            raise ConflictError('New identity data path occupied: ' + home)
        source = Path(old_home)
        if source.is_symlink() or not source.is_dir():
            raise ConflictError('Legacy identity data path missing or symlinked: ' + old_home)
        protected(source, leaf_uids=(entry.pw_uid, *optional_uids))
        result.append({'old': old, 'new': new, 'source': old_home, 'destination': home,
                       'old_uid': entry.pw_uid, 'old_gid': entry.pw_gid})
    required = sum(p.lstat().st_size for item in result for p in Path(item['source']).rglob('*') if p.is_file() and not p.is_symlink())
    if shutil.disk_usage('/var/lib').free < int(required * 1.2) + 64 * 1024**2:
        raise ConflictError('Insufficient capacity for separate identity data copies; original data will not be moved')
    return result


def copy_identities(data):
    # The journal records each newly created account before its home is copied.
    # Rollback removes only these new resources; old accounts/data are untouched.
    for item in data['identities']:
        item['created'] = True
        _save(data)
        _run(['useradd', '--system', '--user-group', '--home-dir', item['destination'],
              '--shell', '/usr/sbin/nologin', item['new']])
        item['created'] = True
        _save(data)
    uids = {x['old_uid']: pwd.getpwnam(x['new']).pw_uid for x in data['identities']}
    gids = {x['old_gid']: grp.getgrnam(x['new']).gr_gid for x in data['identities']}
    for item in data['identities']:
        source, target = Path(item['source']), Path(item['destination'])
        # useradd does not create the home. Mark it before copying for crash recovery.
        item['copied'] = True
        _save(data)
        shutil.copytree(source, target, symlinks=True)
        for original in source.rglob('*'):
            copied = target / original.relative_to(source)
            if original.is_symlink():
                if not copied.is_symlink() or os.readlink(original) != os.readlink(copied):
                    raise ConflictError('Identity copy link verification failed')
            elif original.is_file():
                with original.open('rb') as left, copied.open('rb') as right:
                    if hashlib.file_digest(left, 'sha256').digest() != hashlib.file_digest(right, 'sha256').digest():
                        raise ConflictError('Identity data copy SHA-256 verification failed')
        for path in (target, *target.rglob('*')):
            info = path.lstat()
            os.chown(path, uids.get(info.st_uid, info.st_uid), gids.get(info.st_gid, info.st_gid),
                     follow_symlinks=False)
    node = pwd.getpwnam('serverhub-ai-node')
    import yaml
    for path in Path('/etc/serverhub').glob('*'):
        if path.suffix not in ('.env', '.yaml') or not path.is_file():
            continue
        text = path.read_text()
        for item in data['identities']:
            text = text.replace(item['source'], item['destination'])
        if path.name == 'broker.yaml':
            config = yaml.safe_load(text)
            config['allowed_uids'] = [node.pw_uid if uid == next(x['old_uid'] for x in data['identities'] if x['new'] == 'serverhub-ai-node') else uid
                                      for uid in config.get('allowed_uids', [])]
            config['socket_gid'] = node.pw_gid
            text = yaml.safe_dump(config)
        info = path.stat()
        _atomic_file(path, text.encode(), info.st_mode & 0o777, info.st_uid,
                     gids.get(info.st_gid, info.st_gid))


def old_name(name):
    return name.replace('serverhub-ai-', 'serverhub-', 1)


def migrate_broker_services(config, units):
    """Retarget only the allowlist entries proven to name AI OS services.

    Existing controller grants are not broadened. Old argument grants will be
    denied at the broker until their owner explicitly reviews the new targets.
    """
    mapping = {item['old']: item['new'] for item in units}
    names = set(mapping) | {name.removesuffix('.service') for name in mapping}
    def references(value):
        if isinstance(value, dict):
            return any(references(key) or references(item) for key, item in value.items())
        if isinstance(value, list):
            return any(references(item) for item in value)
        return isinstance(value, str) and value in names
    if references({key: value for key, value in config.items() if key != 'allowed_services'}):
        raise ConflictError('A registered broker plan references a legacy AI unit outside allowed_services; review that plan before migration')
    result = dict(config)
    result['allowed_services'] = [mapping.get(name, name) for name in config.get('allowed_services', [])]
    return result


def plan(source, *, root=Path('/')):
    installer = Installer(source, root=root)
    old_claim = previous_claim(root)
    identities = identity_plan(root)
    journal = root / 'var/lib/serverhub-install/state.json'
    current = root / 'opt/serverhub/current'
    # Older releases can lack the install journal. Only the live host can
    # establish identity without it, using independently protected code hashes,
    # release metadata, and exact systemd unit provenance checked below.
    journal_missing = not journal.exists()
    if root == Path('/'):
        if not journal_missing:
            protected(journal)
    elif journal_missing:
        raise ConflictError('Offline legacy migration requires an install journal')
    if journal_missing:
        if root != Path('/'):
            raise ConflictError('Cannot verify journal-less legacy installation offline')
        data = None
    else:
        data = json.loads(journal.read_text())
        if data.get('format') != 1 or data.get('state') != 'installed' or not data.get('trust_digest'):
            raise ConflictError('No completed legacy AI OS install journal; do not adopt this installation')
    if not current.is_symlink() or not current.resolve().is_relative_to((root / 'opt/serverhub/releases').resolve()):
        raise ConflictError('Legacy current release is not an AI OS release symlink')
    installed = current / 'installed.json'
    metadata_mode = installed.stat().st_mode & 0o777
    unsafe_runtime = []
    if root == Path('/'):
        # installed.json was not chmod'ed by older installers. It is not a trust
        # anchor. Independently validate the root-only code anchor and actual
        # installed modules, including for a previously repaired/upgraded host
        # whose initial install journal's trust digest is intentionally stale.
        trusted_digest = root / 'etc/serverhub/trust-boundaries.sha256'
        anchor_path = root / 'etc/serverhub/trusted-code-hashes.json'
        protected(trusted_digest)
        protected(anchor_path)
        expected_trust = trusted_digest.read_text().strip()
        anchor = json.loads(anchor_path.read_text())
        if anchor.get('format') != 1 or not anchor.get('files'):
            raise ConflictError('Missing independent legacy code anchor')
        packages = list(current.resolve().glob('venv/lib/python*/site-packages/serverhub'))
        if len(packages) != 1:
            raise ConflictError('Cannot uniquely locate legacy installed package')
        site = packages[0].parent
        actual_files = {str(p.relative_to(site)) for p in packages[0].rglob('*.py')}
        if actual_files != set(anchor['files']):
            raise ConflictError('Installed legacy package differs from the root-owned code anchor')
        for name, checksum in anchor['files'].items():
            if not name.startswith('serverhub/') or '..' in Path(name).parts:
                raise ConflictError('Invalid legacy code anchor path')
            module = site / name
            for item in (module, *module.parents):
                if item == current.resolve():
                    break
                info = item.lstat()
                if item.is_symlink() or info.st_uid != 0:
                    raise ConflictError('Foreign owner or symlink in anchored legacy code: ' + str(item))
                if info.st_mode & 0o022:
                    unsafe_runtime.append(str(item))
            if hashlib.sha256(module.read_bytes()).hexdigest() != checksum:
                raise ConflictError('Installed legacy code hash mismatch: ' + name)
        if installed.is_symlink() or installed.stat().st_uid != 0:
            raise ConflictError('Legacy release record must be an ordinary root-owned file')
        protected(installed.resolve().parent)
        expected = {'manifest': {'release_id': current.resolve().name,
                                'schema_revision': '0006_pause_clock',
                                'trust_boundary_digest': expected_trust}}
        if json.loads(installed.read_text()) != expected:
            raise ConflictError('Legacy release record does not match independently verified release identity/trust/schema')
    elif json.loads(installed.read_text())['manifest']['trust_boundary_digest'] != data['trust_digest']:
        raise ConflictError('Legacy release and installer trust records disagree')
    units = []
    for new in installer.units():
        old = new if old_claim else old_name(new)
        target = root / 'etc/systemd/system' / old
        replacement = target.with_name(new)
        if old != new and (replacement.exists() or replacement.is_symlink() or replacement.with_name(new + '.d').exists()):
            raise ConflictError(f'New unit namespace already occupied: {new}')
        if not target.exists():
            if old in ('serverhub-api.service', 'serverhub-worker.service', 'serverhub-broker.service', 'serverhub-node.service'):
                raise ConflictError(f'Missing legacy AI OS unit: {old}')
            continue
        if target.is_symlink():
            raise ConflictError(f'Cannot migrate an aliased legacy unit: {old}')
        if root == Path('/'):
            protected(target)
        expected = (Path(source) / 'packaging/systemd' / new).read_text()
        expected = legacy_resources(expected)
        if not old_claim:
            for name in installer.units():
                expected = expected.replace(name, old_name(name))
        if not old_claim:
            expected = expected.replace('/run/serverhub-ai-broker', '/run/serverhub-broker').replace(
            'RuntimeDirectory=serverhub-ai-broker', 'RuntimeDirectory=serverhub-broker').replace('/opt/serverhub/recovery-ai', '/opt/serverhub/recovery')
        if target.read_text() != expected:
            raise ConflictError(f'Legacy unit {old} is foreign or customized; explicit manual review required; no service changed')
        drop = target.with_name(old + '.d')
        if drop.exists():
            for item in drop.iterdir():
                if (item.is_symlink() or not item.is_file()
                        or not valid_legacy_dropin(new, item.name, item.read_text())):
                    raise ConflictError(f'Unrecognized legacy drop-in: {old}')
                if root == Path('/'):
                    protected(item)
        if root == Path('/'):
            result = subprocess.run(['systemctl', 'show', old,
                '--property=FragmentPath,DropInPaths,ExecStart,NeedDaemonReload'],
                check=False, text=True, capture_output=True, timeout=15, cwd='/')
            loaded = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            if (result.returncode or loaded.get('FragmentPath') != str(target)
                    or loaded.get('NeedDaemonReload') != 'no'
                    or '/opt/serverhub-control' in loaded.get('ExecStart', '')
                    or any(not path.startswith(str(drop) + '/')
                           for path in loaded.get('DropInPaths', '').split())):
                raise ConflictError(f'Loaded legacy unit {old} differs from the reviewed file; no stop or daemon-reload was performed')
        units.append({'old': old, 'new': new})
    broker = root / 'etc/serverhub/broker.yaml'
    if broker.exists():
        import yaml
        if root == Path('/'):
            protected(broker)
        config = yaml.safe_load(broker.read_text())
        if config.get('staging_projects'):
            raise ConflictError('Stop/archive staging projects and remove their enrollment before identity migration; re-enroll after migration')
        migrate_broker_services(config, units)
    return {'identities': identities, 'previous_claim': old_claim, 'units': units, 'previous': str(current.resolve()), 'state': 'reviewed',
            'legacy_metadata_mode': oct(metadata_mode), 'metadata_normalization': metadata_mode != 0o644,
            'unsafe_runtime_paths': sorted(set(unsafe_runtime)),
            'preserved': '/opt/serverhub-control and all foreign services; old identities/data retained; PostgreSQL roles/passwords unchanged'}


def _atomic_file(path, content, mode=0o644, uid=0, gid=0):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.ai-namespace-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _run(argv):
    return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=180, cwd='/')


def _save(value):
    # Legacy installations may have no installer journal directory. Create it
    # with root-only access, but never trust an existing symlink/foreign owner.
    parent = JOURNAL.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if parent.is_symlink() or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o077:
        raise ConflictError('Unsafe migration journal directory: ' + str(parent))
    temp = JOURNAL.with_suffix('.tmp')
    fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, JOURNAL)


def recover(*, force=False):
    protected(JOURNAL)
    data = json.loads(JOURNAL.read_text())
    if data['state'] != 'armed' or (not force and time.time() < data['deadline']):
        return {'state': data['state']}
    # Only units proven by plan() and recorded before any stop are ever touched.
    created = [x['new'] for x in data['units']
               if Path('/etc/systemd/system', x['new']).is_file()]
    if created:
        _run(['systemctl', 'disable', '--now', *created])
    for path, saved in data['files'].items():
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        _atomic_file(target, base64.b64decode(saved['content']), saved['mode'], saved['uid'], saved['gid'])
    for unit in data['units']:
        if unit['old'] == unit['new']:
            continue
        Path('/etc/systemd/system', unit['new']).unlink(missing_ok=True)
        directory = Path('/etc/systemd/system', unit['new'] + '.d')
        for saved_path in data['files']:
            saved = Path(saved_path)
            if saved.parent.name == unit['old'] + '.d':
                (directory / saved.name).unlink(missing_ok=True)
        if directory.exists() and not list(directory.iterdir()):
            directory.rmdir()
    backup_runtime = data.get('recovery_runtime_backup')
    if backup_runtime and Path(backup_runtime).exists():
        backup_path = Path(backup_runtime)
        protected(backup_path)
        runtime = Path('/opt/serverhub/recovery-ai')
        if runtime.exists() or runtime.is_symlink():
            protected(runtime)
            shutil.rmtree(runtime)
        os.replace(backup_path, runtime)
    current = Path('/opt/serverhub/current')
    replacement = current.with_name('.namespace-recover')
    replacement.unlink(missing_ok=True)
    replacement.symlink_to(data['previous'])
    os.replace(replacement, current)
    if not data.get('previous_claim'):
        Path(CLAIM).unlink(missing_ok=True)
    for item in reversed(data.get('identities', [])):
        if item.get('copied'):
            target = Path(item['destination'])
            if target.is_symlink():
                raise RuntimeError('Refusing symlinked migration rollback data')
            if target.exists():
                shutil.rmtree(target)
        if item.get('created'):
            if subprocess.run(['getent', 'passwd', item['new']], capture_output=True).returncode == 0:
                _run(['userdel', item['new']])
            # userdel may remove the dedicated group on Ubuntu.
            result = subprocess.run(['getent', 'group', item['new']], capture_output=True)
            if result.returncode == 0:
                _run(['groupdel', item['new']])
    _run(['systemctl', 'daemon-reload'])
    for unit in data['units']:
        if unit['enabled']:
            _run(['systemctl', 'enable', unit['old']])
        if unit['active']:
            _run(['systemctl', 'start', unit['old']])
    data['state'] = 'reverted'
    _save(data)
    _run(['systemctl', 'disable', '--now', 'serverhub-ai-namespace-recovery.timer'])
    for suffix in ('service', 'timer'):
        Path('/etc/systemd/system/serverhub-ai-namespace-recovery.' + suffix).unlink(missing_ok=True)
    _run(['systemctl', 'daemon-reload'])
    return {'state': 'reverted'}


def migrate(source, *, repair_legacy_permissions=False):
    if os.geteuid() != 0:
        raise ConflictError('Unit migration requires explicit local root')
    if JOURNAL.exists() and json.loads(JOURNAL.read_text()).get('state') == 'armed':
        raise ConflictError('Migration is armed; wait for recovery or run --rollback')
    data = plan(source)
    # Repair requires prebuilt artifacts. Validate them before arming rollback,
    # disabling services, or changing any systemd unit. Builds run as an
    # unprivileged checkout owner, never implicitly inside root migration.
    source = Path(source).resolve()
    wheels = list((source / 'dist').glob('*.whl'))
    if len(wheels) != 1:
        raise ConflictError(
            'Migration requires exactly one prebuilt wheel in dist/. '
            'Build as the checkout owner before --apply.'
        )
    if not (source / 'frontend/dist/index.html').is_file():
        raise ConflictError(
            'Migration requires prebuilt frontend/dist/index.html. '
            'Run npm ci and npm run build as the checkout owner before --apply.'
        )
    if data['unsafe_runtime_paths'] and not repair_legacy_permissions:
        raise ConflictError('Anchored legacy runtime has writable files. Review --plan and explicitly use --repair-legacy-permissions to seal only the verified AI OS runtime; no service changed')
    for name in ('serverhub-ai-namespace-recovery.service', 'serverhub-ai-namespace-recovery.timer'):
        result = _run(['systemctl', 'show', name, '--property=LoadState', '--value'])
        if result.stdout.strip() != 'not-found':
            raise ConflictError('Migration recovery namespace occupied: ' + name)
    if Path('/opt/serverhub/recovery-ai').exists():
        protected(Path('/opt/serverhub/recovery-ai'))
        if not data.get('previous_claim') and (not JOURNAL.exists() or json.loads(JOURNAL.read_text()).get('state') != 'reverted'):
            raise ConflictError('New recovery path already exists; review before migration')
    if data.get('previous_claim') and Path('/opt/serverhub/recovery-ai').exists():
        backup_runtime = Path('/opt/serverhub/recovery-ai.previous-identities')
        if backup_runtime.exists() or backup_runtime.is_symlink():
            raise ConflictError('Reserved previous recovery runtime path occupied; never overwrite it')
        data['recovery_runtime_backup'] = str(backup_runtime)
    # Detect loaded vendor/transient new units too, even if no files exist.
    for item in data['units']:
        state = _run(['systemctl', 'show', item['new'], '--property=LoadState', '--value']).stdout.strip()
        if item['old'] != item['new'] and state != 'not-found':
            raise ConflictError('Loaded new unit namespace is occupied: ' + item['new'])
        item['active'] = subprocess.run(['systemctl', 'is-active', '--quiet', item['old']]).returncode == 0
        item['enabled'] = subprocess.run(['systemctl', 'is-enabled', '--quiet', item['old']]).returncode == 0
    # Refuse ongoing operations; their independent watchdogs must remain running.
    for pending in [Path('/var/lib/serverhub-release/pending.json'),
                    *Path('/var/lib/serverhub-broker/operations').glob('*.json'),
                    *Path('/var/lib/serverhub-recovery').glob('*.json')]:
        if pending.exists() and json.loads(pending.read_text()).get('state') in ('armed', 'running', 'applying'):
            raise ConflictError('Finish or recover pending operation first: ' + str(pending))
    files = [Path('/etc/systemd/system', x['old']) for x in data['units']]
    files += [p for unit in data['units'] for p in Path('/etc/systemd/system', unit['old'] + '.d').glob('*')]
    files += [p for p in Path('/etc/serverhub').rglob('*') if p.is_file()]
    if Path(CLAIM).exists():
        files.append(Path(CLAIM))

    data['files'] = {}
    for path in files:
        protected(path)
        info = path.stat()
        data['files'][str(path)] = {'content': base64.b64encode(path.read_bytes()).decode(),
                                   'mode': info.st_mode & 0o777, 'uid': info.st_uid, 'gid': info.st_gid}
    metadata = Path(data['previous']) / 'installed.json'
    metadata.chmod(0o644)
    data.update(state='armed', deadline=time.time() + 1800)
    _save(data)
    # Stable standalone stdlib recovery: does not depend on a candidate wheel.
    helper = Path('/var/lib/serverhub-install/unit-recovery.py')
    _atomic_file(helper, Path(__file__).with_name('unit_recovery.py').read_bytes(), 0o600)
    service = Path('/etc/systemd/system/serverhub-ai-namespace-recovery.service')
    timer = service.with_suffix('.timer')
    _atomic_file(service, ('[Unit]\nDescription=Independent AI OS namespace migration recovery\n[Service]\nType=oneshot\nUser=root\nExecStart=/usr/bin/python3 -I ' + str(helper) + '\n').encode())
    _atomic_file(timer, ('[Unit]\nDescription=Recover interrupted AI OS namespace migration\n[Timer]\nOnBootSec=30s\nOnActiveSec=30s\nOnUnitInactiveSec=30s\n[Install]\nWantedBy=timers.target\n').encode())
    _run(['systemctl', 'daemon-reload'])
    _run(['systemctl', 'enable', '--now', timer.name])
    try:
        _run(['systemctl', 'disable', '--now', *[x['old'] for x in data['units']]])
        if data.get('recovery_runtime_backup'):
            os.replace('/opt/serverhub/recovery-ai', data['recovery_runtime_backup'])
        if repair_legacy_permissions:
            from .runtime_permissions import seal_runtime
            # The root code anchor was checked immediately above; source bytes
            # must match again after closing the tree to service identities.
            runtime = Path(data['previous'])
            runtime.chmod(0o700)
            verified = plan(source)
            if verified['previous'] != data['previous']:
                raise ConflictError('Legacy release changed during enrollment')
            seal_runtime(runtime)
            legacy_recovery = Path('/opt/serverhub/recovery')
            if legacy_recovery.exists():
                seal_runtime(legacy_recovery)
        # Quiesce old jobs before moving state-path references. We never edit
        # historical job checkpoints or silently abandon a resumable workspace.
        unfinished = _run(['runuser', '-u', 'postgres', '--', 'psql', '-XAt', '-d', 'serverhub', '-c',
            "SELECT count(*) FROM jobs WHERE state NOT IN ('succeeded','failed','cancelled','partial')"]).stdout.strip()
        if unfinished != '0':
            raise ConflictError('Finish/cancel all queued, paused or active jobs before identity migration; original checkpoints retained')
        copy_identities(data)
        for item in data['units']:
            old = Path('/etc/systemd/system', item['old'])
            new = old.with_name(item['new'])
            text = (source / 'packaging/systemd' / item['new']).read_text()
            for unit in data['units']:
                text = text.replace(unit['old'], unit['new'])
            text = text.replace('/run/serverhub-broker', '/run/serverhub-ai-broker').replace(
                'RuntimeDirectory=serverhub-broker', 'RuntimeDirectory=serverhub-ai-broker').replace('/opt/serverhub/recovery/', '/opt/serverhub/recovery-ai/')
            _atomic_file(new, text.encode())
            if old != new:
                old.unlink()
            dropdir = Path(str(old) + '.d')
            if dropdir.exists() and old != new:
                replacement = Path(str(new) + '.d')
                replacement.mkdir()
                for drop in dropdir.iterdir():
                    info = drop.stat()
                    content = drop.read_text().replace('Group=serverhub-worker', 'Group=serverhub-ai-worker')
                    if drop.name == '10-vm-paths.conf':
                        content = '[Service]\nInaccessiblePaths=\n' + next(line for line in (source / 'packaging/systemd/serverhub-ai-worker.service').read_text().splitlines() if line.startswith('InaccessiblePaths=')) + '\n'
                    _atomic_file(replacement / drop.name, content.encode(), info.st_mode & 0o777, info.st_uid, info.st_gid)
                    drop.unlink()
                dropdir.rmdir()
        for path in [Path('/etc/serverhub/broker.yaml'), Path('/etc/serverhub/node.yaml')]:
            text = path.read_text().replace('/run/serverhub-broker', '/run/serverhub-ai-broker')
            if path.name == 'broker.yaml':
                import yaml
                text = yaml.safe_dump(migrate_broker_services(yaml.safe_load(text), data['units']))
            info = path.stat()
            _atomic_file(path, text.encode(), info.st_mode & 0o777, info.st_uid, info.st_gid)
        vm_drop = Path('/etc/systemd/system/serverhub-ai-worker.service.d/10-vm-paths.conf')
        if vm_drop.exists():
            _atomic_file(vm_drop, ('[Service]\nInaccessiblePaths=\n' + next(line for line in (source / 'packaging/systemd/serverhub-ai-worker.service').read_text().splitlines() if line.startswith('InaccessiblePaths=')) + '\n').encode())
        drop = Path('/etc/systemd/system/serverhub-ai-worker.service.d/10-ai-identity.conf')
        if drop.exists():
            _atomic_file(drop, drop.read_bytes().replace(b'Group=serverhub-worker', b'Group=serverhub-ai-worker'))
        Path(CLAIM).unlink(missing_ok=True)
        write_claim()
        _run(['systemctl', 'daemon-reload'])
        # The reviewed repair upgrades code, trust anchors and independent runtime.
        from .repair import repair
        result = repair(source)
        for item in data['units']:
            if item['enabled']:
                _run(['systemctl', 'enable', item['new']])
            if item['active']:
                _run(['systemctl', 'start', item['new']])
        data['state'] = 'verified'
        _save(data)
        _run(['systemctl', 'disable', '--now', 'serverhub-ai-namespace-recovery.timer'])
        return {'state': 'migrated', 'upgrade': result}
    except BaseException:
        recover(force=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path.cwd())
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--plan', action='store_true')
    action.add_argument('--apply', action='store_true')
    action.add_argument('--rollback', action='store_true')
    parser.add_argument('--repair-legacy-permissions', action='store_true', help='Explicit root enrollment: seal independently hash-verified legacy AI OS runtime permissions')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Explicit local root is required')
    try:
        print(json.dumps(plan(args.source) if args.plan else recover(force=True) if args.rollback else migrate(args.source, repair_legacy_permissions=args.repair_legacy_permissions), indent=2))
    except (RuntimeError, OSError, ValueError) as error:
        parser.exit(1, f'Namespace migration refused/failed: {error}\n')


if __name__ == '__main__':
    main()
