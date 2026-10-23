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

from .coexistence import CLAIM, ConflictError, claim, protected, write_claim, valid_dropin
from .installer import Installer

JOURNAL = Path('/var/lib/serverhub-install/unit-migration.json')


def old_name(name):
    return name.replace('serverhub-ai-', 'serverhub-', 1)


def plan(source, *, root=Path('/')):
    installer = Installer(source, root=root)
    if claim(root):
        raise ConflictError('Namespaced installation already claimed; use normal repair-install.sh')
    journal = root / 'var/lib/serverhub-install/state.json'
    current = root / 'opt/serverhub/current'
    if root == Path('/'):
        protected(journal)
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
                                'schema_revision': '0005_priority',
                                'trust_boundary_digest': expected_trust}}
        if json.loads(installed.read_text()) != expected:
            raise ConflictError('Legacy release record does not match independently verified release identity/trust/schema')
    elif json.loads(installed.read_text())['manifest']['trust_boundary_digest'] != data['trust_digest']:
        raise ConflictError('Legacy release and installer trust records disagree')
    units = []
    for new in installer.units():
        old = old_name(new)
        target = root / 'etc/systemd/system' / old
        replacement = target.with_name(new)
        if replacement.exists() or replacement.is_symlink() or replacement.with_name(new + '.d').exists():
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
        for name in installer.units():
            expected = expected.replace(name, old_name(name))
        expected = expected.replace('/run/serverhub-ai-broker', '/run/serverhub-broker').replace(
            'RuntimeDirectory=serverhub-ai-broker', 'RuntimeDirectory=serverhub-broker').replace('/opt/serverhub/recovery-ai', '/opt/serverhub/recovery')
        if target.read_text() != expected:
            raise ConflictError(f'Legacy unit {old} is foreign or customized; explicit manual review required; no service changed')
        drop = target.with_name(old + '.d')
        if drop.exists():
            for item in drop.iterdir():
                if (item.is_symlink() or not item.is_file()
                        or not valid_dropin(new, item.name, item.read_text())):
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
    return {'units': units, 'previous': str(current.resolve()), 'state': 'reviewed',
            'legacy_metadata_mode': oct(metadata_mode), 'metadata_normalization': metadata_mode != 0o644,
            'unsafe_runtime_paths': sorted(set(unsafe_runtime)),
            'preserved': '/opt/serverhub-control and all foreign services; accounts, data and database remain in place'}


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
        Path('/etc/systemd/system', unit['new']).unlink(missing_ok=True)
        directory = Path('/etc/systemd/system', unit['new'] + '.d')
        for saved_path in data['files']:
            saved = Path(saved_path)
            if saved.parent.name == unit['old'] + '.d':
                (directory / saved.name).unlink(missing_ok=True)
        if directory.exists() and not list(directory.iterdir()):
            directory.rmdir()
    current = Path('/opt/serverhub/current')
    replacement = current.with_name('.namespace-recover')
    replacement.unlink(missing_ok=True)
    replacement.symlink_to(data['previous'])
    os.replace(replacement, current)
    Path(CLAIM).unlink(missing_ok=True)
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
    if data['unsafe_runtime_paths'] and not repair_legacy_permissions:
        raise ConflictError('Anchored legacy runtime has writable files. Review --plan and explicitly use --repair-legacy-permissions to seal only the verified AI OS runtime; no service changed')
    for name in ('serverhub-ai-namespace-recovery.service', 'serverhub-ai-namespace-recovery.timer'):
        result = _run(['systemctl', 'show', name, '--property=LoadState', '--value'])
        if result.stdout.strip() != 'not-found':
            raise ConflictError('Migration recovery namespace occupied: ' + name)
    if Path('/opt/serverhub/recovery-ai').exists():
        protected(Path('/opt/serverhub/recovery-ai'))
        if not JOURNAL.exists() or json.loads(JOURNAL.read_text()).get('state') != 'reverted':
            raise ConflictError('New recovery path already exists; review before migration')
    # Detect loaded vendor/transient new units too, even if no files exist.
    for item in data['units']:
        state = _run(['systemctl', 'show', item['new'], '--property=LoadState', '--value']).stdout.strip()
        if state != 'not-found':
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
        for item in data['units']:
            old = Path('/etc/systemd/system', item['old'])
            new = old.with_name(item['new'])
            text = old.read_text()
            for unit in data['units']:
                text = text.replace(unit['old'], unit['new'])
            text = text.replace('/run/serverhub-broker', '/run/serverhub-ai-broker').replace(
                'RuntimeDirectory=serverhub-broker', 'RuntimeDirectory=serverhub-ai-broker').replace('/opt/serverhub/recovery/', '/opt/serverhub/recovery-ai/')
            _atomic_file(new, text.encode())
            old.unlink()
            dropdir = Path(str(old) + '.d')
            if dropdir.exists():
                replacement = Path(str(new) + '.d')
                replacement.mkdir()
                for drop in dropdir.iterdir():
                    info = drop.stat()
                    _atomic_file(replacement / drop.name, drop.read_bytes(), info.st_mode & 0o777, info.st_uid, info.st_gid)
                    drop.unlink()
                dropdir.rmdir()
        for path in [Path('/etc/serverhub/broker.yaml'), Path('/etc/serverhub/node.yaml')]:
            text = path.read_text().replace('/run/serverhub-broker', '/run/serverhub-ai-broker')
            info = path.stat()
            _atomic_file(path, text.encode(), info.st_mode & 0o777, info.st_uid, info.st_gid)
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
