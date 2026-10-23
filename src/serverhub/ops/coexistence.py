"""Fail-closed native resource ownership checks; never adopt Control resources.

The root-only claim is created after a clean preflight, before the installer makes
accounts or files. Interrupted installs therefore retain exactly the same claims.
"""
from __future__ import annotations

import grp
import json
import os
import pwd
import re
import socket
import subprocess
from pathlib import Path

CLAIM = '/var/lib/serverhub-install/ownership.json'
PATHS = (
    '/opt/serverhub', '/etc/serverhub', '/var/backups/serverhub',
    '/var/lib/serverhub-api', '/var/lib/serverhub-worker', '/var/lib/serverhub-node',
    '/var/lib/serverhub-ai', '/var/lib/serverhub-migrate', '/var/lib/serverhub-stage-runtime',
    '/var/lib/serverhub-staging', '/var/lib/serverhub-stage-data',
    '/var/lib/serverhub-broker', '/var/log/serverhub-broker',
    '/var/lib/serverhub-release', '/var/lib/serverhub-recovery',
    '/var/lib/serverhub-status', '/var/lib/serverhub-install',
    '/run/serverhub-ai-broker', '/etc/apparmor.d/serverhub-build',
)
ACCOUNTS = ('serverhub-api', 'serverhub-worker', 'serverhub-node',
            'serverhub-migrate', 'serverhub-staging', 'serverhub-ai')
DATABASE = 'serverhub'
ROLES = ('serverhub_api', 'serverhub_worker', 'serverhub_migrate')


class ConflictError(RuntimeError):
    pass


def protected(path: Path, *, leaf_uids=()):
    """Verify every ancestor before trusting a privileged ownership record."""
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ConflictError(f'Symlinked reserved path: {item}')
        allowed = {0, *leaf_uids} if item == path else {0}
        if item.exists() and (item.stat().st_uid not in allowed or item.stat().st_mode & 0o022):
            raise ConflictError(f'Unsafe ownership or writable reserved path: {item}')


def claim(root=Path('/')):
    path = root / CLAIM.lstrip('/')
    if not path.exists():
        return None
    protected(path)
    value = json.loads(path.read_text())
    if value != {'product': 'serverhub-ai-os', 'namespace': 2, 'paths': list(PATHS),
                 'accounts': list(ACCOUNTS)}:
        raise ConflictError('Unknown AI OS ownership claim; inspect without deleting it')
    return value


def write_claim(root=Path('/')):
    path = root / CLAIM.lstrip('/')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    protected(path.parent)
    value = {'product': 'serverhub-ai-os', 'namespace': 2, 'paths': list(PATHS),
             'accounts': list(ACCOUNTS)}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())


def inspect(*, root=Path('/'), units=(), runner=subprocess.run, live=True):
    root = Path(root)
    owned = claim(root) is not None
    conflicts = []
    def issue(kind, name, reason):
        conflicts.append({'kind': kind, 'resource': name, 'reason': reason})
    for name in PATHS:
        path = root / name.lstrip('/')
        try:
            # Check existing ancestors even when the final path is absent.
            if live:
                uids = []
                if owned and name.startswith('/var/lib/'):
                    for account in ACCOUNTS:
                        try:
                            uids.append(pwd.getpwnam(account).pw_uid)
                        except KeyError:
                            pass
                if owned and name == '/var/lib/serverhub-stage-runtime' and path.exists():
                    try:
                        pwd.getpwnam('serverhub-staging')
                    except KeyError:
                        try:
                            pwd.getpwuid(path.stat().st_uid)
                        except KeyError:
                            uids.append(path.stat().st_uid)  # orphan of the claimed staging account
                protected(path, leaf_uids=uids)
            elif path.is_symlink():
                raise ConflictError(f'Symlinked reserved path: {name}')
            if (path.exists() or path.is_symlink()) and not owned:
                issue('path', name, 'Unclaimed existing path; never adopted automatically')
        except ConflictError as error:
            issue('path', name, str(error))
    for unit in (*units, 'serverhub-ai-namespace-recovery.service', 'serverhub-ai-namespace-recovery.timer'):
        target = root / 'etc/systemd/system' / unit
        dropins = target.with_name(unit + '.d')
        if target.is_symlink():
            issue('service', unit, 'Aliased or masked unit is not owned')
        if owned and target.is_file() and not target.is_symlink():
            text = target.read_text()
            if unit.endswith('.service'):
                executable = next((line.split('=', 1)[1] for line in text.splitlines() if line.startswith('ExecStart=')), '')
                if not executable.startswith(('/opt/serverhub/', '/usr/bin/python3 -I /opt/serverhub/',
                                               '/usr/bin/python3 -I /var/lib/serverhub-install/unit-recovery.py')):
                    issue('service', unit, 'Existing unit executable is outside the AI OS installation')
            elif 'Unit=' in text and 'Unit=serverhub-ai-' not in text:
                issue('service', unit, 'Timer points outside AI OS namespace')
        if dropins.exists():
            for drop in dropins.iterdir():
                if (drop.is_symlink() or not drop.is_file()
                        or not valid_dropin(unit, drop.name, drop.read_text())):
                    issue('service', unit, 'Unrecognized drop-in; explicit review required')
                elif live:
                    try:
                        protected(drop)
                    except ConflictError as error:
                        issue('service', unit, str(error))
        if (target.exists() or target.is_symlink() or dropins.exists()) and not owned:
            issue('service', unit, 'Unclaimed unit or drop-in exists')
        if live:
            result = runner(['systemctl', 'show', unit, '--property=LoadState,FragmentPath,DropInPaths'],
                            check=False, text=True, capture_output=True, timeout=15, cwd='/')
            if result.returncode:
                issue('service', unit, 'Cannot inspect loaded systemd unit')
                continue
            info = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            fragment = info.get('FragmentPath', '')
            if info.get('LoadState', 'not-found') != 'not-found':
                if not owned or fragment != str(target) or target.is_symlink():
                    issue('service', unit, 'Foreign, masked, aliased or transient unit')
            if info.get('DropInPaths'):
                for item in info['DropInPaths'].split():
                    if not owned or not item.startswith(str(dropins) + '/'):
                        issue('service', unit, 'Foreign systemd drop-in: ' + item)
    if live:
        for name in ACCOUNTS:
            for kind, lookup in [('user', pwd.getpwnam), ('group', grp.getgrnam)]:
                try:
                    entry = lookup(name)
                    if owned:
                        if kind == 'user':
                            home = '/var/lib/serverhub-stage-runtime' if name == 'serverhub-staging' else '/var/lib/' + name
                            groups = {grp.getgrgid(gid).gr_name for gid in os.getgrouplist(name, entry.pw_gid)}
                            if (entry.pw_uid == 0 or entry.pw_dir != home
                                    or entry.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin')
                                    or groups & {'sudo', 'docker', 'root', 'adm'}
                                    or grp.getgrnam(name).gr_gid != entry.pw_gid):
                                issue(kind, name, 'Existing service identity changed home, shell, group or privilege')
                        elif entry.gr_gid == 0 or entry.gr_mem:
                            issue(kind, name, 'Shared or privileged service group')
                    if not owned:
                        issue(kind, name, 'Unclaimed existing identity; no usermod/group adoption')
                except KeyError:
                    pass
        # A listener may belong to another application even on an existing AI OS
        # host. Identify its process via systemd; never kill it to free the port.
        port = 9080
        if owned:
            for filename in ('api.env', 'access.env'):
                config = root / 'etc/serverhub' / filename
                if config.exists():
                    protected(config)
                    for line in config.read_text().splitlines():
                        if line.startswith('SERVERHUB_API_PORT='):
                            port = int(line.split('=', 1)[1].strip('\"\''))
            if not 1 <= port <= 65535:
                raise ConflictError('Invalid configured API listener port')
        for family, address in [(socket.AF_INET, ('127.0.0.1', port)),
                                (socket.AF_INET6, ('::1', port))]:
            try:
                with socket.socket(family, socket.SOCK_STREAM) as probe:
                    probe.bind(address)
            except OSError as error:
                if error.errno in (97, 99):  # IPv6 unavailable
                    continue
                if owned and api_owns_port(runner, port):
                    continue
                issue('port', f'{port}/tcp', 'Address unavailable; stop and identify the listener or configure an isolated access plan')
        # Inspect, never alter, an already installed PostgreSQL cluster.
        import shutil
        if shutil.which('psql') and shutil.which('runuser') and not owned:
            query = ("SELECT 'database:'||datname FROM pg_database WHERE datname='serverhub' "
                     "UNION ALL SELECT 'role:'||rolname FROM pg_roles WHERE rolname IN "
                     "('serverhub_api','serverhub_worker','serverhub_migrate')")
            result = runner(['runuser', '-u', 'postgres', '--', 'psql', '-XAt', '-d', 'postgres', '-c', query],
                            check=False, text=True, capture_output=True, timeout=15, cwd='/')
            if result.returncode == 0:
                for name in result.stdout.splitlines():
                    issue('database', name, 'Unclaimed PostgreSQL object; never adopt an existing database or role')
            elif Path('/etc/postgresql').exists():
                issue('database', 'postgresql', 'Installed cluster cannot be inspected; resolve before installation')
    return {'safe': not conflicts, 'owned_installation': owned, 'conflicts': conflicts,
            'control_preserved': ['/opt/serverhub-control', 'serverhub-broker.service',
                                  'serverhub-docker-ro.service', 'serverhub-worker.service']}


def require_safe(**kwargs):
    report = inspect(**kwargs)
    if not report['safe']:
        raise ConflictError('Coexistence preflight refused changes: ' + '; '.join(
            f"{x['kind']} {x['resource']}: {x['reason']}" for x in report['conflicts']))
    return report


def api_owns_port(runner, port=9080):
    result = runner(['systemctl', 'show', 'serverhub-ai-api.service', '--property=ControlGroup', '--value'],
                    check=False, text=True, capture_output=True, timeout=15, cwd='/')
    group = result.stdout.strip()
    if result.returncode or not group.startswith('/system.slice/serverhub-ai-api.service'):
        return False
    result = runner(['ss', '-H', '-lntp', f'sport = :{port}'], check=False, text=True,
                    capture_output=True, timeout=15, cwd='/')
    import re
    listeners = result.stdout.splitlines()
    if result.returncode or not listeners:
        return False
    for listener in listeners:
        pids = re.findall(r'pid=(\d+)', listener)
        if not pids:
            return False
        for pid in pids:
            try:
                if not any(line.split(':', 2)[-1] == group for line in
                           Path('/proc', pid, 'cgroup').read_text().splitlines()):
                    return False
            except OSError:
                return False
    return True


def valid_dropin(unit, name, text):
    if unit == 'serverhub-ai-worker.service' and name == '10-vm-paths.conf':
        # Permit only the legacy VM override that repeats the reviewed unit's
        # exact InaccessiblePaths. Never accept an arbitrary reset/relaxation.
        return text == (
            '[Service]\n'
            'InaccessiblePaths=\n'
            'InaccessiblePaths=-/etc/serverhub/api.env -/etc/serverhub/recovery.env '
            '-/etc/serverhub/broker.yaml -/var/backups/serverhub '
            '-/var/lib/serverhub-recovery -/var/lib/serverhub-release '
            '-/var/run/docker.sock -/run/serverhub-broker -/var/lib/serverhub-node\n'
        )
    if unit == 'serverhub-ai-worker.service' and name == '10-ai-identity.conf':
        return text == '[Service]\nUser=serverhub-ai\nGroup=serverhub-worker\n'
    if unit == 'serverhub-ai-broker.service' and name == '20-administration.conf':
        match = re.fullmatch(
            r'\[Service\]\nReadWritePaths=([^\n]+) -/var/log/apt -/var/log/dpkg.log\n'
            r'ReadOnlyPaths=/etc/serverhub /opt/serverhub /etc/ssh /etc/systemd/system /etc/sudoers /etc/sudoers.d /etc/pam.d\n', text)
        if not match:
            return False
        paths = match[1].split(' ')
        return (paths == sorted(set(paths)) and {'/usr', '/etc', '/var/lib/dpkg', '/var/lib/apt', '/var/cache/apt'} <= set(paths)
                and all(re.fullmatch(r'/[A-Za-z0-9_./-]+', value) and '..' not in Path(value).parts for value in paths))
    return False
