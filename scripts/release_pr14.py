"""PR14-only offline owner maintenance, deliberately outside autonomous upgrades.

No production bypass/test flags. Tests instantiate the transaction with private
fixtures. The installed independent recovery interpreter executes this file.
"""
from __future__ import annotations

import contextlib
import fcntl
import getpass
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
import warnings

# Capture once, before approval; never install a later reread of a writable checkout.
EXECUTING_SOURCE = Path(__file__).read_bytes()

COMMIT = '3e9a2f4bc32d455a2cecffddd495494d8ed08078'
RELEASE = 'oauth-csrf-pr14-3e9a2f4'
PREVIOUS = 'repair-20261024T195431Z-60f67b'
SCHEMA = '0006_pause_clock'
OLD_TRUST = 'd8880cdfcfd97ecd6845627e0c7f52d9a0069ef364ddd6acbd40caa8d8c7b42c'
NEW_TRUST = '5846e2d5940f9fa73408311c438c1ee88a47579211eb8770e0be36e2633010a6'
WHEEL_SHA = 'a96f24266030fd8a611ae6614de0e21faf5e484f04822704dc8fc92bc1b8a130'
SOURCE_SHA = '89b83d3871549bcedb6045ca31cc4aa93e43bcfa0e139daf6f617722851f7fe5'
HASHES = {
    'application.whl': WHEEL_SHA,
    'web.tar.gz': '34e557c682db46bd234b6d2056bd90eae5264040904e30da327554acfe0c1a01',
    'migrations.tar.gz': '259f46189260ffb9f1d1d75bfee7ec25ba4b0397b9244ce7a5b29f4e476a2c6f',
    'requirements.lock': '8b3b5bc8625f46465b16bcca2038c3a1454821ccfcf5f65def61b353a5185c89',
    'alembic.ini': '8965c450bfd77867a3b02b26c5a0cfce35002fbba0f57fd2cd25aa0009393d70',
}
DELTA = {
    'serverhub/main.py': ('013f86846598bacfbea164980df8b13197fdeb1af550883c00e920e7b7d83bfd',
                        '347e4fa919f8927e242515987fd02cf550209704c78a147f8e0235ca559c96ca'),
    'serverhub/mcp.py': ('88219757fe8b54a5242ecf21f667b404b8a049848a47fbef250099388fbcf79f',
                       '43ed7629f3f9a1a6d66bde70da9f106488a23b89a47a2aca6c3863dc2e32e9eb'),
}
STATE = Path('/var/lib/serverhub-release/pr14')
INSTALL = Path('/opt/serverhub')
CONFIG = Path('/etc/serverhub')
EVIDENCE = Path('/home/serverhub/oauth-rc-evidence-20261025')
RESTORE_ROOT = Path('/var/lib/serverhub-pr14-restore')
ORIGIN = 'https://ai.dennishub.dk'
SERVICES = ('serverhub-ai-api.service', 'serverhub-ai-worker.service',
            'serverhub-ai-broker.service', 'serverhub-ai-node.service')
UNRELATED = ('serverhub-worker.service', 'serverhub-broker.service',
             'serverhub-docker-ro.service', 'docker.service', 'postgresql@16-main.service', 'caddy.service')


class Stop(RuntimeError):
    """Safe error text only; never include subprocess output or HTTP bodies."""


def need(condition, message):
    if not condition:
        raise Stop(message)


def tty_text(prompt):
    with open('/dev/tty', 'r+') as tty:
        tty.write(prompt)
        tty.flush()
        return tty.readline().strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, *, private=False, protected=False, limit=128 * 1024 * 1024):
    path = Path(path)
    if protected:
        protected_path(path.parent, directory=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
             'Unsafe regular file')
        if protected:
            need(info.st_uid == 0 and not info.st_mode & 0o022, 'Unprotected file')
        if private:
            need(not info.st_mode & 0o077, 'Private file permissions required')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            return stream.read(limit + 1)
    finally:
        os.close(fd)


def protected_path(path, *, directory=False):
    path = Path(path)
    need(path.is_absolute(), 'Absolute protected path required')
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        need(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             'Unsafe protected path or ancestor')
    if directory:
        need(path.is_dir(), 'Protected directory required')


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_tree(root):
    directories = [root]
    for path in root.rglob('*'):
        if path.is_symlink():
            continue
        if path.is_dir():
            directories.append(path)
        else:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                need(stat.S_ISREG(os.fstat(fd).st_mode), 'Unexpected executable tree payload')
                os.fsync(fd)
            finally:
                os.close(fd)
    for directory in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        sync_dir(directory)
    sync_dir(root.parent)


def atomic_bytes(path, data, mode=0o600):
    path = Path(path)
    need(not path.is_symlink(), 'Refusing symlink state target')
    fd, temporary = tempfile.mkstemp(prefix='.pr14-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(path, data):
    atomic_bytes(path, (json.dumps(data, sort_keys=True, indent=2) + '\n').encode())


def verify_files(directory, hashes):
    for name, checksum in hashes.items():
        need(sha(read_regular(Path(directory) / name)) == checksum, 'Artifact hash mismatch: ' + name)


def run(argv, *, env=None, timeout=120):
    try:
        return subprocess.run(argv, check=True, capture_output=True, text=True,
                              timeout=timeout, env=env or {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
    except (OSError, subprocess.SubprocessError):
        raise Stop('Command failed: ' + Path(argv[0]).name) from None


@contextlib.contextmanager
def locked(path, *, nonblocking=False):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
             and not info.st_mode & 0o077, 'Unsafe release lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        except BlockingIOError:
            raise Stop('Another owner release is running') from None
        yield
    finally:
        os.close(fd)


def transact(host, report):
    """No mutation of live executable/anchors until independent recovery is armed."""
    armed = False
    try:
        for phase in ('preflight', 'backup_restore', 'prepare', 'drill', 'arm', 'install', 'accept', 'commit'):
            report['phase'] = phase
            if hasattr(host, 'checkpoint'):
                host.checkpoint()
            if phase == 'arm':
                armed = True  # arm itself can fail after writing a durable checkpoint
                host.arm(report['backup'])
            elif phase == 'backup_restore':
                report['backup'] = host.backup_restore()
            else:
                getattr(host, phase)()
        report['state'] = 'verified'
    except BaseException as error:
        report['state'] = 'failed'
        report['failure_reason'] = str(error) if isinstance(error, Stop) else 'Internal operation failed; raw errors withheld'
        if armed:
            try:
                host.rollback()
                report['state'] = 'reverted'
            except BaseException:
                report['state'] = 'rollback_failed'
        raise Stop('Release stopped at ' + report['phase'] + '; state ' + report['state']) from None


def package_files(site):
    result = {}
    for path in (site / 'serverhub').rglob('*'):
        if path.is_dir():
            need(not path.is_symlink(), 'Linked package directory')
        elif path.suffix != '.pyc':
            result[str(path.relative_to(site))] = sha(read_regular(path, protected=True))
    return result


def wheel_files(path):
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
        need(len(names) == len(set(names)), 'Duplicate wheel members')
        result = {}
        for name in names:
            need(not Path(name).is_absolute() and '..' not in Path(name).parts,
                 'Unsafe wheel member')
            if name.startswith('serverhub/') and not name.endswith('/'):
                result[name] = wheel.read(name)
            else:
                need(bool(re.fullmatch(r'serverhub_ai_os-[^/]+\.dist-info/(METADATA|WHEEL|RECORD|entry_points\.txt|licenses/LICENSE)', name)),
                     'Unexpected wheel installation payload')
        return result


def check_delta(old, candidate):
    hashes = {name: sha(data) for name, data in candidate.items()}
    need(set(old) == set(hashes), 'Package inventory differs')
    changed = {name for name in old if old[name] != hashes[name]}
    need(changed == set(DELTA), 'Runtime changes exceed approved OAuth patch')
    for name, (before, after) in DELTA.items():
        need(old[name] == before and hashes[name] == after, 'Pinned OAuth module mismatch')
    return hashes


def tree_hashes(path):
    return {str(p.relative_to(path)): sha(read_regular(p, protected=True))
            for p in path.rglob('*') if p.is_file() and p.suffix != '.pyc'}


class NativeHost:
    def __init__(self, report):
        self.report = report
        self.previous = INSTALL / 'releases' / PREVIOUS
        self.candidate = INSTALL / 'releases' / RELEASE
        self.bundle = STATE / 'artifacts'
        self.journal = STATE / 'journal.json'
        self.site = self.previous / 'venv/lib/python3.12/site-packages'
        self.rm = None
        self.created_session = False

    def checkpoint(self):
        atomic_json(STATE / 'report.json', self.report)

    def preflight(self):
        from serverhub.ops.release import ReleaseManager
        from serverhub.ops.repair import read_environment
        self.rm = ReleaseManager(state_root=STATE)
        self.rm._protect()
        protected_path(self.previous, directory=True)
        need((INSTALL / 'current').is_symlink() and (INSTALL / 'current').resolve() == self.previous,
             'Installed baseline differs; do not adopt or overwrite another release')
        if self.candidate.exists():
            protected_path(self.candidate, directory=True)
            existing = json.loads(read_regular(self.candidate / 'installed.json', protected=True))
            need(existing.get('source_commit') == COMMIT and existing.get('wheel_sha256') == WHEEL_SHA,
                 'Existing candidate does not belong to this reviewed transaction')
        for path in (Path('/var/lib/serverhub-release/pending.json'), self.journal):
            if path.exists():
                value = json.loads(read_regular(path, protected=True))
                need(value.get('state') in {'verified', 'reverted'}, 'Pending or unknown release checkpoint')
        manifest = json.loads(read_regular(self.previous / 'installed.json', protected=True))['manifest']
        need(manifest['schema_revision'] == SCHEMA and manifest['trust_boundary_digest'] == OLD_TRUST,
             'Baseline schema or trust identity differs')
        self.old_anchor = read_regular(CONFIG / 'trusted-code-hashes.json', private=True, protected=True)
        self.old_trust = read_regular(CONFIG / 'trust-boundaries.sha256', protected=True)
        need(self.old_trust.decode().strip() == OLD_TRUST, 'Installed trust anchor differs')
        old = package_files(self.site)
        need(json.loads(self.old_anchor) == {'format': 1, 'files': old}, 'Installed code differs from protected anchor')
        candidate = wheel_files(self.bundle / 'application.whl')
        self.new_hashes = check_delta(old, candidate)
        self.new_anchor = json.dumps({'format': 1, 'files': self.new_hashes}, sort_keys=True).encode()
        self.new_trust = (NEW_TRUST + '\n').encode()
        self.environment = read_environment(CONFIG / 'recovery.env')
        # Verify exact unchanged assets against the pinned release archives.
        for name, tree in [('web.tar.gz', 'web'), ('migrations.tar.gz', 'migrations')]:
            with tarfile.open(self.bundle / name) as archive:
                expected = {}
                for member in archive.getmembers():
                    need(member.isfile() or member.isdir(), 'Unsafe artifact archive member')
                    if member.isfile():
                        expected[member.name.removeprefix('./')] = sha(archive.extractfile(member).read())
                need(tree_hashes(self.previous / tree) == expected, 'Installed assets differ: ' + tree)
        need(read_regular(self.previous / 'alembic.ini', protected=True) == read_regular(self.bundle / 'alembic.ini'),
             'Installed migration configuration differs')
        # Imported recovery dependencies are independent of the candidate.
        versions = json.loads(run([str(self.previous / 'venv/bin/python'), '-I', '-c',
                                  'import importlib.metadata,json; print(json.dumps({d.metadata["Name"].lower().replace("_","-"): d.version for d in importlib.metadata.distributions()}))']).stdout)
        for line in (self.bundle / 'requirements.lock').read_text().splitlines():
            matched = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9_.-]*)==([^\s\\]+)', line)
            if matched:
                name, version = matched.groups()
                need(importlib.metadata.version(name) == version
                     and versions.get(name.lower().replace('_', '-')) == version, 'Locked dependency mismatch')
        # All copied executable/dependency paths must already be sealed. Permit only
        # protected symlink destinations (normal venv interpreter and lib64 links).
        for path in self.previous.rglob('*'):
            if path.is_symlink():
                protected_path(path.resolve())
            elif path.is_dir():
                protected_path(path, directory=True)
            else:
                read_regular(path, protected=True)
        self.service_snapshot = self.services(UNRELATED)
        self.services(SERVICES, active=True)
        need(run(['systemctl', 'is-active', 'serverhub-ai-release-watchdog.timer']).stdout.strip() == 'active',
             'Independent release watchdog is unavailable')
        self.api_preflight()

    def services(self, names, active=False):
        values = {}
        for name in names:
            result = run(['systemctl', 'show', name, '-p', 'MainPID', '-p', 'ActiveState', '-p', 'ExecMainStartTimestampMonotonic']).stdout
            fields = dict(line.split('=', 1) for line in result.splitlines() if '=' in line)
            if active:
                need(fields.get('ActiveState') == 'active' and fields.get('MainPID') not in {'0', None},
                     'Required AI service is not active')
            values[name] = fields
        return values

    def client(self):
        import httpx
        return httpx.Client(base_url=ORIGIN, follow_redirects=False, timeout=10, trust_env=False)

    def api_preflight(self):
        with self.client() as client:
            self.authenticate(client)
            need(client.get('/api/auth/me', headers={'Authorization': 'Bearer ' + self.token}).json().get('role') == 'owner',
                 'Existing owner verification session is unavailable')
            headers = {'Authorization': 'Bearer ' + self.token}
            hosts = client.get('/api/hosts', headers=headers)
            need(hosts.status_code == 200, 'Enrolled hosts are unavailable')
            identities = [h.get('id') for h in hosts.json() if not h.get('revoked')
                          and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', h.get('id', ''))]
            need(bool(identities), 'An enrolled host is required for persistent-job verification')
            if (CONFIG / 'pr14-host-id').exists():
                self.host_id = read_regular(CONFIG / 'pr14-host-id', private=True, protected=True).decode().strip()
            elif len(identities) == 1:
                self.host_id = identities[0]
            else:
                print('Enrolled verification host IDs: ' + ', '.join(identities), flush=True)
                self.host_id = tty_text('Host ID for read-only inventory.refresh verification: ')
            need(self.host_id in identities, 'Verification host is not enrolled')
            self.report['verification_host_id'] = self.host_id
        self.db_check_live()

    def authenticate(self, client):
        from serverhub.ops.verify_install import read_token
        if (CONFIG / 'pr14-owner.token').exists():
            self.token = read_token(CONFIG / 'pr14-owner.token')
            return
        username = tty_text('Existing ServerHub owner username: ')
        need(bool(username) and len(username) <= 100, 'Owner username required')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            password = getpass.getpass('Existing ServerHub owner password (not stored): ')
        try:
            response = client.post('/api/auth/login', headers={'Origin': ORIGIN},
                                   json={'username': username, 'password': password})
        finally:
            del password
        need(response.status_code == 200, 'Owner login failed; no deployment performed')
        self.token = response.json()['token']
        self.created_session = True

    def close(self):
        if self.created_session:
            with self.client() as client:
                response = client.post('/api/auth/logout',
                                       headers={'Authorization': 'Bearer ' + self.token, 'Origin': ORIGIN})
                need(response.status_code in {200, 204}, 'Temporary verification login could not be revoked')
            self.created_session = False
            del self.token

    def db_check_live(self):
        from sqlalchemy import create_engine, text
        engine = create_engine(self.environment['SERVERHUB_DATABASE_URL'])
        try:
            with engine.connect() as connection:
                need(connection.scalar(text('SELECT version_num FROM alembic_version')) == SCHEMA,
                     'Live schema mismatch')
                self.report['job_states'] = {str(state): count for state, count in connection.execute(
                    text('SELECT state, count(*) FROM jobs GROUP BY state'))}
        finally:
            engine.dispose()

    def backup_restore(self):
        from serverhub.ops.backup import BackupManager
        manager = BackupManager()
        backup = manager.create(self.environment['SERVERHUB_DATABASE_URL'], [CONFIG])
        manager.verify(backup['id'])
        sync_tree(Path('/var/backups/serverhub') / backup['id'])
        with tarfile.open(Path('/var/backups/serverhub') / backup['id'] / 'configuration.tar.gz') as archive:
            need(all(m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
                     for m in archive.getmembers()), 'Invalid configuration archive')
        # Real independent cluster, no TCP listener; no live database CREATE/DROP.
        self.isolated_restore(Path('/var/backups/serverhub') / backup['id'] / 'postgres.dump')
        return {'id': backup['id'], 'restore': 'verified', 'files': backup['files']}

    def isolated_restore(self, dump):
        from sqlalchemy import create_engine, text
        from sqlalchemy.orm import Session
        from serverhub.audit import verify_chain
        pg = pwd.getpwnam('postgres')
        base = RESTORE_ROOT
        if not base.exists():
            base.mkdir(mode=0o755)
        protected_path(base, directory=True)
        base.chmod(0o755)  # main's private umask must not deny postgres traversal
        directory = Path(tempfile.mkdtemp(prefix='serverhub-pr14-', dir=base))
        os.chown(directory, pg.pw_uid, pg.pw_gid)
        directory.chmod(0o700)
        binary = Path('/usr/lib/postgresql/16/bin')
        started = False
        try:
            run(['runuser', '-u', 'postgres', '--', str(binary / 'initdb'), '-D', str(directory / 'data'),
                 '--auth-local=trust', '--auth-host=reject', '--no-locale', '--encoding=UTF8'], timeout=120)
            (directory / 'socket').mkdir(mode=0o700)
            os.chown(directory / 'socket', pg.pw_uid, pg.pw_gid)
            run(['runuser', '-u', 'postgres', '--', str(binary / 'pg_ctl'), '-D', str(directory / 'data'),
                 '-l', str(directory / 'postgres.log'), '-o', '-c listen_addresses= -k ' + str(directory / 'socket'),
                 '-w', 'start'])
            started = True
            env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'PGHOST': str(directory / 'socket'),
                   'PGUSER': 'postgres', 'PGDATABASE': 'postgres', 'PGCONNECT_TIMEOUT': '10'}
            run(['pg_restore', '--exit-on-error', '--no-owner', '--no-privileges', '--dbname=postgres', str(dump)],
                env=env, timeout=300)
            engine = create_engine('postgresql+psycopg://postgres@/postgres',
                                   connect_args={'host': str(directory / 'socket')})
            try:
                with Session(engine) as db:
                    need(db.scalar(text('SELECT version_num FROM alembic_version')) == SCHEMA,
                         'Restored schema mismatch')
                    need(verify_chain(db)['valid'], 'Restored audit chain invalid')
                    counts = {name: db.scalar(text('SELECT count(*) FROM ' + name))
                              for name in ['users', 'jobs', 'session_tokens', 'oauth_clients', 'oauth_pending', 'audit']}
                    need(counts['users'] > 0, 'Restored owner data missing')
                    self.report['restore'] = {'schema': SCHEMA, 'audit_chain': 'valid', 'counts': counts}
            finally:
                engine.dispose()
        finally:
            if started:
                run(['runuser', '-u', 'postgres', '--', str(binary / 'pg_ctl'), '-D', str(directory / 'data'),
                     '-m', 'immediate', '-w', 'stop'])
            # Only this freshly generated disposable cluster, never live PGDATA.
            shutil.rmtree(directory)

    def prepare(self):
        from serverhub.ops.runtime_permissions import seal_runtime
        # Copy the sealed runtime; no pip, dependency resolution, migrations or installers.
        if not self.candidate.exists():
            shutil.copytree(self.previous, self.candidate, symlinks=True,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        site = self.candidate / 'venv/lib/python3.12/site-packages'
        modules = wheel_files(self.bundle / 'application.whl')
        for name in DELTA:
            atomic_bytes(site / name, modules[name], 0o644)
        # A copied venv's console scripts otherwise execute the old interpreter.
        for path in (self.candidate / 'venv/bin').iterdir():
            if path.is_symlink() or not path.is_file():
                continue
            data = read_regular(path, protected=True)
            if data.startswith(b'#!') and str(self.previous).encode() in data.split(b'\n', 1)[0]:
                atomic_bytes(path, data.replace(str(self.previous).encode(), str(self.candidate).encode()),
                             path.stat().st_mode & 0o777)
        need(package_files(site) == self.new_hashes, 'Prepared package verification failed')
        need(tree_hashes(self.candidate / 'web') == tree_hashes(self.previous / 'web'), 'Prepared web differs')
        need(tree_hashes(self.candidate / 'migrations') == tree_hashes(self.previous / 'migrations'), 'Prepared migrations differ')
        atomic_json(self.candidate / 'installed.json', {'manifest': {'release_id': RELEASE,
                    'schema_revision': SCHEMA, 'trust_boundary_digest': NEW_TRUST,
                    'files': HASHES, 'validation': {'passed': True}},
                    'source_commit': COMMIT, 'maintenance': 'interactive offline owner PR14',
                    'wheel_sha256': WHEEL_SHA})
        (self.candidate / 'installed.json').chmod(0o644)
        seal_runtime(self.candidate)
        sync_tree(self.candidate)

    def drill(self):
        from serverhub.ops.release import ReleaseManager
        # Exercise the existing switch/rollback implementation on private trees.
        root = Path(tempfile.mkdtemp(prefix='drill-', dir=STATE))
        calls = []
        try:
            for name in ['previous', 'candidate']:
                (root / 'install/releases' / name).mkdir(parents=True)
            old = root / 'install/releases/previous'
            new = root / 'install/releases/candidate'
            (root / 'install/current').symlink_to(old)
            def recorder(argv, **kwargs):
                need(argv[0] == 'systemctl' and set(argv[2:]) <= set(SERVICES), 'Unexpected rollback service target')
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, '', '')
            rm = ReleaseManager(root / 'install', root / 'state', runner=recorder)
            rm._protect()
            rm._switch(new)
            journal = {'previous': str(old), 'candidate': str(new), 'state': 'armed'}
            config = root / 'config'
            config.mkdir(mode=0o700)
            atomic_bytes(config / 'trusted-code-hashes.json', self.new_anchor)
            atomic_bytes(config / 'trust-boundaries.sha256', self.new_trust)
            restore_checkpoint(rm, config, journal, self.old_anchor, self.old_trust, lambda: None)
            need((root / 'install/current').resolve() == old and journal['state'] == 'reverted'
                 and len(calls) == 2, 'Executable rollback drill failed')
            need((config / 'trusted-code-hashes.json').read_bytes() == self.old_anchor
                 and (config / 'trust-boundaries.sha256').read_bytes() == self.old_trust,
                 'Anchor rollback drill failed')
            self.report['rollback_drill'] = 'isolated code switch, rollback and exact anchor restore; service calls recorded'
        finally:
            shutil.rmtree(root)

    def arm(self, backup):
        self.db_check_live()
        atomic_bytes(STATE / 'old-code-anchor.json', self.old_anchor)
        atomic_bytes(STATE / 'old-trust.sha256', self.old_trust)
        atomic_bytes(STATE / 'new-code-anchor.json', self.new_anchor)
        atomic_bytes(STATE / 'new-trust.sha256', self.new_trust)
        journal = {'format': 1, 'state': 'armed', 'release_id': RELEASE, 'source_commit': COMMIT,
                   'wheel_sha256': WHEEL_SHA, 'previous': str(self.previous), 'candidate': str(self.candidate),
                   'backup_id': backup['id'], 'deadline': time.time() + 900,
                   'old_anchor_sha256': sha(self.old_anchor), 'new_anchor_sha256': sha(self.new_anchor),
                   'old_trust_sha256': sha(self.old_trust), 'new_trust_sha256': sha(self.new_trust),
                   'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                   'watchdog_sha256': sha(EXECUTING_SOURCE)}
        # Install protected copy before scheduling; it imports only recovery runtime.
        atomic_bytes(STATE / 'release_pr14.py', EXECUTING_SOURCE)
        unit = 'serverhub-ai-pr14-owner-watchdog'
        self.report['watchdog_unit'] = unit
        service = ('[Unit]\nDescription=PR14 independent code and anchor recovery\nAfter=postgresql.service\n'
                   '[Service]\nType=oneshot\nUser=root\nUMask=0077\nTimeoutStartSec=360\n'
                   'ExecStart=/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin '
                   '/opt/serverhub/recovery-ai/venv/bin/python -I ' + str(STATE / 'release_pr14.py') + ' --watchdog\n')
        timer = ('[Unit]\nDescription=PR14 durable recovery timer\n[Timer]\nOnBootSec=15s\n'
                 'OnUnitActiveSec=30s\nAccuracySec=1s\n[Install]\nWantedBy=timers.target\n')
        for suffix, content in [('service', service), ('timer', timer)]:
            target = Path('/etc/systemd/system') / (unit + '.' + suffix)
            protected_path(target.parent, directory=True)
            if target.exists():
                need(read_regular(target, protected=True) == content.encode(), 'Conflicting PR14 watchdog definition')
            else:
                atomic_bytes(target, content.encode(), 0o644)
        atomic_json(self.journal, journal)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', unit + '.timer'])
        need(run(['systemctl', 'is-active', unit + '.timer']).stdout.strip() == 'active', 'Watchdog did not arm')

    def install(self):
        with locked(STATE / 'mutation.lock'):
            value = checked_journal()
            need(value['state'] == 'armed' and time.time() < value['deadline'], 'Release deadline expired')
            need((INSTALL / 'current').resolve() == self.previous, 'Current release changed during preparation')
            atomic_bytes(CONFIG / 'trusted-code-hashes.json', self.new_anchor)
            atomic_bytes(CONFIG / 'trust-boundaries.sha256', self.new_trust, 0o644)
            self.rm._switch(self.candidate)
            sync_dir(INSTALL)
            self.restart()

    def restart(self):
        run(['systemctl', 'restart', *SERVICES[:2]])
        run(['systemctl', 'try-restart', *SERVICES[2:]])

    def accept(self):
        from serverhub.ops.verify_install import verify
        for attempt in range(15):
            try:
                with self.client() as client:
                    need(client.get('/health').json().get('status') == 'ok', 'API health failed')
                break
            except Exception:
                if attempt == 14:
                    raise Stop('API readiness timeout') from None
                time.sleep(2)
        self.services(SERVICES, active=True)
        need(self.services(UNRELATED) == self.service_snapshot, 'Unrelated service changed during release')
        self.db_check_live()
        self.oauth_checks()
        with self.client() as client:
            checks = verify(client, self.token, host_id=self.host_id, timeout=120)
        # No raw diagnostics, prompts, tokens, or HTTP response bodies in report.
        self.report['acceptance'] = [{key: c[key] for key in ['id', 'status', 'job_id', 'job_state'] if key in c}
                                     for c in checks['checks']]
        need(checks['state'] == 'passed', 'Installed API/diagnostics/persistent-job acceptance failed')
        need(package_files(self.candidate / 'venv/lib/python3.12/site-packages') == self.new_hashes,
             'Candidate changed during acceptance')

    def oauth_checks(self):
        from urllib.parse import parse_qs, urlsplit
        import base64
        with self.client() as client:
            owner = {'Authorization': 'Bearer ' + self.token, 'Origin': ORIGIN}
            response = client.get('/mcp')
            need(response.status_code == 401 and 'resource_metadata=' in response.headers.get('www-authenticate', ''),
                 'MCP challenge failed')
            metadata = client.get('/.well-known/oauth-protected-resource').json()
            need(metadata.get('resource') == ORIGIN + '/mcp', 'MCP resource discovery failed')
            discovery = client.get('/.well-known/oauth-authorization-server').json()
            need('S256' in discovery.get('code_challenge_methods_supported', []), 'OAuth PKCE discovery failed')
            callback = 'https://client.example/pr14-release-callback'
            registered = client.post('/api/mcp/clients', headers=owner,
                                     json={'name': 'PR14 release acceptance', 'redirect_uris': [callback]})
            need(registered.status_code == 201, 'OAuth test client registration failed')
            identity = registered.json()['client_id']
            try:
                verifier = secrets.token_urlsafe(48)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
                params = {'client_id': identity, 'redirect_uri': callback, 'response_type': 'code',
                          'scope': 'serverhub:read', 'code_challenge': challenge,
                          'code_challenge_method': 'S256', 'resource': ORIGIN + '/mcp'}
                for reverse in [False, True]:
                    flows = []
                    for state in ['approve', 'deny']:
                        page = client.get('/oauth/authorize', params=params | {'state': state}, headers=owner)
                        need(page.status_code == 200, 'OAuth consent page failed')
                        nonce = re.search(r'name="consent_nonce" value="([^"]+)"', page.text)
                        need(nonce is not None, 'OAuth consent nonce missing')
                        cookie = page.headers.get('set-cookie', '')
                        need(all(s in cookie.lower() for s in ['httponly', 'secure', 'samesite=strict', 'max-age=300']),
                             'OAuth cookie protection differs')
                        flows.append((nonce.group(1), state))
                    for nonce, decision in (list(reversed(flows)) if reverse else flows):
                        form = {'consent_nonce': nonce, 'decision': decision}
                        denied = client.post('/oauth/authorize', data=form, headers=owner | {'Origin': 'https://untrusted.example'})
                        need(denied.status_code == 403, 'Untrusted OAuth Origin accepted')
                        response = client.post('/oauth/authorize', data=form, headers=owner)
                        need(response.status_code == 303, 'Parallel OAuth consent failed')
                        location = urlsplit(response.headers.get('location', ''))
                        need(location.scheme == 'https' and location.netloc == 'client.example'
                             and location.path == '/pr14-release-callback', 'OAuth callback differs')
                        values = parse_qs(location.query)
                        need(values.get('state') == [decision], 'OAuth state mismatch')
                        need(client.post('/oauth/authorize', data=form, headers=owner).status_code in {400, 403},
                             'OAuth replay accepted')
                        if decision == 'deny':
                            need(values.get('error') == ['access_denied'], 'OAuth denial failed')
                            continue
                        token_form = {'grant_type': 'authorization_code', 'client_id': identity,
                                      'redirect_uri': callback, 'resource': ORIGIN + '/mcp',
                                      'code': values['code'][0], 'code_verifier': verifier}
                        need(client.post('/oauth/token', data=token_form | {'code_verifier': 'x' * 64}).status_code == 400,
                             'Invalid PKCE accepted')
                        tokens = client.post('/oauth/token', data=token_form)
                        need(tokens.status_code == 200, 'OAuth token exchange failed')
                        bearer = {'Authorization': 'Bearer ' + tokens.json()['access_token']}
                        for method in ['initialize', 'tools/list']:
                            result = client.post('/mcp', headers=bearer, json={'jsonrpc': '2.0', 'id': 1,
                                                 'method': method, 'params': {}})
                            need(result.status_code == 200 and 'result' in result.json(), 'Authenticated MCP failed')
                        allowed = client.post('/mcp', headers=bearer, json={'jsonrpc': '2.0', 'id': 3,
                                              'method': 'tools/call', 'params': {'name': 'list_hosts', 'arguments': {}}})
                        need(allowed.status_code == 200 and allowed.json().get('result', {}).get('isError') is False,
                             'Authorized read-only MCP tool failed')
                        forbidden = client.post('/mcp', headers=bearer, json={'jsonrpc': '2.0', 'id': 2,
                                                'method': 'tools/call', 'params': {'name': 'submit_job', 'arguments': {}}})
                        need(forbidden.status_code == 403, 'MCP scope denial failed')
            finally:
                need(client.delete('/api/mcp/clients/' + identity, headers=owner).status_code in {200, 204},
                     'OAuth test client revocation failed')
        self.report['oauth_mcp'] = 'parallel approve/deny both orders, replay, Origin, PKCE, authenticated MCP and scope denial passed'

    def commit(self):
        with locked(STATE / 'mutation.lock'):
            value = checked_journal()
            need(value['state'] == 'armed' and time.time() < value['deadline'], 'Watchdog expired before acceptance')
            need((INSTALL / 'current').resolve() == self.candidate, 'Candidate is no longer active')
            need(read_regular(CONFIG / 'trusted-code-hashes.json', protected=True) == self.new_anchor
                 and read_regular(CONFIG / 'trust-boundaries.sha256', protected=True) == self.new_trust,
                 'Protected anchors changed during acceptance')
            value.update(state='verified', verified_at=time.time())
            atomic_json(self.journal, value)

    def rollback(self):
        if self.journal.exists():
            recover()


def checked_journal():
    value = json.loads(read_regular(STATE / 'journal.json', private=True, protected=True))
    need(value.get('format') == 1 and value.get('release_id') == RELEASE and value.get('source_commit') == COMMIT
         and value.get('wheel_sha256') == WHEEL_SHA and value.get('previous') == str(INSTALL / 'releases' / PREVIOUS)
         and value.get('candidate') == str(INSTALL / 'releases' / RELEASE)
         and value.get('state') in {'armed', 'verified', 'reverted'}, 'Invalid PR14 recovery journal')
    for label, name in [('old_anchor', 'old-code-anchor.json'), ('new_anchor', 'new-code-anchor.json'),
                        ('old_trust', 'old-trust.sha256'), ('new_trust', 'new-trust.sha256')]:
        need(sha(read_regular(STATE / name, private=True, protected=True)) == value[label + '_sha256'],
             'Recovery anchor checksum mismatch')
    need(sha(read_regular(STATE / 'release_pr14.py', private=True, protected=True)) == value.get('watchdog_sha256'),
         'Recovery executable checksum mismatch')
    return value


def restore_checkpoint(manager, config, value, anchor, trust, health):
    """Shared by the independent recovery path and the isolated rollback drill."""
    atomic_bytes(config / 'trusted-code-hashes.json', anchor)
    atomic_bytes(config / 'trust-boundaries.sha256', trust, 0o644)
    rollback_value = dict(value)
    manager._rollback(rollback_value)
    sync_dir(manager.install_root)
    health()
    value.update(state='reverted', reverted_at=time.time())


def recover(*, expired_only=False):
    with locked(STATE / 'mutation.lock'):
        value = checked_journal()
        same_boot = value.get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if expired_only and (value['state'] != 'armed' or (same_boot and time.time() < value['deadline'])):
            return
        if value['state'] == 'reverted':
            return
        need((INSTALL / 'current').resolve() in {Path(value['previous']), Path(value['candidate'])},
             'Unrelated release active; recovery refuses substitution')
        # Recovery imports only the unchanged independent maintenance runtime.
        from serverhub.ops.release import ReleaseManager
        manager = ReleaseManager(state_root=STATE)
        manager._protect()
        restore_checkpoint(manager, CONFIG, value,
                           read_regular(STATE / 'old-code-anchor.json', protected=True),
                           read_regular(STATE / 'old-trust.sha256', protected=True),
                           lambda: run([str(Path(value['previous']) / 'venv/bin/serverhub'),
                                        'health', '--url', ORIGIN], timeout=60))
        # Only durable success after restart AND health, so repeated timers retry failures.
        atomic_json(STATE / 'journal.json', value)


def show_plan():
    print('PR14 offline owner maintenance\nRelease: ' + RELEASE + '\nCandidate: ' + COMMIT
          + '\nWheel SHA256: ' + WHEEL_SHA
          + '\nChanges: only serverhub/main.py and serverhub/mcp.py; explicit trust/code-anchor maintenance.'
          + '\nBackup: /var/backups/serverhub; restore into a separate socket-only PostgreSQL cluster.'
          + '\nRollback: exact ' + PREVIOUS + ' AND original code/trust anchors; independent 900s watchdog.'
          + '\nNo migrations, grants, dependency installation, Control/proxy restarts or recovery-runtime replacement.'
          + '\nAdds one persistent PR14-only recovery service/timer; active jobs use existing restart/recovery semantics.'
          + '\nOwner-maintenance executable SHA256: ' + sha(EXECUTING_SOURCE)
          + '\nAcceptance registers/revokes a temporary OAuth client and submits one inventory.refresh job.'
          + '\nUses an existing owner login (password hidden); no new accounts or grants.'
          + '\nReport: ' + str(STATE / 'report.json'), flush=True)


def main():
    os.umask(0o077)
    need(os.geteuid() == 0, 'Local root owner maintenance is required')
    if sys.argv[1:] == ['--watchdog']:
        need(Path(__file__) == STATE / 'release_pr14.py', 'Watchdog must run from protected installed copy')
        protected_path(Path(__file__))
        recover(expired_only=True)
        return
    need(not sys.argv[1:], 'No unattended approval or test flags are supported')
    show_plan()
    need(tty_text('Approve offline code/trust maintenance for ' + COMMIT + '? Type RELEASE PR14: ') == 'RELEASE PR14',
         'Owner declined; no release action performed')
    protected_path(STATE.parent, directory=True)
    STATE.mkdir(mode=0o700, exist_ok=True)
    protected_path(STATE, directory=True)
    need(STATE.stat().st_mode & 0o077 == 0, 'Release state must be mode 0700')
    with locked(STATE / 'owner.lock', nonblocking=True):
        if (STATE / 'journal.json').exists():
            journal = checked_journal()
            if journal['state'] == 'armed':
                recover()
                raise Stop('Interrupted release was rolled back; inspect retained evidence before retry')
            if journal['state'] == 'verified':
                need((INSTALL / 'current').resolve() == Path(journal['candidate']), 'Verified release is no longer current')
                anchor = json.loads(read_regular(CONFIG / 'trusted-code-hashes.json', protected=True))
                need(package_files(Path(journal['candidate']) / 'venv/lib/python3.12/site-packages') == anchor['files'],
                     'Installed verified release integrity differs')
                need(sha(read_regular(CONFIG / 'trusted-code-hashes.json', protected=True)) == journal['new_anchor_sha256']
                     and sha(read_regular(CONFIG / 'trust-boundaries.sha256', protected=True)) == journal['new_trust_sha256'],
                     'Verified release anchors differ')
                run([str(Path(journal['candidate']) / 'venv/bin/serverhub'), 'health', '--url', ORIGIN], timeout=60)
                print('Already installed and verified: ' + RELEASE)
                return
            need((INSTALL / 'current').resolve() == Path(journal['previous']), 'Reverted release is no longer current')
            atomic_json(STATE / ('journal-reverted-' + str(time.time_ns()) + '.json'), journal)
        report = {'release_id': RELEASE, 'candidate_commit': COMMIT, 'wheel_sha256': WHEEL_SHA,
                  'started_at': time.time(), 'state': 'preparing', 'offline_owner_approval': True}
        host = NativeHost(report)
        try:
            bundle = STATE / 'artifacts'
            bundle.mkdir(mode=0o700, exist_ok=True)
            protected_path(bundle, directory=True)
            for name, checksum in HASHES.items():
                data = read_regular(EVIDENCE / 'unsigned-bundle' / name)
                need(sha(data) == checksum, 'Pinned artifact mismatch: ' + name)
                if (bundle / name).exists():
                    need(read_regular(bundle / name, protected=True) == data, 'Prior staging differs from pinned artifact')
                else:
                    atomic_bytes(bundle / name, data)
            data = read_regular(EVIDENCE / 'owner-reviewed-source-3e9a2f4.tar.gz')
            need(sha(data) == SOURCE_SHA, 'Pinned source archive mismatch')
            atomic_bytes(STATE / 'reviewed-source.tar.gz', data)
            verify_files(bundle, HASHES)
            def interrupted(signum, frame):
                raise Stop('Owner release interrupted')
            signal.signal(signal.SIGTERM, interrupted)
            signal.signal(signal.SIGINT, interrupted)
            transact(host, report)
        finally:
            try:
                host.close()
                report['temporary_login_cleanup'] = 'passed'
            except BaseException:
                report['temporary_login_cleanup'] = 'failed; session expires under existing policy'
            if report['state'] == 'preparing':
                report['state'] = 'failed_before_transaction'
            report['finished_at'] = time.time()
            atomic_json(STATE / 'report.json', report)
        print('Installed and verified: ' + RELEASE + '; report ' + str(STATE / 'report.json'))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        # Never format exceptions: database/HTTP/subprocess exceptions can contain secrets.
        print('PR14 release stopped. Inspect the protected report and journal; no secrets are printed.', file=sys.stderr)
        sys.exit(1)
