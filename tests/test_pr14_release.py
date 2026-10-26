"""Owner-maintenance transaction tests use private files and a fake host only."""
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest
from test_control_plane import control  # noqa: F401


def load_release():
    path = Path(__file__).parents[1] / 'scripts/release_pr14.py'
    assert path.is_file(), 'PR14 owner release implementation is missing'
    spec = importlib.util.spec_from_file_location('release_pr14', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_entrypoint_exists_and_has_no_unattended_approval():
    path = Path(__file__).parents[1] / 'scripts/release-pr14.sh'
    assert path.is_file(), 'owner entrypoint is missing'
    assert '--yes' not in path.read_text()


def test_shell_bootstrap_pins_exact_helper():
    m = load_release()
    wrapper = (Path(__file__).parents[1] / 'scripts/release-pr14.sh').read_text()
    assert 'release_helper_sha=' + m.sha(Path(m.__file__).read_bytes()) in wrapper


def test_declining_owner_approval_creates_no_release_state(tmp_path, monkeypatch, capsys):
    m = load_release()
    monkeypatch.setattr(m.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(m.sys, 'argv', ['release_pr14.py'])
    monkeypatch.setattr(m, 'STATE', tmp_path / 'not-created')
    monkeypatch.setattr(m, 'tty_text', lambda prompt: 'no')
    with pytest.raises(m.Stop, match='Owner declined'):
        m.main()
    assert not m.STATE.exists()
    output = capsys.readouterr().out
    assert m.RELEASE in output and '/var/backups/serverhub' in output and m.PREVIOUS in output


def test_artifact_tampering_is_rejected_before_host_changes(tmp_path):
    m = load_release()
    artifact = tmp_path / 'application.whl'
    artifact.write_bytes(b'tampered')
    with pytest.raises(m.Stop):
        m.verify_files(tmp_path, {'application.whl': '0' * 64})


def test_atomic_state_and_permissions(tmp_path):
    m = load_release()
    path = tmp_path / 'journal.json'
    m.atomic_json(path, {'state': 'armed', 'wheel_sha256': m.WHEEL_SHA})
    assert json.loads(path.read_text())['wheel_sha256'] == m.WHEEL_SHA
    assert path.stat().st_mode & 0o777 == 0o600
    link = tmp_path / 'link'
    link.symlink_to(path)
    with pytest.raises(m.Stop):
        m.atomic_json(link, {})


class FakeHost:
    def __init__(self, root, fail=None):
        self.root, self.fail = root, fail
        self.events = []
        self.current = 'old'
        self.anchors = 'old'

    def step(self, name):
        self.events.append(name)
        if self.fail == name:
            raise RuntimeError('sensitive token=do-not-report')

    def preflight(self):
        self.step('preflight')

    def backup_restore(self):
        self.step('backup_restore')
        return {'id': 'fresh-backup', 'restore': 'verified'}

    def prepare(self):
        self.step('prepare')

    def drill(self):
        self.step('drill')

    def arm(self, backup):
        self.step('arm')

    def install(self):
        self.anchors = 'candidate'
        self.step('anchor_write')
        self.current = 'candidate'
        self.step('switch')

    def accept(self):
        self.step('accept')

    def commit(self):
        self.step('commit')

    def rollback(self):
        self.events.append('rollback')
        self.current = self.anchors = 'old'


def test_success_orders_restore_drill_and_arm_before_install(tmp_path):
    m = load_release()
    host = FakeHost(tmp_path)
    report = {}
    m.transact(host, report)
    assert host.events == ['preflight', 'backup_restore', 'prepare', 'drill',
                           'arm', 'anchor_write', 'switch', 'accept', 'commit']
    assert report['state'] == 'verified'


@pytest.mark.parametrize('failure', ['preflight', 'backup_restore', 'prepare', 'drill',
                                      'arm', 'anchor_write', 'switch', 'accept', 'commit'])
def test_failures_never_leave_changed_code_or_anchors(tmp_path, failure):
    m = load_release()
    host = FakeHost(tmp_path, failure)
    report = {}
    with pytest.raises(m.Stop):
        m.transact(host, report)
    assert host.current == host.anchors == 'old'
    assert 'do-not-report' not in json.dumps(report)
    if failure in {'anchor_write', 'switch', 'accept', 'commit', 'arm'}:
        assert host.events[-1] == 'rollback'
    else:
        assert 'rollback' not in host.events


@pytest.fixture
def recovery_tree(tmp_path, monkeypatch):
    """Run the real journal and rollback code, substituting only service effects."""
    m = load_release()
    from serverhub.ops.release import ReleaseManager
    for name in ['INSTALL', 'CONFIG', 'STATE']:
        path = tmp_path / name.lower()
        path.mkdir()
        monkeypatch.setattr(m, name, path)
    monkeypatch.setattr(m, 'protected_path', lambda *args, **kwargs: None)
    read = m.read_regular
    monkeypatch.setattr(m, 'read_regular', lambda path, **kwargs: read(path, **(kwargs | {'protected': False})))
    for name in [m.PREVIOUS, m.RELEASE]:
        (m.INSTALL / 'releases' / name).mkdir(parents=True)
    previous = m.INSTALL / 'releases' / m.PREVIOUS
    candidate = m.INSTALL / 'releases' / m.RELEASE
    (m.INSTALL / 'current').symlink_to(candidate)
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, '', '')
    class PrivateManager(ReleaseManager):
        def __init__(self, **kwargs):
            super().__init__(m.INSTALL, m.STATE, require_root=False, runner=runner)
    monkeypatch.setattr('serverhub.ops.release.ReleaseManager', PrivateManager)
    monkeypatch.setattr(m, 'run', runner)
    journal = {'format': 1, 'state': 'armed', 'release_id': m.RELEASE,
               'source_commit': m.COMMIT, 'wheel_sha256': m.WHEEL_SHA,
               'previous': str(previous), 'candidate': str(candidate),
               'deadline': 0, 'boot_id': 'old-boot', 'backup_id': 'private-backup'}
    for label, name in [('old_anchor', 'old-code-anchor.json'), ('new_anchor', 'new-code-anchor.json'),
                        ('old_trust', 'old-trust.sha256'), ('new_trust', 'new-trust.sha256')]:
        content = label.encode()
        m.atomic_bytes(m.STATE / name, content)
        journal[label + '_sha256'] = m.sha(content)
    source = Path(m.__file__).read_bytes()
    m.atomic_bytes(m.STATE / 'release_pr14.py', source)
    journal['watchdog_sha256'] = m.sha(source)
    m.atomic_json(m.STATE / 'journal.json', journal)
    m.atomic_bytes(m.CONFIG / 'trusted-code-hashes.json', b'new_anchor')
    m.atomic_bytes(m.CONFIG / 'trust-boundaries.sha256', b'new_trust')
    return m, calls


def test_real_recovery_restores_mixed_anchors_and_code(recovery_tree):
    m, calls = recovery_tree
    # Model process death after only one anchor write.
    m.atomic_bytes(m.CONFIG / 'trust-boundaries.sha256', b'old_trust')
    m.recover(expired_only=True)
    assert (m.INSTALL / 'current').resolve().name == m.PREVIOUS
    assert (m.CONFIG / 'trusted-code-hashes.json').read_bytes() == b'old_anchor'
    assert (m.CONFIG / 'trust-boundaries.sha256').read_bytes() == b'old_trust'
    assert m.checked_journal()['state'] == 'reverted'
    assert len(calls) >= 3  # real rollback restart commands and health probe


def test_failed_rollback_health_remains_retryable(recovery_tree, monkeypatch):
    m, calls = recovery_tree
    normal_run = m.run
    def fail_health(argv, **kwargs):
        raise m.Stop('health failure')
    monkeypatch.setattr(m, 'run', fail_health)
    with pytest.raises(m.Stop):
        m.recover(expired_only=True)
    assert m.checked_journal()['state'] == 'armed'
    monkeypatch.setattr(m, 'run', normal_run)
    m.recover(expired_only=True)
    assert m.checked_journal()['state'] == 'reverted'


def test_reboot_recovers_even_before_wallclock_deadline(recovery_tree):
    m, _ = recovery_tree
    journal = m.checked_journal()
    journal['deadline'] = 10**12
    m.atomic_json(m.STATE / 'journal.json', journal)
    m.recover(expired_only=True)
    assert (m.INSTALL / 'current').resolve().name == m.PREVIOUS


def test_recovery_rejects_tampered_watchdog(recovery_tree):
    m, _ = recovery_tree
    (m.STATE / 'release_pr14.py').write_text('malicious replacement')
    with pytest.raises(m.Stop):
        m.recover()
    assert (m.INSTALL / 'current').resolve().name == m.RELEASE


def test_verified_rerun_checks_integrity_without_reinstalling(recovery_tree, monkeypatch, capsys):
    import contextlib
    m, calls = recovery_tree
    site = m.INSTALL / 'releases' / m.RELEASE / 'venv/lib/python3.12/site-packages'
    (site / 'serverhub').mkdir(parents=True)
    (site / 'serverhub/main.py').write_bytes(b'approved code')
    anchor = json.dumps({'format': 1, 'files': {'serverhub/main.py': m.sha(b'approved code')}}).encode()
    m.atomic_bytes(m.STATE / 'new-code-anchor.json', anchor)
    m.atomic_bytes(m.CONFIG / 'trusted-code-hashes.json', anchor)
    journal = json.loads((m.STATE / 'journal.json').read_text())
    journal.update(state='verified', new_anchor_sha256=m.sha(anchor))
    m.atomic_json(m.STATE / 'journal.json', journal)
    m.STATE.chmod(0o700)
    monkeypatch.setattr(m.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(m.sys, 'argv', ['release_pr14.py'])
    monkeypatch.setattr(m, 'locked', lambda *args, **kwargs: contextlib.nullcontext())
    monkeypatch.setattr(m, 'tty_text', lambda prompt: 'RELEASE PR14')
    m.main()
    assert 'Already installed and verified' in capsys.readouterr().out
    assert len(calls) == 1 and 'health' in calls[0]
    assert not (m.STATE / 'artifacts').exists()


def test_hash_read_rejects_symlinks_and_hardlinks(tmp_path):
    m = load_release()
    file = tmp_path / 'artifact'
    file.write_bytes(b'approved')
    link = tmp_path / 'symlink'
    link.symlink_to(file)
    with pytest.raises(OSError):
        m.read_regular(link)
    import os
    os.link(file, tmp_path / 'hardlink')
    with pytest.raises(m.Stop):
        m.read_regular(file)


def test_protected_paths_reject_user_writable_ancestor(tmp_path):
    m = load_release()
    with pytest.raises(m.Stop):
        m.protected_path(tmp_path)


def test_candidate_sync_flushes_files_and_directories_without_following_links(tmp_path, monkeypatch):
    import os
    m = load_release()
    root = tmp_path / 'candidate'
    root.mkdir()
    (root / 'module.py').write_text('approved')
    outside = tmp_path / 'outside'
    outside.write_text('not candidate')
    (root / 'interpreter').symlink_to(outside)
    synced = []
    fsync = os.fsync
    def record(fd):
        synced.append(Path(os.readlink('/proc/self/fd/' + str(fd))))
        fsync(fd)
    monkeypatch.setattr(m.os, 'fsync', record)
    m.sync_tree(root)
    assert root / 'module.py' in synced and root in synced and root.parent in synced
    assert outside not in synced


def test_rollback_failure_is_not_reported_as_reverted(tmp_path):
    m = load_release()
    class BrokenRollback(FakeHost):
        def rollback(self):
            raise RuntimeError('password=secret')
    report = {}
    with pytest.raises(m.Stop):
        m.transact(BrokenRollback(tmp_path, 'accept'), report)
    assert report['state'] == 'rollback_failed'
    assert 'secret' not in json.dumps(report)


def test_oauth_acceptance_against_real_isolated_api(control, monkeypatch):  # noqa: F811
    m = load_release()
    from serverhub.settings import get_settings
    client, headers, _ = control
    settings = get_settings()
    monkeypatch.setattr(settings, 'dev_mode', False)
    monkeypatch.setattr(settings, 'public_url', 'https://testserver')
    client.base_url = 'https://testserver'
    client.follow_redirects = False
    monkeypatch.setattr(m, 'ORIGIN', 'https://testserver')
    host = m.NativeHost({})
    host.token = headers['Authorization'].removeprefix('Bearer ')
    monkeypatch.setattr(host, 'client', lambda: client)
    host.oauth_checks()
    assert 'passed' in host.report['oauth_mcp']


def test_owner_login_uses_existing_api_without_persisting_credentials(control, monkeypatch, tmp_path):  # noqa: F811
    m = load_release()
    import getpass
    client, _, _ = control
    monkeypatch.setattr(m, 'ORIGIN', 'http://testserver')
    configuration = tmp_path / 'owner-config'
    configuration.mkdir()
    monkeypatch.setattr(m, 'CONFIG', configuration)
    monkeypatch.setattr(m, 'tty_text', lambda prompt: 'owner', raising=False)
    monkeypatch.setattr(getpass, 'getpass', lambda *args, **kwargs: 'strong-test-password-42')
    host = m.NativeHost({})
    host.authenticate(client)
    assert host.created_session
    assert client.get('/api/auth/me', headers={'Authorization': 'Bearer ' + host.token}).status_code == 200
    assert 'strong-test-password-42' not in json.dumps(host.report)
    assert list(configuration.iterdir()) == []
    token = host.token
    monkeypatch.setattr(host, 'client', lambda: client)
    host.close()
    assert not host.created_session
    assert client.get('/api/auth/me', headers={'Authorization': 'Bearer ' + token}).status_code == 401


@pytest.mark.parametrize('corruption', [None, 'schema', 'audit', 'dump'])
def test_real_isolated_postgresql_restore(monkeypatch, corruption):
    """A real pg_dump/pg_restore; no production DB, account or systemd access."""
    import os
    import shutil
    import tempfile
    from types import SimpleNamespace
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session
    from serverhub.models import Base, User
    import serverhub.oauth_models  # noqa: F401 -- register OAuth table metadata
    from serverhub.audit import append_audit

    binary = Path('/usr/lib/postgresql/16/bin')
    if not (binary / 'initdb').exists() or os.geteuid() == 0:
        pytest.skip('PostgreSQL 16 binaries and a non-root disposable test user required')
    m = load_release()
    directory = Path(tempfile.mkdtemp(prefix='pr14pg-'))
    source = directory / 'source'
    socket = directory / 'sock'
    socket.mkdir()
    def command(argv, **kwargs):
        return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=60, **kwargs)
    command([str(binary / 'initdb'), '-D', str(source), '--auth=trust', '--no-locale', '--encoding=UTF8'])
    command([str(binary / 'pg_ctl'), '-D', str(source), '-l', str(directory / 'log'),
             '-o', '-c listen_addresses= -k ' + str(socket), '-w', 'start'])
    try:
        engine = create_engine('postgresql+psycopg:///postgres', connect_args={'host': str(socket)})
        try:
            Base.metadata.create_all(engine)
            with engine.begin() as connection:
                connection.execute(text('CREATE TABLE alembic_version (version_num varchar(32))'))
                connection.execute(text('INSERT INTO alembic_version VALUES (:schema)'), {'schema': m.SCHEMA})
            with Session(engine) as db:
                db.add(User(username='isolated-owner', password_hash='fixture-only', role='owner'))
                append_audit(db, 'isolated-owner', 'release.restore.test')
                db.commit()
            if corruption == 'schema':
                with engine.begin() as connection:
                    connection.execute(text("UPDATE alembic_version SET version_num = '0003_schedules'"))
            if corruption == 'audit':
                with engine.begin() as connection:
                    connection.execute(text("UPDATE audit SET hash = 'corrupted'"))
            dump = directory / 'postgres.dump'
            env = dict(os.environ, PGHOST=str(socket), PGDATABASE='postgres')
            command([str(binary / 'pg_dump'), '--format=custom', '--file', str(dump)], env=env)
            if corruption == 'dump':
                dump.write_bytes(b'invalid archive')
            monkeypatch.setattr(m, 'RESTORE_ROOT', directory / 'restore')
            monkeypatch.setattr(m, 'protected_path', lambda *args, **kwargs: None)
            monkeypatch.setattr(m.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
            normal_run = m.run
            def local_user_run(argv, **kwargs):
                return normal_run(argv[4:] if argv[0] == 'runuser' else argv, **kwargs)
            monkeypatch.setattr(m, 'run', local_user_run)
            host = m.NativeHost({})
            # Source cluster's initial role matches current user; restore uses postgres.
            # initdb for destination must explicitly create the postgres role.
            original_run = m.run
            def postgres_initdb(argv, **kwargs):
                if 'initdb' in str(argv):
                    argv = argv + ['--username=postgres']
                return original_run(argv, **kwargs)
            monkeypatch.setattr(m, 'run', postgres_initdb)
            previous_umask = os.umask(0o077)
            try:
                if corruption:
                    with pytest.raises(m.Stop):
                        host.isolated_restore(dump)
                else:
                    host.isolated_restore(dump)
                    assert host.report['restore']['schema'] == m.SCHEMA
                    assert host.report['restore']['audit_chain'] == 'valid'
                    assert host.report['restore']['counts']['users'] == 1
            finally:
                os.umask(previous_umask)
            assert (directory / 'restore').stat().st_mode & 0o777 == 0o755
            assert list((directory / 'restore').iterdir()) == []
        finally:
            engine.dispose()
    finally:
        command([str(binary / 'pg_ctl'), '-D', str(source), '-m', 'immediate', '-w', 'stop'])
        shutil.rmtree(directory)
