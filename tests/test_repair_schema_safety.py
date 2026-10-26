import pytest

from serverhub.ops.installer import InstallError


def test_schema_change_rejected_before_backup_or_runtime_mutation(monkeypatch):
    from serverhub.ops.repair import require_compatible_schema
    monkeypatch.setattr('serverhub.ops.repair.read_schema_revision', lambda url: '0006_pause_clock')
    with pytest.raises(InstallError, match='schema-changing repair is blocked'):
        require_compatible_schema('not-exposed')


def test_same_schema_is_permitted(monkeypatch):
    from serverhub.ops.repair import require_compatible_schema
    monkeypatch.setattr('serverhub.ops.repair.read_schema_revision', lambda url: '0007_job_controls')
    assert require_compatible_schema('not-exposed') == '0007_job_controls'


@pytest.mark.parametrize('recorded,actual,previous_revision', [
    (None, '0007_job_controls', '0006_pause_clock'),
    ('0006_pause_clock', '0007_job_controls', '0006_pause_clock'),
    ('0007_job_controls', None, '0006_pause_clock'),
    ('0007_job_controls', '0007_job_controls', '0006_pause_clock'),
])
def test_independent_watchdog_blocks_unproven_repair_rollback(tmp_path, monkeypatch, recorded, actual, previous_revision):
    from serverhub.ops.release import ReleaseManager, ReleaseError
    import serverhub.ops.repair as repair
    import json
    install = tmp_path / 'install'
    previous = install / 'releases/previous'
    candidate = install / 'releases/candidate'
    previous.mkdir(parents=True)
    candidate.mkdir()
    (install / 'current').symlink_to(candidate)
    (previous / 'installed.json').write_text(json.dumps({'manifest': {'schema_revision': previous_revision}}))
    calls = []
    manager = ReleaseManager(install, tmp_path / 'state', require_root=False, clock=lambda: 100)
    manager._protect()
    monkeypatch.setattr(manager, '_run', lambda command: calls.append(command))
    monkeypatch.setattr(repair, 'read_environment', lambda path: {'SERVERHUB_DATABASE_URL': 'private'})
    def revision(url):
        if actual is None:
            raise InstallError('unavailable')
        return actual
    monkeypatch.setattr(repair, 'read_schema_revision', revision)
    journal = {'state': 'armed', 'release_id': 'repair-test', 'previous': str(previous),
               'candidate': str(candidate), 'deadline': 99}
    if recorded:
        journal['repair_schema_revision'] = recorded
    manager._write_journal(journal)
    with pytest.raises(ReleaseError, match='rollback blocked'):
        manager.watchdog()
    assert (install / 'current').resolve() == candidate
    assert calls == [['systemctl', 'stop', 'serverhub-ai-api.service', 'serverhub-ai-worker.service']]
    assert json.loads((tmp_path / 'state/pending.json').read_text())['state'] == 'manual_recovery_required'
    assert manager.watchdog()['state'] == 'manual_recovery_required'


def test_database_probe_errors_do_not_expose_password(monkeypatch):
    from serverhub.ops.repair import read_schema_revision
    import psycopg
    def fail(*args, **kwargs):
        raise RuntimeError('secret-password')
    monkeypatch.setattr(psycopg, 'connect', fail)
    with pytest.raises(InstallError) as error:
        read_schema_revision('postgresql://user:secret-password@localhost/serverhub')
    assert 'secret-password' not in str(error.value)
