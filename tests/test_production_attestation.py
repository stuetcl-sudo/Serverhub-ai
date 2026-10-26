import importlib.util
from pathlib import Path
import subprocess

import pytest

spec = importlib.util.spec_from_file_location('attest', Path(__file__).parents[1] / 'scripts/attest-production.py')
attest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(attest)


def test_schema_uses_api_read_only_no_secret_output(monkeypatch, tmp_path):
    config = tmp_path / 'api.env'
    config.write_text('SERVERHUB_DATABASE_URL=postgresql+psycopg://serverhub_api:TOPSECRET@127.0.0.1/serverhub\n')
    monkeypatch.setattr(attest, 'sealed', lambda _: config)
    def run(argv, env):
        assert env['PGUSER'] == 'serverhub_api'
        assert 'default_transaction_read_only=on' in env['PGOPTIONS']
        assert env['PGPASSWORD'] == 'TOPSECRET'
        assert 'TOPSECRET' not in repr(argv)
        assert argv[-1] == 'SELECT version_num FROM public.alembic_version'
        return '0006_pause_clock\n'
    monkeypatch.setattr(attest, 'run', run)
    assert attest.schema() == {'revision': '0006_pause_clock', 'role': 'serverhub_api', 'read_only': True}


@pytest.mark.parametrize('url', ['postgresql+psycopg://serverhub_migrate:secret@localhost/serverhub',
                                'postgresql+psycopg://serverhub_api:secret@remote/serverhub'])
def test_rejects_privileged_or_remote_database(monkeypatch, tmp_path, url):
    config = tmp_path / 'env'
    config.write_text('SERVERHUB_DATABASE_URL=' + url)
    monkeypatch.setattr(attest, 'sealed', lambda _: config)
    with pytest.raises(ValueError):
        attest.schema()


def test_command_failure_never_discloses_output(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 1, 'SECRET', 'PASSWORD'))
    with pytest.raises(ValueError, match='^read command failed$'):
        attest.run(['psql'])


def test_symlink_tree_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(attest, 'sealed', lambda p: p)
    (tmp_path / 'escape').symlink_to('/etc/passwd')
    with pytest.raises(ValueError, match='symlink'):
        attest.hashes(tmp_path)


def test_failure_closed_and_sanitized(monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError('PASSWORD')
    monkeypatch.setattr(attest, 'services', fail)
    monkeypatch.setattr(attest, 'hashes', fail)
    monkeypatch.setattr(attest, 'schema', fail)
    report = attest.collect()
    assert not report['local_integrity_checks_passed']
    assert not report['production_install_authorized']
    assert 'PASSWORD' not in repr(report)
    assert report['errors']


def test_runtime_exact_anchor_and_dependency_evidence(monkeypatch, tmp_path):
    site = tmp_path / 'venv/lib/python3.12/site-packages/serverhub'
    site.mkdir(parents=True)
    (site / '__init__.py').write_text('# reviewed')
    monkeypatch.setattr(attest, 'sealed', lambda p: p)
    expected = {'serverhub/__init__.py': attest.digest(site / '__init__.py')}
    assert attest.runtime(tmp_path, {'files': expected})['matches_code_anchor']
    (site / 'extra.py').write_text('# unexpected')
    assert not attest.runtime(tmp_path, {'files': expected})['matches_code_anchor']


def snapshots():
    import copy
    baseline = attest.recovery_baseline()
    before = {u: {'properties': {'Id': u}, 'file_hashes': {}} for u in attest.UNITS}
    service, timer = 'serverhub-ai-recovery.service', 'serverhub-ai-recovery.timer'
    for u in (service, timer):
        path = '/etc/systemd/system/' + u
        before[u] = {'properties': {'FragmentPath': path, 'DropInPaths': '', 'LoadState': 'loaded'},
                     'file_hashes': {path: baseline['units'][u]}}
    before[service]['properties'].update(Type='oneshot', Restart='no', Result='success', ExecMainStatus='0',
                                        User='root', TriggeredBy=timer, ActiveState='inactive', SubState='dead',
                                        MainPID='0', ExecMainStartTimestampMonotonic='10')
    before[timer]['properties'].update(ActiveState='active', SubState='waiting', Triggers=service)
    after = copy.deepcopy(before)
    after[service]['properties'].update(ActiveState='activating', SubState='start', MainPID='123',
                                       ExecMainStartTimestampMonotonic='20')
    return before, after, baseline


def test_scheduled_oneshot_is_stable():
    assert attest.stable_services(*snapshots())


@pytest.mark.parametrize('field,value', [('Result', 'exit-code'), ('ExecMainStatus', '1'),
                                        ('Type', 'simple'), ('Restart', 'always'), ('User', 'nobody'),
                                        ('TriggeredBy', ''), ('ActiveState', 'failed'),
                                        ('DropInPaths', '/override.conf')])
def test_watchdog_failures_and_identity_changes_rejected(field, value):
    before, after, baseline = snapshots()
    after['serverhub-ai-recovery.service']['properties'][field] = value
    assert not attest.stable_services(before, after, baseline)


def test_timer_and_control_changes_rejected():
    before, after, baseline = snapshots()
    after['serverhub-ai-recovery.timer']['properties']['Triggers'] = 'other.service'
    assert not attest.stable_services(before, after, baseline)
    before, after, baseline = snapshots()
    after['serverhub-worker.service']['properties']['MainPID'] = 'new'
    assert not attest.stable_services(before, after, baseline)
    before, after, baseline = snapshots()
    after['serverhub-ai-recovery.timer']['file_hashes']['/extra'] = 'bad'
    assert not attest.stable_services(before, after, baseline)


def test_intermediate_journal_failure_is_not_hidden(monkeypatch):
    monkeypatch.setattr(attest, 'run', lambda args: '\n'.join([
        '{"PRIORITY":"6","SERVICE_RESULT":"exit-code","MESSAGE":"SECRET"}',
        '{"PRIORITY":"6","SERVICE_RESULT":"success"}']))
    assert attest.watchdog_errors('2026-10-26') == {'errors_observed': 1}


def test_recovery_baseline_is_independent_and_not_ignored():
    baseline = attest.recovery_baseline()
    assert baseline['source_commit'] == '42483fb0fe59f76e783ca309aff1ac381dd24d84'
    assert baseline['files']['serverhub/main.py'] == '013f86846598bacfbea164980df8b13197fdeb1af550883c00e920e7b7d83bfd'
    assert baseline['files']['serverhub/mcp.py'] == '88219757fe8b54a5242ecf21f667b404b8a049848a47fbef250099388fbcf79f'
    assert len(baseline['files']) == 65


def test_baseline_tampering_rejected(monkeypatch):
    monkeypatch.setattr(attest, 'BASELINE_SHA256', '0' * 64)
    with pytest.raises(ValueError, match='baseline digest mismatch'):
        attest.recovery_baseline()
