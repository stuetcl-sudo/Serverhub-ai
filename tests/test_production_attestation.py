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
