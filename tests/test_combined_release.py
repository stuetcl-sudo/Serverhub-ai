"""Pin the exact approved OAuth runtime while extending the autopilot base."""
import hashlib
from pathlib import Path


def test_oauth_runtime_bytes_preserved_from_reviewed_pr14():
    expected = {'main.py': '347e4fa919f8927e242515987fd02cf550209704c78a147f8e0235ca559c96ca', 'mcp.py': '43ed7629f3f9a1a6d66bde70da9f106488a23b89a47a2aca6c3863dc2e32e9eb'}
    for name, digest in expected.items():
        assert hashlib.sha256((Path("src/serverhub") / name).read_bytes()).hexdigest() == digest


def test_autopilot_migration_and_protected_grants_preserved():
    assert Path('migrations/versions/0007_job_controls.py').is_file()
    grants = Path('packaging/postgresql-grants.sql').read_text()
    assert 'GRANT SELECT, INSERT, UPDATE ON job_control_state TO serverhub_api, serverhub_worker;' in grants
    assert 'enrollments, system_state, backups FROM serverhub_worker;' in grants
