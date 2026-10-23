"""Actual legacy 1905abc -> namespaced release upgrade, rollback and retry.

Run only on a fresh disposable GitHub Ubuntu VM, separately from Control fixtures.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
from serverhub.ops.migrate_units import plan, migrate
from serverhub.ops.installer import Installer
from unittest.mock import patch

if os.environ.get('SERVERHUB_DISPOSABLE_TEST') != 'fresh-ubuntu-ci' or not os.environ.get('GITHUB_ACTIONS') or os.geteuid():
    raise SystemExit('Disposable root Ubuntu CI only')
if Path('/etc/serverhub').exists() or Path('/opt/serverhub-control').exists():
    raise SystemExit('Refusing existing installation')
# Use an ordinary secure Ubuntu operator umask for the exact older installer.
# The candidate itself sets metadata modes explicitly, independent of umask.
os.umask(0o022)
source = Path(__file__).resolve().parents[1]
legacy = Path(sys.argv[1]).resolve()
subprocess.run([sys.executable, '-m', 'serverhub.ops.installer', '--source', str(legacy), '--apply',
                '--public-url', 'https://migration.test', '--ai-identity', '--enable-broker', '--owner-password-stdin'],
               env=dict(os.environ, PYTHONPATH=str(legacy / 'src')),
               input='isolated-migration-test-password-42\n', text=True, check=True)


before = {name: Path('/etc/serverhub', name).read_bytes() for name in ('api.env', 'worker.env', 'recovery.env', 'node.yaml', 'broker.yaml')}
previous = Path('/opt/serverhub/current').resolve()
metadata = (previous / 'installed.json').stat()
print('LEGACY_METADATA=' + json.dumps({'uid': metadata.st_uid, 'gid': metadata.st_gid, 'mode': oct(metadata.st_mode & 0o777)}), flush=True)
assert plan(source)['state'] == 'reviewed'
# Real services, DB migration and backup run, then acceptance deliberately fails.
with patch.object(Installer, '_healthchecks', side_effect=RuntimeError('Intentional namespace health failure')):
    try:
        migrate(source, repair_legacy_permissions=True)
    except RuntimeError as error:
        assert 'Intentional' in str(error)
    else:
        raise AssertionError('Expected migration rollback')
assert Path('/opt/serverhub/current').resolve() == previous
assert not Path('/var/lib/serverhub-install/ownership.json').exists()
assert json.loads(Path('/var/lib/serverhub-install/unit-migration.json').read_text())['state'] == 'reverted'
for name, content in before.items():
    assert Path('/etc/serverhub', name).read_bytes() == content
for unit in ['serverhub-api.service', 'serverhub-worker.service', 'serverhub-broker.service']:
    subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True)

assert migrate(source, repair_legacy_permissions=True)['state'] == 'migrated'
for name in ('api.env', 'worker.env', 'recovery.env'):
    assert Path('/etc/serverhub', name).read_bytes() == before[name]
for unit in ['serverhub-ai-api.service', 'serverhub-ai-worker.service', 'serverhub-ai-broker.service']:
    subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True)
for unit in ['serverhub-api.service', 'serverhub-worker.service', 'serverhub-broker.service']:
    assert not Path('/etc/systemd/system', unit).exists()
assert '/run/serverhub-ai-broker/control.sock' in Path('/etc/serverhub/broker.yaml').read_text()
assert Path('/opt/serverhub/recovery/venv/bin/python').exists(), 'Legacy independent recovery retained'
assert Path('/opt/serverhub/recovery-ai/venv/bin/python').exists()
print('LEGACY_UNIT_MIGRATION_EVIDENCE=' + json.dumps({'state': 'passed',
    'legacy_commit': '1905abcc244767cc58a2dbbf950e033be940c6ed',
    'intentional_failed_health_rollback': True, 'credentials_retained': True,
    'retry_succeeded': True, 'new_units_active': True, 'production_modified': False}), flush=True)
