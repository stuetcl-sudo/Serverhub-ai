"""Actual legacy 1905abc -> namespaced release upgrade, rollback and retry.

Run only on a fresh disposable GitHub Ubuntu VM, separately from Control fixtures.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from serverhub.ops.migrate_units import plan, migrate, legacy_resources
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


namespaced = Path('/var/lib/serverhub-install/ownership.json').exists()
old_units = ['serverhub-ai-api.service', 'serverhub-ai-worker.service', 'serverhub-ai-broker.service'] if namespaced else ['serverhub-api.service', 'serverhub-worker.service', 'serverhub-broker.service']
old_claim = Path('/var/lib/serverhub-install/ownership.json').read_bytes() if namespaced else None
old_identities = {name: subprocess.check_output(['getent', 'passwd', name]) for name in ['serverhub-api', 'serverhub-worker', 'serverhub-node', 'serverhub-migrate', 'serverhub-staging']}
before = {name: Path('/etc/serverhub', name).read_bytes() for name in ('api.env', 'worker.env', 'recovery.env', 'node.yaml', 'broker.yaml')}
previous = Path('/opt/serverhub/current').resolve()
metadata = (previous / 'installed.json').stat()
print('LEGACY_METADATA=' + json.dumps({'uid': metadata.st_uid, 'gid': metadata.st_gid, 'mode': oct(metadata.st_mode & 0o777)}), flush=True)
assert plan(source)['state'] == 'reviewed'
# Kill the migration after namespace conversion but before reviewed repair.
# Only the installed standalone systemd timer can recover this dead process.
child = "from unittest.mock import patch; import os, signal; from pathlib import Path; from serverhub.ops.migrate_units import migrate; "
child += "killer=lambda *args,**kwargs: os.kill(os.getpid(), signal.SIGKILL); "
child += "context=patch('serverhub.ops.repair.repair', side_effect=killer); context.start(); "
child += "migrate(Path(" + repr(str(source)) + "), repair_legacy_permissions=True)"
process = subprocess.run([sys.executable, '-c', child], env=dict(os.environ, PYTHONPATH=str(source / 'src')))
assert process.returncode == -9, 'Expected real killed migration process'
migration_journal = Path('/var/lib/serverhub-install/unit-migration.json')
armed = json.loads(migration_journal.read_text())
assert armed['state'] == 'armed'
armed['deadline'] = 0  # deterministic test expiry; do not wait 30 minutes in CI
migration_journal.write_text(json.dumps(armed))
limit = time.monotonic() + 75
while time.monotonic() < limit and json.loads(migration_journal.read_text())['state'] == 'armed':
    time.sleep(1)
assert json.loads(migration_journal.read_text())['state'] == 'reverted', 'Independent namespace timer did not recover killed migration'
while time.monotonic() < limit and subprocess.run(['systemctl', 'is-active', '--quiet', 'serverhub-ai-namespace-recovery.service'], capture_output=True).returncode == 0:
    time.sleep(0.2)
assert Path('/opt/serverhub/current').resolve() == previous
assert (Path('/var/lib/serverhub-install/ownership.json').read_bytes() if namespaced else None) == old_claim
if not namespaced:
    assert not Path('/var/lib/serverhub-install/ownership.json').exists()
for name, content in before.items():
    assert Path('/etc/serverhub', name).read_bytes() == content
for unit in old_units:
    subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True)
print('NAMESPACE_WATCHDOG_EVIDENCE=' + json.dumps({'state': 'passed', 'process_killed': True,
    'independent_systemd_timer_recovered': True, 'deadline_shortened_for_disposable_test': True}), flush=True)

# Real services, DB migration and backup run, then acceptance deliberately fails.
with patch.object(Installer, '_healthchecks', side_effect=RuntimeError('Intentional namespace health failure')):
    try:
        migrate(source, repair_legacy_permissions=True)
    except RuntimeError as error:
        assert 'Intentional' in str(error)
    else:
        raise AssertionError('Expected migration rollback')
assert Path('/opt/serverhub/current').resolve() == previous
assert (Path('/var/lib/serverhub-install/ownership.json').read_bytes() if namespaced else None) == old_claim
if not namespaced:
    assert not Path('/var/lib/serverhub-install/ownership.json').exists()
assert json.loads(Path('/var/lib/serverhub-install/unit-migration.json').read_text())['state'] == 'reverted'
for name, content in before.items():
    assert Path('/etc/serverhub', name).read_bytes() == content
for unit in old_units:
    subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True)

assert migrate(source, repair_legacy_permissions=True)['state'] == 'migrated'
for name in ('api.env', 'worker.env', 'recovery.env'):
    actual = Path('/etc/serverhub', name).read_text()
    assert legacy_resources(actual).encode() == before[name]
for name, content in old_identities.items():
    assert subprocess.check_output(['getent', 'passwd', name]) == content
for unit in ['serverhub-ai-api.service', 'serverhub-ai-worker.service', 'serverhub-ai-broker.service']:
    subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True)
if not namespaced:
    for unit in old_units:
        assert not Path('/etc/systemd/system', unit).exists()
assert '/run/serverhub-ai-broker/control.sock' in Path('/etc/serverhub/broker.yaml').read_text()
if not namespaced:
    assert Path('/opt/serverhub/recovery/venv/bin/python').exists(), 'Legacy independent recovery retained'
assert Path('/opt/serverhub/recovery-ai/venv/bin/python').exists()
print('LEGACY_UNIT_MIGRATION_EVIDENCE=' + json.dumps({'state': 'passed',
    'legacy_commit': subprocess.check_output(['git', '-C', str(legacy), 'rev-parse', 'HEAD'], text=True).strip(),
    'intentional_failed_health_rollback': True, 'killed_migration_independent_timer_recovery': True, 'credentials_retained': True,
    'retry_succeeded': True, 'new_units_active': True, 'production_modified': False}), flush=True)
