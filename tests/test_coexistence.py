"""No test here touches the real service manager or host identities."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from serverhub.ops.coexistence import ConflictError, inspect, require_safe, write_claim
from serverhub.ops.installer import Installer
from serverhub.ops.migrate_units import old_name, plan

SOURCE = Path(__file__).resolve().parents[1]


def test_control_units_and_tree_are_not_installer_resources(tmp_path):
    control = tmp_path / 'opt/serverhub-control'
    control.mkdir(parents=True)
    sentinel = control / 'sentinel'
    sentinel.write_bytes(b'unchanged-control')
    units = tmp_path / 'etc/systemd/system'
    units.mkdir(parents=True)
    for name in ['serverhub-broker.service', 'serverhub-worker.service', 'serverhub-docker-ro.service']:
        (units / name).write_text('ExecStart=/opt/serverhub-control/worker\n')
    installer = Installer(SOURCE, root=tmp_path)
    assert require_safe(root=tmp_path, units=installer.units(), live=False)['safe']
    installer.stage()
    assert sentinel.read_bytes() == b'unchanged-control'
    for name in ['serverhub-broker.service', 'serverhub-worker.service', 'serverhub-docker-ro.service']:
        assert (units / name).read_text() == 'ExecStart=/opt/serverhub-control/worker\n'
    assert all(name.startswith('serverhub-ai-') for name in installer.units())
    assert 'RuntimeDirectory=serverhub-ai-broker' in (units / 'serverhub-ai-broker.service').read_text()


@pytest.mark.parametrize('path', ['/etc/serverhub', '/opt/serverhub', '/var/lib/serverhub-worker',
                                  '/var/lib/serverhub-broker', '/run/serverhub-ai-broker'])
def test_foreign_paths_rejected_without_mutation(tmp_path, path):
    target = tmp_path / path.lstrip('/')
    target.mkdir(parents=True)
    before = set(tmp_path.rglob('*'))
    with pytest.raises(ConflictError, match=path):
        require_safe(root=tmp_path, live=False)
    assert set(tmp_path.rglob('*')) == before


@pytest.mark.parametrize('suffix', ['', '.d'])
def test_foreign_unit_and_dropin_rejected(tmp_path, suffix):
    target = tmp_path / ('etc/systemd/system/serverhub-ai-worker.service' + suffix)
    target.parent.mkdir(parents=True)
    target.mkdir() if suffix else target.write_text('foreign')
    assert not inspect(root=tmp_path, units=Installer(SOURCE).units(), live=False)['safe']


def test_symlink_path_rejected(tmp_path):
    target = tmp_path / 'opt/serverhub'
    target.parent.mkdir()
    target.symlink_to('/opt/serverhub-control')
    assert not inspect(root=tmp_path, live=False)['safe']


def legacy(tmp_path):
    release = tmp_path / 'opt/serverhub/releases/old'
    release.mkdir(parents=True)
    (release / 'installed.json').write_text(json.dumps({'manifest': {'trust_boundary_digest': 'old-trust'}}))
    (release.parent.parent / 'current').symlink_to(release)
    journal = tmp_path / 'var/lib/serverhub-install/state.json'
    journal.parent.mkdir(parents=True)
    journal.write_text(json.dumps({'format': 1, 'state': 'installed', 'trust_digest': 'old-trust'}))
    units = tmp_path / 'etc/systemd/system'
    units.mkdir(parents=True)
    installer = Installer(SOURCE)
    for name in installer.units():
        content = (SOURCE / 'packaging/systemd' / name).read_text()
        for new in installer.units():
            content = content.replace(new, old_name(new))
        content = content.replace('/run/serverhub-ai-broker', '/run/serverhub-broker').replace(
            'RuntimeDirectory=serverhub-ai-broker', 'RuntimeDirectory=serverhub-broker').replace(
            '/opt/serverhub/recovery-ai', '/opt/serverhub/recovery')
        (units / old_name(name)).write_text(content)
    return units


def test_legacy_migration_requires_matching_install_and_exact_units(tmp_path):
    legacy(tmp_path)
    result = plan(SOURCE, root=tmp_path)
    assert len(result['units']) == len(Installer(SOURCE).units())
    assert result['state'] == 'reviewed'


@pytest.mark.parametrize('name', ['serverhub-worker.service', 'serverhub-broker.service'])
def test_mixed_control_legacy_install_is_never_migrated(tmp_path, name):
    units = legacy(tmp_path)
    (units / name).write_text('[Service]\nExecStart=/opt/serverhub-control/worker\n')
    before = {p: p.read_bytes() for p in units.iterdir()}
    with pytest.raises(ConflictError, match='foreign'):
        plan(SOURCE, root=tmp_path)
    assert {p: p.read_bytes() for p in units.iterdir()} == before


def test_legacy_migration_rejects_new_namespace_collision(tmp_path):
    units = legacy(tmp_path)
    (units / 'serverhub-ai-worker.service').write_text('foreign')
    with pytest.raises(ConflictError, match='occupied'):
        plan(SOURCE, root=tmp_path)


def test_legacy_migration_rejects_custom_dropin(tmp_path):
    units = legacy(tmp_path)
    drop = units / 'serverhub-worker.service.d'
    drop.mkdir()
    (drop / 'root.conf').write_text('[Service]\nUser=root\n')
    with pytest.raises(ConflictError, match='drop-in'):
        plan(SOURCE, root=tmp_path)


def test_claim_cannot_overwrite_or_adopt_unknown_claim(tmp_path, monkeypatch):
    import serverhub.ops.coexistence as module
    # Temp ancestry is intentionally unprivileged; simulate only this trust boundary.
    monkeypatch.setattr(module, 'protected', lambda path, **kwargs: None)
    write_claim(tmp_path)
    assert inspect(root=tmp_path, live=False)['safe']
    with pytest.raises(FileExistsError):
        write_claim(tmp_path)
    path = tmp_path / module.CLAIM.lstrip('/')
    path.write_text('{}')
    with pytest.raises(ConflictError, match='Unknown'):
        inspect(root=tmp_path, live=False)


def test_claimed_install_rejects_loaded_foreign_unit(tmp_path, monkeypatch):
    import serverhub.ops.coexistence as module
    monkeypatch.setattr(module, 'claim', lambda root: {'owned': True})
    monkeypatch.setattr(module, 'protected', lambda path, **kwargs: None)
    monkeypatch.setattr(module, 'api_owns_port', lambda runner, port: True)
    def missing(name):
        raise KeyError(name)
    monkeypatch.setattr(module.pwd, 'getpwnam', missing)
    monkeypatch.setattr(module.grp, 'getgrnam', missing)
    def runner(args, **kwargs):
        return SimpleNamespace(returncode=0, stdout='LoadState=loaded\nFragmentPath=/usr/lib/systemd/system/foreign.service\nDropInPaths=\n')
    result = inspect(root=tmp_path, units=['serverhub-ai-worker.service'], runner=runner)
    assert any(c['kind'] == 'service' and 'Foreign' in c['reason'] for c in result['conflicts'])


def test_root_enrolled_administration_dropin_can_survive_upgrade(tmp_path):
    from serverhub.ops.coexistence import valid_dropin
    content = ('[Service]\nReadWritePaths=/etc /usr /var/cache/apt /var/lib/apt /var/lib/dpkg -/var/log/apt -/var/log/dpkg.log\n'
               'ReadOnlyPaths=/etc/serverhub /opt/serverhub /etc/ssh /etc/systemd/system /etc/sudoers /etc/sudoers.d /etc/pam.d\n')
    assert valid_dropin('serverhub-ai-broker.service', '20-administration.conf', content)
    assert not valid_dropin('serverhub-ai-worker.service', '20-administration.conf', content)
    assert not valid_dropin('serverhub-ai-broker.service', '20-administration.conf', content + 'User=attacker\n')
    units = legacy(tmp_path)
    drop = units / 'serverhub-broker.service.d'
    drop.mkdir()
    (drop / '20-administration.conf').write_text(content)
    assert plan(SOURCE, root=tmp_path)['state'] == 'reviewed'


def test_independent_namespace_watchdog_restores_only_recorded_ai_resources(tmp_path, monkeypatch):
    import base64
    import serverhub.ops.unit_recovery as watchdog
    actual_path = Path
    def rooted(*parts):
        path = actual_path(*parts)
        if path.is_absolute() and not path.is_relative_to(tmp_path):
            return tmp_path / str(path).lstrip('/')
        return path
    journal = tmp_path / 'var/lib/serverhub-install/unit-migration.json'
    journal.parent.mkdir(parents=True)
    current = rooted('/opt/serverhub/current')
    current.parent.mkdir(parents=True)
    current.symlink_to('/opt/serverhub/releases/bad')
    control = rooted('/opt/serverhub-control/sentinel')
    control.parent.mkdir()
    control.write_bytes(b'untouched')
    unit = rooted('/etc/systemd/system/serverhub-ai-worker.service')
    unit.parent.mkdir(parents=True)
    unit.write_text('candidate unit')
    data = {'state': 'armed', 'deadline': 100,
            'previous': '/opt/serverhub/releases/old',
            'units': [{'new': 'serverhub-ai-worker.service', 'old': 'serverhub-worker.service',
                       'active': True, 'enabled': False}],
            'files': {'/etc/systemd/system/serverhub-worker.service': {
                'content': base64.b64encode(b'proven AI predecessor').decode(),
                'mode': 0o644, 'uid': os.getuid(), 'gid': os.getgid()}}}
    journal.write_text(json.dumps(data))
    calls = []
    monkeypatch.setattr(watchdog, 'Path', rooted)
    monkeypatch.setattr(watchdog, 'JOURNAL', journal)
    monkeypatch.setattr(watchdog, 'protected', lambda path: None)
    monkeypatch.setattr(watchdog, '_run', lambda args: calls.append(args))
    monkeypatch.setattr(watchdog.time, 'time', lambda: 99)
    assert watchdog.recover()['state'] == 'armed'
    assert not calls
    monkeypatch.setattr(watchdog.time, 'time', lambda: 101)
    assert watchdog.recover()['state'] == 'reverted'
    assert not unit.exists()
    assert rooted('/etc/systemd/system/serverhub-worker.service').read_bytes() == b'proven AI predecessor'
    assert control.read_bytes() == b'untouched'
    assert os.readlink(current) == '/opt/serverhub/releases/old'
    assert ['systemctl', 'start', 'serverhub-worker.service'] in calls
    assert not any('serverhub-broker.service' in args or 'serverhub-docker-ro.service' in args for args in calls)
    assert not any(args[:2] == ['systemctl', 'enable'] for args in calls)


def test_watchdog_and_interactive_recovery_have_identical_implementation():
    import inspect
    from serverhub.ops.migrate_units import recover
    from serverhub.ops.unit_recovery import recover as standalone
    assert inspect.getsource(recover) == inspect.getsource(standalone)
