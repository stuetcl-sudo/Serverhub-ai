"""Real systemd coexistence drill on an explicitly disposable Ubuntu CI runner.

These are native harmless Control-name fixtures, not the owner's Control software.
No code in this module may run on a pre-existing Control installation.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

BASELINE = Path('/var/lib/serverhub-control-ci/baseline.json')
NAMES = ['serverhub-broker.service', 'serverhub-docker-ro.service', 'serverhub-worker.service']


def run(*args):
    return subprocess.check_output(args, text=True, cwd='/').strip()


def guard():
    if os.geteuid() or os.environ.get('SERVERHUB_DISPOSABLE_TEST') != 'fresh-ubuntu-ci' or not os.environ.get('GITHUB_ACTIONS'):
        raise RuntimeError('Disposable Ubuntu CI only')


def snapshot():
    result = {'files': {}, 'units': {}, 'identity': run('getent', 'passwd', 'serverhub-control-ci'),
              'group': run('getent', 'group', 'serverhub-control-ci')}
    for path in [*Path('/opt/serverhub-control').rglob('*'),
                 *[Path('/etc/systemd/system', name) for name in NAMES]]:
        if path.is_file():
            info = path.stat()
            result['files'][str(path)] = [hashlib.sha256(path.read_bytes()).hexdigest(),
                                         info.st_mode, info.st_uid, info.st_gid]
    for name in NAMES:
        result['units'][name] = run('systemctl', 'show', name, '--property=MainPID,ActiveState,SubState,ActiveEnterTimestampMonotonic,UnitFileState')
    return result


def verify():
    guard()
    assert snapshot() == json.loads(BASELINE.read_text()), 'Control fixture changed, stopped or restarted'
    import urllib.request
    for port in [18765, 18766]:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/sentinel', timeout=5) as response:
            assert response.read() == b'Control fixture untouched\n'
    print('CONTROL_COEXISTENCE_EVIDENCE=' + json.dumps({'state': 'passed', 'units': NAMES,
          'pids_and_start_times_unchanged': True, 'files_and_identities_unchanged': True,
          'gateway_http_ports': [18765, 18766], 'kind': 'real systemd / harmless Control-name fixtures'}), flush=True)


def start():
    guard()
    if Path('/opt/serverhub-control').exists() or BASELINE.exists():
        raise RuntimeError('Refusing existing Control installation')
    for name in NAMES:
        if run('systemctl', 'show', name, '--property=LoadState', '--value') != 'not-found':
            raise RuntimeError('Refusing existing Control service')
    subprocess.run(['useradd', '--system', '--user-group', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', 'serverhub-control-ci'], check=True)
    tree = Path('/opt/serverhub-control')
    tree.mkdir(mode=0o755)
    (tree / 'sentinel').write_text('Control fixture untouched\n')
    for name, port in zip(NAMES, [18765, 18766, None]):
        command = f'/usr/bin/python3 -m http.server {port} --bind 127.0.0.1 --directory /opt/serverhub-control' if port else '/usr/bin/sleep infinity'
        Path('/etc/systemd/system', name).write_text('[Unit]\nDescription=Disposable Control coexistence fixture\n[Service]\nUser=serverhub-control-ci\nExecStart=' + command + '\n[Install]\nWantedBy=multi-user.target\n')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', *NAMES], check=True)
    time.sleep(1)
    BASELINE.parent.mkdir(mode=0o700)
    BASELINE.write_text(json.dumps(snapshot()))
    verify()


def conflicts(source):
    from serverhub.ops.coexistence import ConflictError, require_safe
    from serverhub.ops.installer import Installer, InstallError
    units = Installer(source).units()
    def rejected(kind):
        try:
            Installer(source).apply()
        except (ConflictError, InstallError) as error:
            assert kind in str(error)
        else:
            raise AssertionError('Conflict not rejected: ' + kind)
        assert not Path('/var/lib/serverhub-install').exists()
        assert not Path('/opt/serverhub').exists()
        verify()
    path = Path('/etc/serverhub')
    path.mkdir()
    (path / 'foreign').write_text('must not be adopted')
    rejected('path')
    (path / 'foreign').unlink()
    path.rmdir()
    unit = Path('/etc/systemd/system/serverhub-ai-worker.service')
    unit.write_text('[Service]\nExecStart=/usr/bin/sleep infinity\n')
    rejected('service')
    unit.unlink()
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['useradd', '--system', '--no-user-group', '--gid', 'nogroup', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', 'serverhub-api'], check=True)
    rejected('user')
    subprocess.run(['userdel', 'serverhub-api'], check=True)
    subprocess.run(['groupadd', '--system', 'serverhub-worker'], check=True)
    rejected('group')
    subprocess.run(['groupdel', 'serverhub-worker'], check=True)
    import socket
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 9080))
        listener.listen()
        rejected('port')
    assert require_safe(units=units)['safe']
    print('CONFLICT_PREFLIGHT_EVIDENCE=' + json.dumps({'state': 'passed', 'rejected': ['path', 'service', 'user', 'group', 'port'], 'installer_mutations': False}), flush=True)


if __name__ == '__main__':
    verify()
