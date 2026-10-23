"""Standalone root-only namespace rollback, installed before service conversion."""
import base64
import json
import os
import time
import subprocess
from pathlib import Path
JOURNAL = Path('/var/lib/serverhub-install/unit-migration.json')
CLAIM = '/var/lib/serverhub-install/ownership.json'
def protected(path):
    for item in (path, *path.parents):
        if item.is_symlink() or (item.exists() and (item.stat().st_uid != 0 or item.stat().st_mode & 0o022)):
            raise RuntimeError('Unsafe recovery record or path')

def _run(argv):
    return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=180, cwd='/')


def _save(value):
    temp = JOURNAL.with_suffix('.tmp')
    fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, JOURNAL)


def recover(*, force=False):
    protected(JOURNAL)
    data = json.loads(JOURNAL.read_text())
    if data['state'] != 'armed' or (not force and time.time() < data['deadline']):
        return {'state': data['state']}
    # Only units proven by plan() and recorded before any stop are ever touched.
    _run(['systemctl', 'disable', '--now', *[x['new'] for x in data['units']]])
    for path, saved in data['files'].items():
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(base64.b64decode(saved['content']))
        target.chmod(saved['mode'])
        os.chown(target, saved['uid'], saved['gid'])
    for unit in data['units']:
        Path('/etc/systemd/system', unit['new']).unlink(missing_ok=True)
        directory = Path('/etc/systemd/system', unit['new'] + '.d')
        for saved_path in data['files']:
            saved = Path(saved_path)
            if saved.parent.name == unit['old'] + '.d':
                (directory / saved.name).unlink(missing_ok=True)
        if directory.exists() and not list(directory.iterdir()):
            directory.rmdir()
    current = Path('/opt/serverhub/current')
    replacement = current.with_name('.namespace-recover')
    replacement.unlink(missing_ok=True)
    replacement.symlink_to(data['previous'])
    os.replace(replacement, current)
    Path(CLAIM).unlink(missing_ok=True)
    _run(['systemctl', 'daemon-reload'])
    for unit in data['units']:
        if unit['enabled']:
            _run(['systemctl', 'enable', unit['old']])
        if unit['active']:
            _run(['systemctl', 'start', unit['old']])
    data['state'] = 'reverted'
    _save(data)
    _run(['systemctl', 'disable', '--now', 'serverhub-ai-namespace-recovery.timer'])
    for suffix in ('service', 'timer'):
        Path('/etc/systemd/system/serverhub-ai-namespace-recovery.' + suffix).unlink(missing_ok=True)
    _run(['systemctl', 'daemon-reload'])
    return {'state': 'reverted'}


if __name__ == '__main__':
    print(json.dumps(recover()))
