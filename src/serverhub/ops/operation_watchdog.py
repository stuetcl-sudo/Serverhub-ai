"""Standalone root rollback worker, deliberately stdlib-only and installable outside candidate code.

Called by /usr/bin/python3 -I from a stable root-owned path. Journals contain only
root-enrolled structured inverses; prompts cannot select commands or paths.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time


def protected(path):
    path = Path(path)
    for part in (path, *path.parents):
        metadata = part.lstat()
        if part.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('Unprotected recovery path')
    return path


def run(argv):
    subprocess.run(argv, check=True, timeout=180, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive'})


def restore(record):
    if record['kind'] == 'docker_start':
        names = record.get('containers', [])
        if not all(re.fullmatch('[a-f0-9]{64}', value) for value in names):
            raise ValueError('Invalid Docker recovery identities')
        if names:
            run(['/usr/bin/docker','start',*names])
    elif record['kind'] == 'configuration':
        target, backup = protected(record['target']), protected(record['backup'])
        if str(target).startswith(('/etc/serverhub', '/opt/serverhub', '/etc/ssh', '/etc/sudoers', '/etc/pam', '/etc/systemd')):
            raise ValueError('Protected control-plane recovery target')
        temporary = target.with_name('.serverhub-rollback-' + record['id'])
        shutil.copyfile(backup, temporary)
        os.chmod(temporary, record['mode'])
        os.chown(temporary, record['uid'], record['gid'])
        os.replace(temporary, target)
        if record.get('service'):
            if not re.fullmatch('[A-Za-z0-9_.@-]+\\.service', record['service']) or record['service'].startswith(('serverhub','ssh','systemd','network','sudo','docker','postgres')):
                raise ValueError('Protected recovery service')
            run(['/usr/bin/systemctl','restart',record['service']])
    elif record['kind'] == 'package':
        files = [str(protected(path)) for path in record['previous_debs']]
        if files:
            run(['/usr/bin/apt-get','-y','--no-download','--no-remove','--allow-downgrades','install',*files])
        if record.get('new_packages'):
            if not all(re.fullmatch('[a-z0-9][a-z0-9+.-]+', value) for value in record['new_packages']):
                raise ValueError('Invalid package inverse')
            run(['/usr/bin/dpkg','--remove',*record['new_packages']])
    elif record['kind'] == 'compose':
        path = protected(record['previous_file'])
        if not re.fullmatch('[A-Za-z0-9_-]{1,64}',record['project']):
            raise ValueError('Invalid Compose recovery project')
        run(['/usr/bin/docker','compose','--project-name',record['project'],'--env-file','/dev/null',
             '-f',str(path),'up','-d','--wait','--wait-timeout','120'])
    else:
        raise ValueError('Unsupported recovery kind')


def tick(directory):
    if os.geteuid() != 0:
        raise ValueError('Root recovery required')
    if not Path(directory).exists():
        return []
    directory = protected(directory)
    results = []
    for path in directory.glob('*.json'):
        with path.with_suffix('.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                protected(path)
                record = json.loads(path.read_text())
                if record.get('state') != 'armed' or record.get('deadline', float('inf')) > time.time():
                    continue
                restore(record)
                record['state'], record['restored_at'] = 'reverted', time.time()
                temporary = path.with_suffix('.new')
                with temporary.open('w') as out:
                    os.chmod(temporary, 0o600)
                    json.dump(record, out)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(temporary, path)
                results.append({'id':path.stem,'state':'reverted'})
            except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
                results.append({'id':path.stem,'state':'recovery_failed','error':type(error).__name__})
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory',default='/var/lib/serverhub-broker/operations')
    print(json.dumps(tick(parser.parse_args().directory)))
