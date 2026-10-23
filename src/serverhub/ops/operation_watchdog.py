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
import uuid


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
                   env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive','HOME':'/nonexistent'})


def launch_stage(spec):
    if not re.fullmatch('[a-zA-Z0-9_-]{1,100}',spec['unit']) or not spec['unit'].startswith('serverhub-stage-'):
        raise ValueError('Invalid staging unit')
    directory=protected(spec['directory'])
    data=Path(spec['data_directory'])
    if not directory.is_relative_to('/var/lib/serverhub-staging/releases') or not data.is_relative_to('/var/lib/serverhub-stage-data'):
        raise ValueError('Staging path outside its namespace')
    argv=spec['argv']
    if not isinstance(argv,list) or not argv or not argv[0].startswith('/usr/bin/') or any(not isinstance(arg,str) or '\0' in arg for arg in argv):
        raise ValueError('Invalid enrolled staging executable')
    project_group=spec.get('project_group','')
    if not re.fullmatch(r'serverhub-project-[a-f0-9]{12}',project_group):
        raise ValueError('Staging project group missing or invalid')
    dynamic_user='serverhub-stage-'+data.name[:12]
    properties=['DynamicUser=yes', 'User='+dynamic_user, 'SupplementaryGroups='+project_group,
        'StateDirectory=serverhub-stage-data/'+data.name, 'StateDirectoryMode=0700', 'ProtectProc=invisible', 'NoNewPrivileges=yes','PrivateNetwork=yes','PrivateTmp=yes','ProtectSystem=strict','ProtectHome=yes',
        'CapabilityBoundingSet=','RestrictSUIDSGID=yes','ProtectKernelTunables=yes','ProtectKernelModules=yes',
        'ProtectControlGroups=yes','TasksMax=128',f'MemoryMax={spec["memory_mb"]}M',f'ReadWritePaths={data}',
        'InaccessiblePaths=-/etc/serverhub -/opt/serverhub -/var/backups/serverhub -/run/serverhub-ai-broker -/var/run/docker.sock -/var/lib/serverhub-worker']
    command=['/usr/bin/systemd-run','--quiet','--unit',spec['unit'],
             '--working-directory',str(directory)]
    for prop in properties:
        command+=['--property',prop]
    for key,value in spec['environment'].items():
        if not re.fullmatch('[A-Z][A-Z0-9_]{0,63}',key) or not isinstance(value,str) or '\0' in value:
            raise ValueError('Invalid staging environment')
        command+=['--setenv',key+'='+value]
    loaded=subprocess.run(['/usr/bin/systemctl','show',spec['unit'],'--property=LoadState','--value'],
        text=True,capture_output=True,check=False).stdout.strip()
    if loaded == 'loaded':
        run(['/usr/bin/systemctl','start',spec['unit']])
    else:
        run([*command,'--',*argv])


def stage_health(spec, *, timeout=90):
    health=spec.get('health')
    if not isinstance(health,dict):
        raise ValueError('Staging health contract missing')
    port,path,expected=health['port'],health['path'],health['contains']
    if not isinstance(port,int) or not 1024<=port<=65535 or not isinstance(path,str) or not path.startswith('/') or len(path)>200 or not isinstance(expected,str) or len(expected)>1000:
        raise ValueError('Invalid staging health contract')
    script='import urllib.request; print(urllib.request.urlopen('+repr(f'http://127.0.0.1:{port}{path}')+', timeout=3).read(65536).decode())'
    deadline=time.monotonic()+timeout
    while True:
        pid=subprocess.run(['/usr/bin/systemctl','show',spec['unit'],'--property=MainPID','--value'],text=True,capture_output=True,check=False).stdout.strip()
        if pid.isdigit() and int(pid)>0:
            response=subprocess.run(['/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect',
                '--unit','serverhub-health-'+uuid.uuid4().hex[:12],
                '--property','User=serverhub-staging','--property','Group=serverhub-staging',
                '--property','NetworkNamespacePath=/proc/'+pid+'/ns/net',
                '--property','NoNewPrivileges=yes','--property','CapabilityBoundingSet=',
                '--property','ProtectSystem=strict','--property','ProtectHome=yes','--property','PrivateTmp=yes',
                '--property','MemoryMax=128M','--property','TasksMax=16','--property','RuntimeMaxSec=5',
                '--property','InaccessiblePaths=-/etc/serverhub -/var/lib/serverhub-worker -/var/lib/serverhub-broker -/var/run/docker.sock',
                '--','/usr/bin/python3','-I','-c',script],
                text=True,capture_output=True,check=False,timeout=10,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'})
            if response.returncode==0 and expected in response.stdout:
                return True
        if time.monotonic()>=deadline:
            raise ValueError('Staging acceptance healthcheck failed')
        time.sleep(1)


def restore(record):
    if record['kind'] == 'staging':
        unit=record['new_launch']['unit']
        if not re.fullmatch('serverhub-stage-[A-Za-z0-9_-]{1,90}',unit):
            raise ValueError('Invalid staging rollback unit')
        run(['/usr/bin/systemctl','stop',unit])
        if record.get('previous_launch'):
            launch_stage(record['previous_launch'])
            stage_health(record['previous_launch'])
    elif record['kind'] == 'docker_start':
        names = record.get('containers', [])
        if not all(re.fullmatch('[a-f0-9]{64}', value) for value in names):
            raise ValueError('Invalid Docker recovery identities')
        if names:
            run(['/usr/bin/docker','start',*names])
    elif record['kind'] == 'configuration':
        target, backup = protected(record['target']), protected(record['backup'])
        if str(target).startswith(('/etc/serverhub', '/opt/serverhub', '/etc/ssh', '/etc/sudoers', '/etc/pam', '/etc/systemd', '/etc/apparmor', '/etc/security', '/etc/profile', '/etc/environment', '/etc/ld.so', '/etc/cron', '/etc/init.d', '/etc/rc', '/etc/polkit', '/etc/dbus', '/etc/udev', '/etc/modules', '/etc/modprobe', '/etc/sysctl', '/var/lib/serverhub', '/var/log/serverhub', '/var/backups/serverhub', '/var/spool/cron', '/root', '/usr', '/bin', '/sbin', '/lib', '/boot', '/proc', '/sys', '/dev', '/run')):
            raise ValueError('Protected control-plane recovery target')
        temporary = target.with_name('.serverhub-rollback-' + record['id'])
        shutil.copyfile(backup, temporary)
        os.chmod(temporary, record['mode'])
        os.chown(temporary, record['uid'], record['gid'])
        os.replace(temporary, target)
        if record.get('service'):
            if not re.fullmatch(r'[A-Za-z0-9_.@-]+\.service', record['service']) or record['service'].startswith(('serverhub','ssh','systemd','network','sudo','docker','postgres')):
                raise ValueError('Protected recovery service')
            run(['/usr/bin/systemctl','restart',record['service']])
    elif record['kind'] == 'package':
        files = [str(protected(path)) for path in record['previous_debs']]
        if files:
            run(['/usr/bin/dpkg','--install',*files])
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
                results.append({'id':path.stem,'state':'recovery_failed','error':type(error).__name__, 'reason':str(error)[:500]})
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory',default='/var/lib/serverhub-broker/operations')
    print(json.dumps(tick(parser.parse_args().directory)))
