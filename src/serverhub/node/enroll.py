"""Explicit local-root enrollment. Never exposed as an AI/MCP tool."""
import argparse
import json
import os
from pathlib import Path
import secrets
import re
import subprocess

import yaml

from .docker_backup import protected
from .broker import load_config


def enroll(plans, *, config='/etc/serverhub/broker.yaml', apply=False):
    if os.geteuid()!=0:
        raise ValueError('Explicit local root enrollment required')
    allowed={'docker_backup_plans','package_plans','configuration_plans','compose_updates','staging_projects'}
    if not isinstance(plans,dict) or set(plans)-allowed:
        raise ValueError('Only documented named plan families may be enrolled')
    if not apply:
        return {'state':'plan','families':{key:list(value) for key,value in plans.items()},
                'privileges':'Root package/configuration adapters only; protected runtime/audit/SSH paths remain read-only'}
    path=protected(config)
    current=load_config(str(path))
    for key,value in plans.items():
        if not isinstance(value,dict):
            raise ValueError('Plan family must be a mapping')
        current.setdefault(key,{}).update(value)
    current['enable_administration']=True
    for plan in current.get('docker_backup_plans',{}).values():
        key_path=Path(plan['key_file'])
        protected(key_path.parent)
        if not key_path.exists():
            fd=os.open(key_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as out:
                out.write(secrets.token_bytes(32))
                out.flush()
                os.fsync(out.fileno())
    temporary=path.with_suffix('.enrolled')
    with temporary.open('w') as out:
        os.chmod(temporary,0o600)
        yaml.safe_dump(current,out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary,path)
    directory=Path('/etc/systemd/system/serverhub-broker.service.d')
    directory.mkdir(mode=0o755,exist_ok=True)
    # Scope writable namespaces needed by approved distro package scripts. Root
    # approved artifacts are a powerful capability, never treated as unprivileged.
    writable=['/usr','/etc','/var/lib/dpkg','/var/lib/apt','/var/cache/apt']
    backups=current.get('docker_backup_plans',{})
    writable.extend(str(plan.get('destination','/mnt/storage/ServerHub-Backups')) for plan in backups.values())
    if any(plan.get('allow_isolated_restore') is True for plan in backups.values()):
        docker_root=subprocess.run(['docker','info','--format','{{.DockerRootDir}}'],
            check=True,capture_output=True,text=True,timeout=15).stdout.strip()
        writable.append(str(Path(docker_root)/'volumes'))
    if any(not re.fullmatch(r'/[A-Za-z0-9_./-]+',path) or '..' in Path(path).parts for path in writable):
        raise ValueError('Enrolled writable directories must be absolute without whitespace, traversal or systemd specifiers')
    (directory/'20-administration.conf').write_text('[Service]\nReadWritePaths='+' '.join(sorted(set(writable)))+'\n'
        'ReadOnlyPaths=/etc/serverhub /opt/serverhub /etc/ssh /etc/systemd/system /etc/sudoers /etc/sudoers.d /etc/pam.d\n')
    protected('/var/lib/serverhub-broker/operations',create=True)
    protected('/var/lib/serverhub-staging',create=True)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','restart','serverhub-broker'],check=True)
    return {'state':'enrolled','families':{key:list(value) for key,value in plans.items()}}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plans',required=True)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    print(json.dumps(enroll(yaml.safe_load(protected(args.plans).read_text()),apply=args.apply)))
