"""Root-enrolled host transactions; AI supplies a plan name, never argv or paths."""
from __future__ import annotations
import hashlib
import os
import re
import shutil
import time
import uuid

from .docker_backup import protected, atomic, DockerBackupError
from .discovery import command, CollectionError
from serverhub.ops.operation_watchdog import restore

PROTECTED_PACKAGES = re.compile(r'^(serverhub|openssh|sudo|systemd|libc6|linux-|postgresql|mysql|mariadb|redis|ufw|nftables|iptables|network-manager|netplan|polkit|dbus|pam|libpam)', re.I)
PROTECTED_PATHS = ('/etc/serverhub', '/etc/ssh', '/etc/sudoers', '/etc/pam', '/etc/shadow', '/etc/passwd', '/etc/group', '/etc/gshadow', '/etc/systemd', '/etc/apt', '/etc/netplan', '/etc/network', '/etc/nftables', '/etc/ufw', '/opt/serverhub')


def approved_file(entry):
    path = protected(entry['path'])
    if not path.is_file() or path.stat().st_size > 1024**3:
        raise DockerBackupError('Invalid enrolled artifact')
    from .docker_backup import digest
    if not re.fullmatch('[a-f0-9]{64}', entry.get('sha256', '')) or digest(path) != entry['sha256']:
        raise DockerBackupError('Enrolled artifact SHA-256 differs')
    return path


def package_description(path):
    data = command('dpkg-deb','--field',str(path),'Package','Version','Architecture')
    values = dict(line.split(': ',1) for line in data.splitlines() if ': ' in line)
    name = values.get('Package','')
    if not re.fullmatch('[a-z0-9][a-z0-9+.-]+',name) or PROTECTED_PACKAGES.match(name):
        raise DockerBackupError('Critical package outside administration boundary')
    return {'name':name,'version':values['Version'],'architecture':values['Architecture']}


def installed_version(name):
    try:
        text = command('dpkg-query','-W','-f=${Status}|${Version}',name)
        status, version = text.split('|',1)
        return version if status == 'install ok installed' else None
    except (CollectionError, ValueError):
        return None


def execute_administration(operation, arguments, config):
    if config.get('enable_administration') is not True:
        raise DockerBackupError('Root enrollment of administration capability required')
    if set(arguments) != {'target'} or not re.fullmatch('[A-Za-z0-9_-]{1,64}', str(arguments['target'])):
        raise DockerBackupError('Expected exact enrolled plan name')
    target = arguments['target']
    family = 'package_plans' if operation.startswith('package.') else 'configuration_plans'
    plan = config.get(family,{}).get(target)
    if not isinstance(plan,dict):
        raise DockerBackupError('Administration plan is not enrolled')
    state = protected(config.get('operations_state','/var/lib/serverhub-broker/operations'),create=True)
    transaction = uuid.uuid4().hex
    directory = state / transaction
    directory.mkdir(mode=0o700)
    record = {'id':transaction,'target_name':target,'state':'armed','deadline':time.time()+300}
    journal = state / (transaction + '.json')
    if family == 'package_plans':
        candidates = [approved_file(entry) for entry in plan.get('debs',[])]
        previous = [approved_file(entry) for entry in plan.get('previous_debs',[])]
        if not candidates or len(candidates)>100:
            raise DockerBackupError('Plan requires 1..100 pinned package artifacts')
        descriptions = [package_description(path) for path in candidates]
        previous_versions = {package_description(path)['name']: package_description(path)['version'] for path in previous}
        before = {item['name']:installed_version(item['name']) for item in descriptions}
        for name, version in before.items():
            if version is not None and previous_versions.get(name) != version:
                raise DockerBackupError('Every installed package requires its exact cached rollback .deb')
        simulation = command('apt-get','-o','APT::Sandbox::User=root','-s','--no-download','--no-remove','--allow-downgrades','install',*[str(path) for path in candidates],timeout=45)
        changed = set(re.findall(r'^Inst ([a-z0-9+.-]+)(?::\S+)? ',simulation,re.M))
        if changed - set(before) or re.search(r'^Remv ',simulation,re.M):
            raise DockerBackupError('Dependency changes outside the enrolled artifact set are forbidden')
        if operation == 'package.plan':
            return {'target':target,'packages':descriptions,'before':before,'verified':True,'changes_executed':[]}
        if operation != 'package.apply':
            raise DockerBackupError('Unsupported package operation')
        if plan.get('stateless') is not True:
            raise DockerBackupError('Package plans require explicit stateless enrollment; data migrations need a separate verified application procedure')
        copies=[]
        for index,path in enumerate(previous):
            backup=directory / f'previous-{index}.deb'
            shutil.copy2(path,backup)
            copies.append(str(backup))
        record.update(kind='package', previous_debs=copies,new_packages=[name for name,version in before.items() if version is None])
        atomic(journal,record)
        try:
            command('apt-get','-o','APT::Sandbox::User=root','-y','--no-download','--no-remove','--allow-downgrades','install',*[str(path) for path in candidates],timeout=180)
            if any(installed_version(item['name']) != item['version'] for item in descriptions):
                raise DockerBackupError('Installed package version verification failed')
            if plan.get('verify_file'):
                health=plan['verify_file']
                path=protected(health['path'])
                if hashlib.sha256(path.read_bytes()).hexdigest()!=health['sha256']:
                    raise DockerBackupError('Package acceptance check failed')
            record['state']='committed'
            atomic(journal,record)
            return {'target':target,'transaction_id':transaction,'packages':descriptions,'verified':True,
                    'verification':'Exact installed versions and root-enrolled acceptance checks','rollback_available':True}
        except BaseException:
            record['deadline'] = time.time() + 300
            atomic(journal,record)
            restore(record)
            record['state']='reverted'
            atomic(journal,record)
            raise
    path = protected(plan['path'])
    if any(str(path).startswith(prefix) for prefix in PROTECTED_PATHS) or not path.is_file():
        raise DockerBackupError('Protected configuration target')
    candidate = approved_file(plan['candidate'])
    if candidate.stat().st_size > 1024**2:
        raise DockerBackupError('Configuration candidate exceeds 1 MiB')
    if operation == 'configuration.plan':
        return {'target':target,'before_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                'after_sha256':plan['candidate']['sha256'],'verified':True,'changes_executed':[]}
    if operation != 'configuration.apply':
        raise DockerBackupError('Unsupported configuration operation')
    from .broker import PROTECTED_UNITS, _systemd_status
    service=plan.get('service')
    if service and (not re.fullmatch('[A-Za-z0-9_.@-]+\\.service',service) or PROTECTED_UNITS.match(service)):
        raise DockerBackupError('Protected configuration service')
    backup=directory/'configuration.before'
    shutil.copy2(path,backup)
    metadata=path.stat()
    record.update(kind='configuration',target=str(path),backup=str(backup),mode=metadata.st_mode&0o777,uid=metadata.st_uid,gid=metadata.st_gid,service=service)
    atomic(journal,record)
    try:
        temporary=path.with_name('.serverhub-candidate-'+transaction)
        shutil.copyfile(candidate,temporary)
        os.chmod(temporary,record['mode'])
        os.chown(temporary,record['uid'],record['gid'])
        os.replace(temporary,path)
        if service:
            command('systemctl','restart',service,timeout=45)
            if _systemd_status(service)['active']!='active':
                raise DockerBackupError('Configured service did not recover')
        if hashlib.sha256(path.read_bytes()).hexdigest()!=plan['candidate']['sha256']:
            raise DockerBackupError('Configuration content verification failed')
        record['state']='committed'
        atomic(journal,record)
        return {'target':target,'transaction_id':transaction,'verified':True,'verification':'Exact content checksum and configured service state','rollback_available':True}
    except BaseException:
        restore(record)
        record['state']='reverted'
        atomic(journal,record)
        raise
