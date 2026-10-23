"""Pinned stateless Compose updates with checkpointed health-gated rollback."""
import json
import shutil
import time
import uuid

from .docker_backup import protected, atomic, DockerBackupError
from .discovery import command
from serverhub.ops.operation_watchdog import restore


def update(arguments, config):
    from .broker import _compose_file, _safe_container, _name
    if set(arguments) != {'target'}:
        raise DockerBackupError('Expected exact enrolled update target')
    target = _name(arguments['target'])
    plan = config.get('compose_updates',{}).get(target)
    if not isinstance(plan,dict) or plan.get('stateless') is not True:
        raise DockerBackupError('Root-enrolled stateless update required; stateful data migration needs a tested application adapter')
    project = _name(plan['project'])
    _, previous = _compose_file(plan['previous'])
    directory, candidate = _compose_file(plan['candidate'])
    old_manifest = __import__('yaml').safe_load(previous.read_text())
    new_manifest = __import__('yaml').safe_load(candidate.read_text())
    if set(old_manifest['services']) != set(new_manifest['services']):
        raise DockerBackupError('Automatic update cannot add/remove services')
    for manifest in (old_manifest,new_manifest):
        if any(service.get('volumes') for service in manifest['services'].values()):
            raise DockerBackupError('In-place data-bearing update is outside stateless transaction scope')
    old_prefix=['compose','--project-name',project,'--env-file','/dev/null','-f',str(previous)]
    before=command('docker',*old_prefix,'ps','--all','--quiet').split()
    if not before:
        raise DockerBackupError('Existing project required for update')
    for name in before:
        item=_safe_container(name)
        label=item.get('Config',{}).get('Labels',{}).get('com.docker.compose.service')
        if label not in old_manifest['services']:
            raise DockerBackupError('Unexpected service in existing project')
        image=json.loads(command('docker','image','inspect',old_manifest['services'][label]['image']))[0]['Id']
        if item['Image']!=image:
            raise DockerBackupError('Current image differs from enrolled baseline')
    state=protected(config.get('operations_state','/var/lib/serverhub-broker/operations'),create=True)
    identity=uuid.uuid4().hex
    transaction=state/identity
    transaction.mkdir(mode=0o700)
    snapshot=transaction/'compose.previous.yaml'
    shutil.copy2(previous,snapshot)
    record={'id':identity,'kind':'compose','project':project,'previous_file':str(snapshot),'state':'armed','deadline':time.time()+240}
    journal=state/(identity+'.json')
    atomic(journal,record)
    try:
        command('docker','compose','--project-name',project,'--project-directory',str(directory),'--env-file','/dev/null',
                '-f',str(candidate),'up','-d','--pull','never','--wait','--wait-timeout','90',timeout=120)
        record['state']='committed'
        atomic(journal,record)
        return {'target':target,'project':project,'transaction_id':identity,'verified':True,
                'verification':'Pinned images and Compose service healthchecks passed','rollback_available':True}
    except BaseException:
        record['deadline']=time.time()+240
        atomic(journal,record)
        restore(record)
        record['state']='reverted'
        atomic(journal,record)
        raise
