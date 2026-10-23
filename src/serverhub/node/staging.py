"""Native isolated staging under a credential-free Linux identity and private netns."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import tarfile
import time
import uuid

from .docker_backup import protected, atomic, DockerBackupError
from .discovery import command
from serverhub.ops.operation_watchdog import launch_stage, restore, stage_health


def deploy(arguments, config):
    if set(arguments)!={'target','artifact_id'}:
        raise DockerBackupError('Expected project and candidate identity only')
    target=arguments['target']
    artifact_id=arguments['artifact_id']
    if not re.fullmatch('[A-Za-z0-9_-]{1,64}',target) or not re.fullmatch('[A-Za-z0-9_-]{1,64}',artifact_id):
        raise DockerBackupError('Invalid staging identity')
    plan=config.get('staging_projects',{}).get(target)
    if not isinstance(plan,dict):
        raise DockerBackupError('Staging project not enrolled by root')
    source=Path(plan.get('candidate_root','/var/lib/serverhub-worker/development/candidates'))
    manifest=source/(artifact_id+'.json')
    artifact=source/(artifact_id+'.tar')
    # Candidate content is untrusted, run only under the staging identity. The
    # artifact identity and independent-check receipt must match the scoped project.
    if source.is_symlink() or manifest.is_symlink() or artifact.is_symlink() or not artifact.is_file():
        raise DockerBackupError('Candidate missing or symlinked')
    data=json.loads(manifest.read_text())
    if data.get('project')!=target or not data.get('tests_passed') or not data.get('independent_checks_passed'):
        raise DockerBackupError('Candidate requires matching project, tests and independent checks')
    with artifact.open('rb') as stream:
        digest=hashlib.file_digest(stream,'sha256').hexdigest()
    if digest!=data.get('candidate',{}).get('sha256') or artifact.stat().st_size>2*1024**3:
        raise DockerBackupError('Candidate digest/size mismatch')
    health={'port':int(plan['port']),'path':plan.get('health_path','/'),'contains':plan.get('health_contains','')}
    if not 1024<=health['port']<=65535 or not isinstance(health['path'],str) or not health['path'].startswith('/') or len(health['path'])>200 or not isinstance(health['contains'],str) or len(health['contains'])>1000:
        raise DockerBackupError('Invalid enrolled health endpoint')
    stage_user=pwd.getpwnam('serverhub-staging')
    base=protected('/var/lib/serverhub-staging',create=True)
    os.chown(base,0,stage_user.pw_gid)
    base.chmod(0o750)
    releases=base/'releases'
    releases.mkdir(mode=0o750,exist_ok=True)
    os.chown(releases,0,stage_user.pw_gid)
    identity=uuid.uuid4().hex
    release=releases/identity
    release.mkdir(mode=0o750)
    os.chown(release,0,stage_user.pw_gid)
    with tarfile.open(artifact) as archive:
        members=archive.getmembers()
        if len(members)>100000 or sum(member.size for member in members)>2*1024**3:
            raise DockerBackupError('Candidate expands beyond staging limit')
        if any(not (member.isfile() or member.isdir()) for member in members):
            raise DockerBackupError('Staging archives cannot contain links or special files')
        archive.extractall(release,filter='data')
    for path in release.rglob('*'):
        os.chown(path,0,stage_user.pw_gid)
        path.chmod(0o750 if path.is_dir() or path.stat().st_mode&0o111 else 0o640)
    data_dir=Path('/var/lib/serverhub-stage-data')/identity
    state=protected(config.get('operations_state','/var/lib/serverhub-broker/operations'),create=True)
    current=state/('stage-'+target+'.state')
    previous=json.loads(current.read_text()) if current.exists() else None
    launch={'unit':f'serverhub-stage-{target}-{identity[:12]}','directory':str(release),
            'data_directory':str(data_dir),'argv':plan['argv'],
            'environment':{**plan.get('environment',{}),'PYTHONPATH':str(release/'runtime'),'DB_PATH':str(data_dir/'application.db')},
            'memory_mb':min(int(plan.get('memory_mb',1024)),4096),'health':health}
    record={'id':identity,'kind':'staging','target_name':target,'state':'armed','deadline':time.time()+180,
            'new_launch':launch,'previous_launch':previous}
    journal=state/(identity+'.json')
    atomic(journal,record)
    try:
        if previous:
            command('systemctl','stop',previous['unit'],timeout=45)
        launch_stage(launch)
        stage_health(launch)
        atomic(current,launch)
        record['state']='committed'
        atomic(journal,record)
        return {'target':target,'artifact_id':artifact_id,'transaction_id':identity,'verified':True,
                'verification':'Independent checks, candidate SHA-256 and actual HTTP response in private network namespace',
                'unit':launch['unit'],'private_network':True,'production_deployed':False,'rollback_available':previous is not None}
    except BaseException:
        restore(record)
        record['state']='reverted'
        atomic(journal,record)
        raise
