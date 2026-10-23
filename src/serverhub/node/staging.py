"""Native isolated staging under a credential-free Linux identity and private netns."""
import hashlib
import json
import os
from pathlib import Path
import grp
import re
import tarfile
import stat
import shutil
import time
import uuid

from .docker_backup import protected, atomic, DockerBackupError
from .discovery import command
from serverhub.ops.operation_watchdog import launch_stage, restore, stage_health


def secure_release_permissions(release, project_gid):
    # A tar member named "." can reset the root to the worker's 0700 umask.
    # Normalize the root too; only this project's group receives read access.
    for path in [release,*release.rglob('*')]:
        executable=bool(path.stat().st_mode&0o111)
        os.chown(path,0,project_gid)
        path.chmod(0o750 if path.is_dir() or executable else 0o640)


def snapshot_candidate(source, artifact_id, snapshot):
    """Anchor each directory and both files with O_NOFOLLOW before root reads."""
    source=Path(source)
    if not source.is_absolute() or '..' in source.parts:
        raise DockerBackupError('Absolute candidate root required')
    directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in source.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            os.close(directory)
            directory=child
        with os.fdopen(os.open(artifact_id+'.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory),'rb') as stream:
            raw=stream.read(1024**2+1)
            if len(raw)>1024**2:
                raise DockerBackupError('Candidate receipt exceeds limit')
            data=json.loads(raw)
        digest=hashlib.sha256()
        total=0
        fd=os.open(artifact_id+'.tar',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
        with os.fdopen(fd,'rb') as inp, snapshot.open('xb') as out:
            snapshot.chmod(0o600)
            if not stat.S_ISREG(os.fstat(inp.fileno()).st_mode):
                raise DockerBackupError('Candidate archive must be a regular file')
            for block in iter(lambda:inp.read(1024**2),b''):
                total+=len(block)
                if total>2*1024**3:
                    raise DockerBackupError('Candidate archive exceeds limit')
                digest.update(block)
                out.write(block)
            out.flush()
            os.fsync(out.fileno())
        if digest.hexdigest()!=data.get('candidate',{}).get('sha256'):
            raise DockerBackupError('Candidate digest mismatch')
        return data
    except BaseException:
        snapshot.unlink(missing_ok=True)
        raise
    finally:
        os.close(directory)


def deploy(arguments, config):
    state=protected(config.get('operations_state','/var/lib/serverhub-broker/operations'),create=True)
    identity=uuid.uuid4().hex
    artifact=state/('candidate-'+identity+'.tar')
    try:
        return _deploy(arguments,config,state,identity,artifact)
    finally:
        artifact.unlink(missing_ok=True)


def _deploy(arguments, config, state, identity, artifact):
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
    data=snapshot_candidate(source,artifact_id,artifact)
    if data.get('project')!=target or not data.get('tests_passed') or not data.get('independent_checks_passed'):
        artifact.unlink(missing_ok=True)
        raise DockerBackupError('Candidate requires matching project, tests and independent checks')
    health={'port':int(plan['port']),'path':plan.get('health_path','/'),'contains':plan.get('health_contains','')}
    if not 1024<=health['port']<=65535 or not isinstance(health['path'],str) or not health['path'].startswith('/') or len(health['path'])>200 or not isinstance(health['contains'],str) or len(health['contains'])>1000:
        raise DockerBackupError('Invalid enrolled health endpoint')
    group='serverhub-project-'+hashlib.sha256(target.encode()).hexdigest()[:12]
    if plan.get('project_group')!=group:
        raise DockerBackupError('Re-enroll the staging project to establish its isolated source group')
    project_gid=grp.getgrnam(group).gr_gid
    from .administration import approved_file
    acceptance=approved_file(plan['acceptance_script'])
    base=protected('/var/lib/serverhub-staging',create=True)
    os.chown(base,0,project_gid)
    base.chmod(0o755)
    releases=base/'releases'
    releases.mkdir(mode=0o755,exist_ok=True)
    releases.chmod(0o755)
    os.chown(releases,0,project_gid)
    release=releases/identity
    release.mkdir(mode=0o750)
    os.chown(release,0,project_gid)
    with tarfile.open(artifact) as archive:
        members=archive.getmembers()
        if len(members)>100000 or sum(member.size for member in members)>2*1024**3:
            raise DockerBackupError('Candidate expands beyond staging limit')
        if any(not (member.isfile() or member.isdir()) for member in members):
            raise DockerBackupError('Staging archives cannot contain links or special files')
        if shutil.disk_usage(releases).free < int(sum(member.size for member in members)*1.2)+64*1024**2:
            raise DockerBackupError('Insufficient staging capacity')
        archive.extractall(release,filter='data')
    artifact.unlink(missing_ok=True)
    secure_release_permissions(release,project_gid)
    # Root chooses this immutable acceptance executable; it runs as a separate
    # nonprivileged identity, outside the AI worker's writable receipt state.
    command('systemd-run','--quiet','--wait','--pipe','--collect','--unit','serverhub-check-'+identity,
            '--property','User=serverhub-staging','--property','Group='+group,
            '--property','NoNewPrivileges=yes','--property','CapabilityBoundingSet=',
            '--property','ProtectSystem=strict','--property','ProtectHome=yes','--property','PrivateNetwork=yes',
            '--property','PrivateTmp=yes','--property','MemoryMax=256M','--property','TasksMax=32',
            '--property','RuntimeMaxSec=90',
            '--property','InaccessiblePaths=-/etc/serverhub -/var/lib/serverhub-worker -/var/lib/serverhub-broker -/var/run/docker.sock',
            '--','/usr/bin/python3','-I',str(acceptance),str(release),timeout=100)
    data_dir=Path('/var/lib/serverhub-stage-data')/identity
    state=protected(config.get('operations_state','/var/lib/serverhub-broker/operations'),create=True)
    current=state/('stage-'+target+'.state')
    previous=json.loads(current.read_text()) if current.exists() else None
    launch={'unit':f'serverhub-stage-{target}-{identity[:12]}','directory':str(release),
            'data_directory':str(data_dir),'argv':plan['argv'],
            'environment':{**plan.get('environment',{}),'PYTHONPATH':str(release/'runtime'),'DB_PATH':str(data_dir/'application.db')},
            'project_group':group,'memory_mb':min(int(plan.get('memory_mb',1024)),4096),'health':health}
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
