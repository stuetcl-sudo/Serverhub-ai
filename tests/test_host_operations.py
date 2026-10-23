"""Adversarial unit/integration tests complement real guarded Ubuntu operations."""
import json
import os
from pathlib import Path
import secrets
import tempfile

import pytest

from test_core import core_env as core_env, client as client, bearer, owner as owner
from serverhub.node.docker_backup import crypt_file, DockerBackupError, tree_manifest, atomic
from serverhub.node.administration import execute_administration
from serverhub.database import SessionLocal, utcnow
from serverhub.jobs import HANDLERS, Worker, submit_job
from serverhub.models import Job, Policy
from serverhub.policy import authorize, PermissionDenied
from datetime import timedelta


def test_backup_encryption_authentication_and_content(tmp_path):
    from cryptography.exceptions import InvalidTag
    key=secrets.token_bytes(32)
    plain=tmp_path/'plain'
    encrypted=tmp_path/'encrypted'
    restored=tmp_path/'restored'
    plain.write_bytes(b'SECRET DATABASE CONTENT\n'*10000)
    crypt_file(plain,encrypted,key)
    assert b'SECRET DATABASE' not in encrypted.read_bytes()
    crypt_file(encrypted,restored,key,decrypt=True)
    assert restored.read_bytes()==plain.read_bytes()
    damaged=bytearray(encrypted.read_bytes())
    damaged[20]^=1
    encrypted.write_bytes(damaged)
    with pytest.raises(InvalidTag):
        crypt_file(encrypted,tmp_path/'invalid',key,decrypt=True)


def test_storage_manifest_detects_changes_and_preserves_links(tmp_path):
    (tmp_path/'a').write_text('original')
    (tmp_path/'b').symlink_to('a')
    before=tree_manifest(tmp_path)
    assert before['b']=={'link':'a'}
    (tmp_path/'a').write_text('changed')
    assert tree_manifest(tmp_path)!=before


def test_recovered_transaction_cannot_be_rearmed_or_committed(tmp_path):
    journal=tmp_path/'operation.json'
    atomic(journal,{'state':'armed'})
    atomic(journal,{'state':'reverted'})
    for state in ('armed','committed'):
        with pytest.raises(DockerBackupError,match='already reverted'):
            atomic(journal,{'state':state})
    assert json.loads(journal.read_text())['state']=='reverted'


def test_administration_requires_local_root_enrollment():
    with pytest.raises(DockerBackupError,match='enrollment'):
        execute_administration('package.apply',{'target':'anything'},{})
    with pytest.raises(DockerBackupError,match='exact'):
        execute_administration('package.apply',{'target':'anything','command':'id'},{'enable_administration':True})


def test_once_delegated_maintenance_stays_exact_expiring_and_role_scoped(client,owner):
    with SessionLocal() as db:
        headers=bearer(db)
    result=client.post('/api/policies/profiles',headers=headers,json={'profile':'maintenance','subject_id':'owner','host_id':'node1',
        'hours':1,'backup_targets':['data'],'package_targets':['approved'],'configuration_targets':['app']})
    assert result.status_code==201,result.text
    with SessionLocal() as db:
        for _ in range(3):
            authorize(db,owner,'package.apply','node1',arguments={'target':'approved'})
            authorize(db,owner,'docker.backup.create','node1',arguments={'target':'data'})
        with pytest.raises(PermissionDenied):
            authorize(db,owner,'package.apply','node1',arguments={'target':'other'})
        with pytest.raises(PermissionDenied):
            authorize(db,owner,'configuration.apply','node2',arguments={'target':'app'})
        for grant in db.query(Policy).all():
            grant.expires_at=utcnow()-timedelta(seconds=1)
        db.commit()
        with pytest.raises(PermissionDenied):
            authorize(db,owner,'package.apply','node1',arguments={'target':'approved'})


def test_priorities_are_persisted_and_do_not_bypass_dependencies(core_env,owner):
    HANDLERS['priority-test']=lambda ctx,spec:{'verified':True}
    with SessionLocal() as db:
        low=submit_job(db,owner,'priority-test',{},priority=-1)
        high=submit_job(db,owner,'priority-test',{},priority=10,depends_on=[low.id])
        middle=submit_job(db,owner,'priority-test',{},priority=5)
        identities=low.id,high.id,middle.id
        db.commit()
    worker=Worker(isolated=False)
    assert worker.run_once()
    with SessionLocal() as db:
        assert db.get(Job,identities[2]).state=='succeeded'
        assert db.get(Job,identities[1]).state=='queued'
    assert worker.run_once() and worker.run_once()
    with SessionLocal() as db:
        assert all(db.get(Job,key).state=='succeeded' for key in identities)


def test_root_named_plan_cannot_touch_control_plane():
    if os.geteuid()!=0:
        pytest.skip('root-only protected fixture')
    with tempfile.TemporaryDirectory(prefix='serverhub-admin-test-',dir='/opt') as directory:
        from serverhub.node.docker_backup import digest
        root=Path(directory)
        candidate=root/'candidate'
        candidate.write_text('arbitrary bytes')
        config={'enable_administration':True,'operations_state':str(root/'state'),
                'configuration_plans':{'unsafe':{'path':'/etc/passwd','candidate':{'path':str(candidate),'sha256':digest(candidate)}}}}
        with pytest.raises(DockerBackupError,match='Protected'):
            execute_administration('configuration.apply',{'target':'unsafe'},config)
