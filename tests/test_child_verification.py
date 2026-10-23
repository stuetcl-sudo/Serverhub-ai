"""A parent cannot borrow another task's success as proof."""
from types import SimpleNamespace
from test_core import core_env as core_env, owner as owner
from serverhub.database import SessionLocal
from serverhub.jobs import HANDLERS, submit_job
from serverhub.verification import verify_task


def test_only_this_owners_verified_direct_child_can_satisfy_acceptance(core_env,owner):
    HANDLERS['proof-fixture']=lambda ctx,spec:{}
    with SessionLocal() as db:
        parent=submit_job(db,owner,'proof-fixture',{},host_id='node1')
        child=submit_job(db,owner,'proof-fixture',{},host_id='node1',parent_id=parent.id)
        other=submit_job(db,owner,'proof-fixture',{},host_id='node1')
        for job in (child,other):
            job.state='succeeded'
            job.result={'verified':True}
        db.commit()
        ctx=SimpleNamespace(db=db,job=parent)
        assert verify_task(ctx,[{'kind':'job.verified','target':child.id}])['verified']
        assert not verify_task(ctx,[{'kind':'job.verified','target':other.id}])['verified']
        child.result={'verified':False}
        db.commit()
        assert not verify_task(ctx,[{'kind':'job.verified','target':child.id}])['verified']
        assert not verify_task(ctx,[{'kind':'job.verified','target':'not-a-job-id'}])['verified']
