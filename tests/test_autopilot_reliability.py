from datetime import timedelta
from types import SimpleNamespace
import multiprocessing
import os
import signal
import threading
import time

import pytest

from test_core import core_env as core_env, owner as owner
from serverhub.database import SessionLocal, utcnow
from serverhub.jobs import HANDLERS, Worker, submit_job, elapsed_seconds, mark_paused, resume_clock
from serverhub.models import Job, ModelRoute
from serverhub.policy import PermissionDenied
from serverhub.development.workspace import read_source
from serverhub.development.config import DevelopmentError


def test_clock_excludes_only_explicit_pause_and_preserves_real_execution():
    now = utcnow()
    job = SimpleNamespace(started_at=now-timedelta(seconds=100), paused_seconds=0,
                          paused_at=None, state="waiting_approval")
    mark_paused(job)
    job.paused_at = now-timedelta(seconds=80)
    assert elapsed_seconds(job, now) == 20
    resume_clock(job)
    assert 19 <= elapsed_seconds(job) <= 21
    assert job.started_at == now-timedelta(seconds=100)
    assert job.paused_at is None
    job.state = "running"
    mark_paused(job)
    assert job.paused_at is None


def test_model_defaults_and_explicit_job_budget(core_env, owner, monkeypatch):
    monkeypatch.setitem(HANDLERS, "autonomous", lambda *_: {})
    with SessionLocal() as db:
        db.add(ModelRoute(name="default", config={"kind":"ollama", "model":"fixture",
            "base_url":"http://localhost:11434", "default_job_token_budget":85000,
            "default_job_cost_budget":2.5}, enabled=True, updated_by="owner"))
        db.commit()
        job = submit_job(db, owner, "autonomous", {"prompt":"inspect"}, host_id="node1")
        assert (job.token_budget,job.cost_budget)==(85000,2.5)
        explicit = submit_job(db, owner, "autonomous", {"prompt":"inspect"}, host_id="node1",
                              token_budget=0, cost_budget=0)
        assert (explicit.token_budget,explicit.cost_budget)==(0,0)


def test_approval_pause_survives_worker_claim_but_permission_is_rechecked(core_env, owner, monkeypatch):
    calls=[]
    def handler(ctx, spec):
        calls.append("attempt")
        ctx.save_checkpoint({"progress":"retained"})
        raise PermissionDenied("No active grant")
    monkeypatch.setitem(HANDLERS, "pause-test", handler)
    with SessionLocal() as db:
        job=submit_job(db, owner, "pause-test", {}, time_limit=20)
        identity=job.id
        db.commit()
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job=db.get(Job,identity)
        assert job.state=="waiting_approval" and job.paused_at
        job.started_at-=timedelta(hours=2)
        job.paused_at-=timedelta(hours=2)
        resume_clock(job)
        job.state="queued"
        db.commit()
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job=db.get(Job,identity)
        assert job.state=="waiting_approval" and job.checkpoint=={"progress":"retained"}
        assert len(calls)==2
        assert elapsed_seconds(job)<20


def _signal_child():
    import serverhub.jobs as jobs
    jobs.get_engine=lambda: SimpleNamespace(dispose=lambda **kw: None)
    jobs.execute_job=lambda *_: time.sleep(20)
    jobs._child_execute("test", "test")


def test_fork_child_does_not_inherit_worker_sigterm_handler():
    original=signal.signal(signal.SIGTERM, lambda *_: None)
    process=multiprocessing.get_context("fork").Process(target=_signal_child)
    try:
        process.start()
        time.sleep(.2)
        process.terminate()
        process.join(2)
        assert process.exitcode == -signal.SIGTERM
    finally:
        signal.signal(signal.SIGTERM,original)
        if process.is_alive():
            process.kill()
            process.join()


@pytest.mark.parametrize("path", ["../secret.txt", "/etc/passwd", ".env", ".ssh/key.txt",
                                   "secrets.json", "secrets.toml", "credentials.txt", ".git/config", "key.pem"])
def test_read_source_rejects_sensitive_and_escaping_paths(tmp_path,path):
    with pytest.raises((DevelopmentError,OSError)):
        read_source(tmp_path,path)


def test_read_source_does_not_follow_links_or_special_files(tmp_path):
    outside=tmp_path/"secret.txt"
    outside.write_text("secret")
    workspace=tmp_path/"workspace"
    workspace.mkdir()
    (workspace/"link.txt").symlink_to(outside)
    (workspace/"parent").symlink_to(tmp_path, target_is_directory=True)
    os.link(outside, workspace/"hard.txt")
    os.mkfifo(workspace/"fifo.txt")
    for path in ["link.txt","parent/secret.txt","hard.txt","fifo.txt"]:
        with pytest.raises((OSError,DevelopmentError)):
            read_source(workspace,path)
    (workspace/"good.py").write_text("print('safe')")
    assert read_source(workspace,"good.py")=="print('safe')"


def test_broker_connection_slots_are_bounded_and_released(monkeypatch):
    from serverhub.node.broker import BrokerServer
    import socketserver
    server=object.__new__(BrokerServer)
    server.slots=threading.BoundedSemaphore(1)
    started=[]
    closed=[]
    monkeypatch.setattr(socketserver.ThreadingMixIn,"process_request",lambda *args: started.append(args))
    monkeypatch.setattr(socketserver.ThreadingMixIn,"process_request_thread",lambda *args: None)
    monkeypatch.setattr(server,"shutdown_request",lambda request: closed.append(request))
    server.process_request("first",None)
    server.process_request("second",None)
    assert len(started)==1 and closed==["second"]
    server.process_request_thread("first",None)
    server.process_request("third",None)
    assert len(started)==2


def test_watchdog_stale_temporary_cannot_block_retry(monkeypatch):
    import tempfile
    from pathlib import Path
    from serverhub.node import watchdog
    if os.geteuid()!=0:
        pytest.skip("requires disposable root filesystem")
    with tempfile.TemporaryDirectory(dir="/root") as directory:
        root=Path(directory)
        root.chmod(0o700)
        target=root/"application.conf"
        target.write_text("original")
        target.chmod(0o640)
        clock=[1000]
        monkeypatch.setattr(watchdog.time,"time",lambda:clock[0])
        record=watchdog.arm(root/"recovery",target,timeout=10)
        stale=root/(".serverhub-recovery-"+record["id"])
        stale.write_text("interrupted")
        target.write_text("changed")
        clock[0]+=11
        replace=watchdog.os.replace
        def fail_target(source,destination):
            if destination==target:
                raise OSError("simulated interruption before rename")
            return replace(source,destination)
        monkeypatch.setattr(watchdog.os,"replace",fail_target)
        assert watchdog.tick(root/"recovery")[0]["state"]=="failed"
        assert list(root.glob(".serverhub-recovery-*"))==[stale]
        monkeypatch.setattr(watchdog.os,"replace",replace)
        assert watchdog.tick(root/"recovery")[0]["state"]=="reverted"
        assert target.read_text()=="original" and stale.read_text()=="interrupted"


def test_real_broker_reads_progress_during_serialized_writes(tmp_path,monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from serverhub.node import broker
    entered=threading.Event()
    release=threading.Event()
    active=[0,0]
    lock=threading.Lock()
    audit=[]
    def execute(operation,args,config):
        if operation=="systemd.restart":
            with lock:
                active[0]+=1
                active[1]=max(active)
            entered.set()
            assert release.wait(3)
            with lock:
                active[0]-=1
        return {"verified":True}
    monkeypatch.setattr(broker,"execute",execute)
    monkeypatch.setattr(broker,"append_broker_audit",lambda config,record:audit.append(record))
    path=str(tmp_path/"broker.sock")
    try:
        server=broker.BrokerServer(path,{"allowed_uids":[os.getuid()],"max_connections":4})
    except PermissionError:
        if os.environ.get("CI"):
            raise
        pytest.skip("local sandbox denies Unix sockets; required in Ubuntu CI")
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            first=pool.submit(broker.call_broker,path,"systemd.restart",{"service":"demo"})
            assert entered.wait(2)
            second=pool.submit(broker.call_broker,path,"systemd.restart",{"service":"demo"})
            assert broker.call_broker(path,"systemd.status",{"service":"demo"})["verified"]
            release.set()
            assert first.result(3)["verified"] and second.result(3)["verified"]
        assert active[1]==1
        assert len([r for r in audit if r["phase"]=="after"])==3
        server.config["allowed_uids"]=[]
        with pytest.raises(broker.BrokerDenied,match="peer identity"):
            broker.call_broker(path,"systemd.restart",{"service":"demo"})
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(3)


def test_budget_pause_update_preserves_usage_and_scope(core_env,owner,monkeypatch):
    from serverhub.api import update_job_budget, JobBudgetUpdate
    from serverhub.auth import Principal
    from fastapi import HTTPException
    from serverhub.jobs import BudgetExceeded
    def handler(ctx,spec):
        ctx.save_checkpoint({"step":"saved"})
        ctx.usage(10,.1)
        raise BudgetExceeded("Output reservation does not fit remaining budget")
    monkeypatch.setitem(HANDLERS,"budget-test",handler)
    with SessionLocal() as db:
        job=submit_job(db,owner,"budget-test",{},token_budget=10,cost_budget=.1)
        identity=job.id
        db.commit()
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job=db.get(Job,identity)
        assert job.state=="paused" and job.failure_class=="budget"
        with pytest.raises(HTTPException):
            update_job_budget(identity,JobBudgetUpdate(token_budget=100,cost_budget=1),
                              Principal("adult","adult","adult"),db)
        with pytest.raises(HTTPException):
            update_job_budget(identity,JobBudgetUpdate(token_budget=9,cost_budget=1),owner,db)
        update_job_budget(identity,JobBudgetUpdate(token_budget=100,cost_budget=1),owner,db)
        assert (job.tokens_used,job.cost_used)==(10,.1)
        assert job.checkpoint["step"]=="saved" and job.state=="paused"


def test_expired_grant_stays_expired_after_approval_pause(core_env,monkeypatch):
    from serverhub.auth import Principal
    from serverhub.models import Policy
    from serverhub.policy import authorize
    with SessionLocal() as db:
        policy=Policy(name="expired",subject_id="adult",host_id="node1",project="example",
                      operations=["development.read"],constraints={},environment="any",
                      expires_at=utcnow()-timedelta(seconds=1),created_by="owner")
        db.add(policy)
        db.commit()
        with pytest.raises(PermissionDenied):
            authorize(db,Principal("adult","adult","adult"),"development.read","node1","example")


def test_pause_schema_upgrade_and_downgrade_preserves_job(core_env,owner):
    from alembic import command
    from serverhub.cli import _alembic_config
    from serverhub.database import get_engine
    from sqlalchemy import text, inspect
    HANDLERS["migration-test"]=lambda *_:{}
    with SessionLocal() as db:
        job=submit_job(db,owner,"migration-test",{})
        job.state="waiting_approval"
        identity=job.id
        db.commit()
    # Exercise actual old table shape, not only metadata.create_all().
    with get_engine().begin() as connection:
        connection.execute(text("ALTER TABLE jobs DROP COLUMN paused_at"))
        connection.execute(text("ALTER TABLE jobs DROP COLUMN paused_seconds"))
    command.stamp(_alembic_config(),"0005_priority")
    command.upgrade(_alembic_config(),"head")
    with SessionLocal() as db:
        job=db.get(Job,identity)
        assert job.paused_at and job.paused_seconds==0
    command.downgrade(_alembic_config(),"0005_priority")
    assert "paused_at" not in {c["name"] for c in inspect(get_engine()).get_columns("jobs")}
    command.upgrade(_alembic_config(),"head")
    with SessionLocal() as db:
        assert db.get(Job,identity).state=="waiting_approval"


def test_legacy_release_identity_keeps_historical_schema():
    # This is deliberately a source contract check: the privileged full migration
    # is exercised against two actual old installations by Ubuntu CI.
    import inspect
    from serverhub.ops.migrate_units import plan
    source = inspect.getsource(plan)
    assert "'schema_revision': '0005_priority'" in source
    assert "'schema_revision': '0006_pause_clock'" not in source


def test_pausing_unstarted_job_does_not_create_execution_credit():
    job = SimpleNamespace(started_at=None, paused_seconds=0,
                          paused_at=utcnow()-timedelta(hours=2))
    resume_clock(job)
    assert job.paused_seconds == 0 and job.paused_at is None
    now = utcnow()
    job.started_at = now-timedelta(seconds=30)
    assert elapsed_seconds(job,now) == 30
