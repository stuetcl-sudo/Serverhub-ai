from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from test_core import core_env as core_env, owner as owner, client as client, bearer
from serverhub.api import job_action, update_job_budget, JobBudgetUpdate
from serverhub.auth import Principal
from serverhub.database import SessionLocal, utcnow
from serverhub.jobs import (HANDLERS, BudgetExceeded, JobContext, Worker, submit_job,
                           parent_paused, parent_stopped, JobPaused)
from serverhub.models import Job, ModelRoute, Incident, Host, SystemState
from serverhub.policy import PermissionDenied
from serverhub.settings import get_settings


def test_budget_pause_increase_resume_completion_keeps_progress(core_env, owner, monkeypatch):
    def task(ctx, spec):
        if not ctx.job.checkpoint.get("done"):
            ctx.save_checkpoint({"done": True})
            ctx.usage(10, .1)
            raise BudgetExceeded("Next request needs room", {"estimated_input_tokens": 50, "cost_reserve": .2})
        return {"verified": True}
    monkeypatch.setitem(HANDLERS, "fixture", task)
    with SessionLocal() as db:
        job = submit_job(db, owner, "fixture", {}, token_budget=10, cost_budget=.1, max_attempts=1)
        identity = job.id
        db.commit()
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.attempts == 0 and job.checkpoint["done"]
        for tokens, cost in [(10, .1), (91, 1), (200, .1)]:
            update_job_budget(identity, JobBudgetUpdate(token_budget=tokens, cost_budget=cost), owner, db)
            with pytest.raises(HTTPException) as denied:
                job_action(identity, "resume", owner, db)
            assert denied.value.status_code == 409
            assert denied.value.detail["budget_endpoint"] == f"/api/jobs/{identity}/budget"
        update_job_budget(identity, JobBudgetUpdate(token_budget=200, cost_budget=1), owner, db)
        job_action(identity, "resume", owner, db)
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.state == "succeeded" and job.checkpoint["done"]
        assert job.tokens_used == 10 and job.attempts == 1


@pytest.mark.parametrize("route", [[], {}, 1, True, None, ""])
def test_invalid_route_returns_422_even_with_explicit_budgets(client, monkeypatch, route):
    monkeypatch.setitem(HANDLERS, "fixture", lambda *_: {})
    with SessionLocal() as db:
        headers = bearer(db)
    response = client.post("/api/jobs", headers=headers, json={"kind": "fixture",
        "spec": {"model_route": route}, "token_budget": 100, "cost_budget": 0})
    assert response.status_code == 422


def test_route_ceiling_and_owner_escalation(core_env, owner, monkeypatch):
    from serverhub.job_limits import check_route_budget
    monkeypatch.setitem(HANDLERS, "autonomous", lambda *_: {})
    with SessionLocal() as db:
        db.add(ModelRoute(name="default", enabled=True, updated_by="owner", config={
            "kind": "ollama", "model": "fixture", "base_url": "http://localhost:11434",
            "ordinary_job_token_limit": 30000, "ordinary_job_cost_limit": 2,
            "max_job_token_budget": 50000, "max_job_cost_budget": 5}))
        db.commit()
        nonowner = Principal("adult", "administrator", "adult")
        check_route_budget(nonowner, "autonomous", {}, 30000, 2)
        with pytest.raises(PermissionDenied):
            check_route_budget(nonowner, "autonomous", {}, 30001, 2)
        with pytest.raises(PermissionDenied):
            check_route_budget(nonowner, "autonomous", {}, 30000, 3)
        check_route_budget(owner, "autonomous", {}, 50000, 5)
        with pytest.raises(ValueError, match="ceiling"):
            submit_job(db, owner, "autonomous", {}, host_id="node1", token_budget=50001)
        job = submit_job(db, owner, "autonomous", {}, host_id="node1")
        db.commit()
        with pytest.raises(HTTPException) as error:
            update_job_budget(job.id, JobBudgetUpdate(token_budget=50001, cost_budget=1), owner, db)
        assert error.value.status_code == 422


def test_parent_budget_pause_blocks_tree_and_resume_releases_it(core_env, owner, monkeypatch):
    calls = []
    monkeypatch.setitem(HANDLERS, "child", lambda *_: calls.append("child") or {})
    monkeypatch.setitem(HANDLERS, "parent", lambda *_: (_ for _ in ()).throw(BudgetExceeded("budget")))
    with SessionLocal() as db:
        parent = submit_job(db, owner, "parent", {})
        child = submit_job(db, owner, "child", {}, parent_id=parent.id)
        ids = parent.id, child.id
        db.commit()
    assert Worker(isolated=False).run_once()
    assert not Worker(isolated=False).run_once()
    with SessionLocal() as db:
        child = db.get(Job, ids[1])
        assert child.state == "paused" and parent_paused(db, child)
        with pytest.raises(HTTPException):
            job_action(child.id, "resume", owner, db)
        job_action(ids[0], "resume", owner, db)
        # A delegated parent waits without occupying a running quota slot.
        parent = db.get(Job, ids[0])
        parent.state, parent.depends_on = "waiting_children", [child.id]
        db.commit()
    assert Worker(isolated=False).run_once()
    assert calls == ["child"]
    with SessionLocal() as db:
        assert db.get(Job, ids[1]).state == "succeeded"


def test_running_descendant_rechecks_ancestor_and_cancel_cascades(core_env, owner, monkeypatch):
    monkeypatch.setitem(HANDLERS, "fixture", lambda *_: {})
    with SessionLocal() as db:
        parent = submit_job(db, owner, "fixture", {})
        child = submit_job(db, owner, "fixture", {}, parent_id=parent.id)
        grandchild = submit_job(db, owner, "fixture", {}, parent_id=child.id)
        grandchild.state, grandchild.worker_id = "running", "test"
        parent.state = "paused"
        db.commit()
        ctx = JobContext(db, grandchild, owner)
        with pytest.raises(JobPaused):
            ctx.require("inventory.read")
        job_action(parent.id, "cancel", owner, db)
        assert child.state == "cancelled" and grandchild.state == "cancel_requested"
        assert parent_stopped(db, grandchild)


def test_quota_idempotence_runtime_daily_jobs_and_concurrency(core_env, owner, monkeypatch):
    monkeypatch.setitem(HANDLERS, "fixture", lambda *_: {})
    settings = get_settings()
    settings.user_daily_jobs = 2
    settings.user_daily_runtime_seconds = 20
    settings.max_user_jobs = 1
    with SessionLocal() as db:
        first = submit_job(db, owner, "fixture", {}, time_limit=10, idempotency_key="one")
        db.commit()
        assert submit_job(db, owner, "fixture", {}, time_limit=10, idempotency_key="one").id == first.id
        second = submit_job(db, owner, "fixture", {}, time_limit=10)
        db.commit()
        with pytest.raises(ValueError, match="daily job"):
            submit_job(db, owner, "fixture", {}, time_limit=1)
        db.rollback()
        settings.user_daily_jobs = 3
        with pytest.raises(ValueError, match="runtime"):
            submit_job(db, owner, "fixture", {}, time_limit=1)
        db.rollback()
        ids = first.id, second.id
    worker = Worker(isolated=False)
    assert worker._claim() == ids[0]
    assert Worker(isolated=False)._claim() is None


def test_daily_model_reservations_survive_restart_without_refund(core_env, owner, monkeypatch):
    monkeypatch.setitem(HANDLERS, "fixture", lambda *_: {})
    get_settings().user_daily_tokens = 100
    with SessionLocal() as db:
        job = submit_job(db, owner, "fixture", {})
        job.state, job.worker_id = "running", "test"
        db.commit()
        ctx = JobContext(db, job, owner)
        ctx.reserve_model_request(80, 0)
        ctx.reconcile_model_reservation()
        with pytest.raises(BudgetExceeded, match="daily"):
            ctx.reserve_model_request(21, 0)
        db.rollback()
        assert job.tokens_used == 80
        ctx.reserve_model_request(20, 0)
        assert job.tokens_used == 100


def test_monitor_restart_caps_are_per_target_and_durable(core_env, owner):
    from serverhub.extensions import reserve_monitor_restart
    class Context:
        principal = owner
        def require(self, *args):
            pass  # quota unit test; authorization/dispatch denial tested independently
    with SessionLocal() as db:
        ctx = Context()
        ctx.db = db
        ctx.job = SimpleNamespace(id="first", host_id="node1")
        remedy = {"operation": "systemd.restart", "arguments": {"service": "example.service"}}
        key, blocked = reserve_monitor_restart(ctx, remedy)
        assert key and not blocked
        assert reserve_monitor_restart(ctx, remedy) == (key, None)
        ctx.job.id = "second"
        assert reserve_monitor_restart(ctx, remedy)[1]
        row = db.scalar(select(SystemState).where(SystemState.key.like("monitor-restart:%")))
        row.value = {"attempts": [{"job": str(i), "time": utcnow().timestamp()-500} for i in range(3)]}
        db.commit()
        assert reserve_monitor_restart(ctx, remedy)[1]
        ctx.job.host_id = "node2"
        assert reserve_monitor_restart(ctx, remedy)[0]


def test_incident_delta_and_stable_observations(core_env, monkeypatch):
    import serverhub.telemetry as telemetry
    settings = get_settings()
    settings.incident_stable_seconds = 10
    clock = [utcnow()]
    monkeypatch.setattr(telemetry, "utcnow", lambda: clock[0])
    def observation(count, health="healthy", errors=None):
        return {"docker": {"containers": [{"id": "same", "name": "app", "state": "running",
                 "restart_count": count, "health": health}]}, "errors": errors or []}
    with SessionLocal() as db:
        host = db.get(Host, "node1")
        telemetry.ingest_inventory(db, host, observation(50))
        db.commit()
        assert not db.scalars(select(Incident)).all()  # historical restarts aren't current faults
        clock[0] += timedelta(seconds=5)
        telemetry.ingest_inventory(db, host, observation(55))
        db.commit()
        incident = db.scalar(select(Incident))
        assert incident.state == "open" and incident.evidence["restart_delta"] == 5
        for _ in range(3):
            clock[0] += timedelta(seconds=5)
            telemetry.ingest_inventory(db, host, observation(55))
            db.commit()
        assert incident.state == "resolved" and incident.resolution["verified"]
        assert len(incident.resolution["samples"]) == 3


def test_watchdog_cleanup_only_old_root_owned_matching_files(monkeypatch):
    import os
    import tempfile
    import time
    from pathlib import Path
    from serverhub.node import watchdog
    if os.geteuid() != 0:
        pytest.skip("requires isolated root filesystem")
    with tempfile.TemporaryDirectory(dir="/root") as directory:
        root = Path(directory)
        target = root / "app.conf"
        target.write_text("original")
        target.chmod(0o600)
        journal = root / "recovery"
        record = watchdog.arm(journal, target, timeout=10)
        key = record["id"]
        stale = root / f".serverhub-recovery-{key}-orphan"
        fresh = root / f".serverhub-recovery-{key}-fresh"
        link = root / f".serverhub-recovery-{key}-link"
        foreign = root / ".serverhub-recovery-unknown-orphan"
        for path in (stale, fresh, foreign):
            path.write_text("temporary")
            path.chmod(0o600)
        old = time.time()-7200
        os.utime(stale, (old, old))
        os.utime(foreign, (old, old))
        link.symlink_to(stale)
        # Armed/live recovery is never cleaned.
        watchdog.tick(journal)
        assert stale.exists()
        path, data = watchdog._load(journal, key)
        data.update(state="restoring", deadline=time.time()-1)
        watchdog._atomic(path, data)
        target.write_text("modified")
        assert watchdog.tick(journal)[0]["state"] == "reverted"
        assert not stale.exists() and fresh.exists() and foreign.exists() and link.is_symlink()
        assert target.read_text() == "original"


def test_incident_missing_failed_or_reset_measurements_never_prove_stability(core_env, monkeypatch):
    from serverhub.telemetry import ingest_inventory
    with SessionLocal() as db:
        host = db.get(Host, "node1")
        ingest_inventory(db, host, {"services": [{"name": "app", "active": "failed"}]})
        db.commit()
        incident = db.scalar(select(Incident))
        for value in ({}, {"services": []}, {"services": [{"name": "app", "active": "active"}], "errors": [{"collector": "services", "error": "failed"}]}):
            ingest_inventory(db, host, value)
            db.commit()
            assert incident.state == "open" and not incident.evidence.get("stable")


def test_manual_pause_cannot_bypass_budget_gate(core_env, owner, monkeypatch):
    monkeypatch.setitem(HANDLERS, "fixture", lambda *_: {})
    with SessionLocal() as db:
        job = submit_job(db, owner, "fixture", {}, token_budget=0)
        job.state, job.failure_class = "paused", "budget"
        db.commit()
        job_action(job.id, "pause", owner, db)
        with pytest.raises(HTTPException) as denied:
            job_action(job.id, "resume", owner, db)
        assert denied.value.status_code == 409


def test_paused_waiting_parent_preserves_delegated_failure_semantics(core_env, owner, monkeypatch):
    monkeypatch.setitem(HANDLERS, "fixture", lambda *_: {"verified": True})
    with SessionLocal() as db:
        parent = submit_job(db, owner, "fixture", {})
        child = submit_job(db, owner, "fixture", {}, parent_id=parent.id)
        parent.depends_on, parent.state = [child.id], "waiting_children"
        db.commit()
        job_action(parent.id, "pause", owner, db)
        job_action(parent.id, "resume", owner, db)
        assert parent.state == "waiting_children"
        child.state = "failed"
        db.commit()
        identity = parent.id
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        assert db.get(Job, identity).state == "succeeded"


def test_expired_child_lease_under_paused_parent_does_not_exhaust_attempts(core_env, owner, monkeypatch):
    monkeypatch.setitem(HANDLERS, "fixture", lambda *_: {})
    with SessionLocal() as db:
        parent = submit_job(db, owner, "fixture", {})
        child = submit_job(db, owner, "fixture", {}, parent_id=parent.id, max_attempts=1)
        parent.state, parent.failure_class = "paused", "budget"
        child.state, child.worker_id, child.attempts = "running", "dead", 1
        child.lease_until = utcnow()-timedelta(seconds=1)
        child.checkpoint = {"in_flight": {"idempotency_key": "stable-write"}}
        identity = child.id
        db.commit()
    assert not Worker(isolated=False).run_once()
    with SessionLocal() as db:
        child = db.get(Job, identity)
        assert (child.state, child.failure_class, child.attempts) == ("paused", "parent_paused", 0)
        assert child.checkpoint["in_flight"]["idempotency_key"] == "stable-write"


def test_daily_and_pending_limits_reject_without_charging_or_dispatch(core_env, owner, monkeypatch):
    from serverhub.job_limits import charge_daily
    monkeypatch.setitem(HANDLERS, "fixture", lambda *_: {})
    settings = get_settings()
    settings.max_user_pending_jobs = 1
    settings.user_daily_cost = 1
    with SessionLocal() as db:
        first = submit_job(db, owner, "fixture", {})
        db.commit()
        with pytest.raises(ValueError, match="pending"):
            submit_job(db, owner, "fixture", {})
        db.rollback()
        charge_daily(db, owner.id, 0, 1)
        db.commit()
        first.state, first.failure_class = "paused", "budget"
        first.checkpoint = {"budget_pause": {"minimum_tokens": 32, "minimum_cost": .1}}
        db.commit()
        with pytest.raises(HTTPException) as denied:
            job_action(first.id, "resume", owner, db)
        assert denied.value.status_code == 409 and denied.value.detail["job_budget_increase_will_not_bypass_quota"]


def test_monitor_denied_grant_never_reserves_restart(core_env, owner, monkeypatch):
    from serverhub.extensions import reserve_monitor_restart
    monkeypatch.setitem(HANDLERS, "fixture", lambda *_: {})
    with SessionLocal() as db:
        job = submit_job(db, owner, "fixture", {}, host_id="node1")
        job.state, job.worker_id = "running", "test"
        db.commit()
        ctx = JobContext(db, job, owner)
        with pytest.raises(PermissionDenied):
            reserve_monitor_restart(ctx, {"operation": "systemd.restart", "arguments": {"service": "example.service"}})
        assert not db.scalars(select(SystemState).where(SystemState.key.like("monitor-restart:%"))).all()


def test_parent_resume_accounts_for_delegated_usage_and_verification_reserve(core_env, owner, monkeypatch):
    monkeypatch.setitem(HANDLERS, "fixture", lambda *_: {})
    with SessionLocal() as db:
        parent = submit_job(db, owner, "fixture", {}, token_budget=5000)
        child = submit_job(db, owner, "fixture", {}, parent_id=parent.id)
        child.tokens_used, child.state = 1000, "succeeded"
        parent.state, parent.failure_class = "paused", "budget"
        parent.checkpoint = {"budget_pause": {"minimum_tokens": 4032}}
        db.commit()
        with pytest.raises(HTTPException) as denied:
            job_action(parent.id, "resume", owner, db)
        assert denied.value.status_code == 409 and denied.value.detail["remaining_tokens"] == 4000
        update_job_budget(parent.id, JobBudgetUpdate(token_budget=5032, cost_budget=1), owner, db)
        job_action(parent.id, "resume", owner, db)
        assert parent.state == "queued"


def test_removing_container_healthcheck_is_not_verified_recovery(core_env):
    from serverhub.telemetry import ingest_inventory
    with SessionLocal() as db:
        host = db.get(Host, "node1")
        def observation(health):
            return {"docker": {"containers": [{"id": "same", "name": "app", "state": "running",
                    "health": health, "restart_count": 0}]}}
        ingest_inventory(db, host, observation("unhealthy"))
        db.commit()
        incident = db.scalar(select(Incident))
        for _ in range(4):
            ingest_inventory(db, host, observation(None))
            db.commit()
        assert incident.state == "open" and incident.evidence["stable"] == []
