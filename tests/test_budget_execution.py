"""Budget admission is paused without burning attempts; actual work is never refunded."""
import json

import httpx
from sqlalchemy import select

from serverhub.ai import orchestrator
from serverhub.ai.providers import ChatProvider, ProviderConfig, PreflightRejected
from serverhub.database import SessionLocal
from serverhub.jobs import Worker, submit_job
from serverhub.models import InventorySample, Job, JobEvent
from test_core import core_env as core_env, client as client, bearer  # noqa: F401


def test_preflight_pause_resume_and_verified_read_only_job_complete(client, monkeypatch):
    cfg = ProviderConfig(kind="ollama", model="qwen2.5:3b", base_url="http://localhost:11434", context_limit=1024)
    monkeypatch.setattr(orchestrator, "load_routes", lambda: {"default": cfg})
    requests = []
    replies = [
        {"content": "", "tool_calls": [{"function": {"name": "inventory__read", "arguments": {}}}]},
        {"content": "", "tool_calls": [{"function": {"name": "task__verify", "arguments": {"checks": [{"kind": "inventory.fresh"}, {"kind": "host.online"}]}}}]},
        {"content": "Read-only inventory and specific freshness checks completed"},
    ]
    def handle(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"message": replies[len(requests)-1], "prompt_eval_count": 100, "eval_count": 20})
    monkeypatch.setattr(orchestrator, "ChatProvider", lambda config: ChatProvider(config, transport=httpx.MockTransport(handle)))
    with SessionLocal() as db:
        headers = bearer(db)
        db.add(InventorySample(host_id="node1", metrics={}))
        db.commit()
    response = client.post("/api/jobs", headers=headers, json={"kind": "autonomous", "host_id": "node1", "token_budget": 20000, "spec": {"prompt": "Read inventory; verify freshness. PRIVATE_SENTINEL"}})
    identity = response.json()["id"]
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert (job.state, job.attempts, job.tokens_used) == ("paused", 0, 0)
        assert job.failure_class == "preflight" and job.worker_id is None
        assert job.result["preflight"]["context_limit"] == 1024
        assert job.result["preflight"]["remaining_job_budget"] == 20000
        assert "PRIVATE_SENTINEL" not in job.error
        assert "remaining job budget=" in job.error
        events = db.scalars(select(JobEvent).where(JobEvent.job_id == identity)).all()
        assert any(event.message == "Job interrupted" for event in events)
    assert requests == []
    assert not Worker(isolated=False).run_once()  # no automatic busy retry loop
    cfg.context_limit = 16384
    assert client.post(f"/api/jobs/{identity}/resume", headers=headers).status_code == 200
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.state == "succeeded", job.error
        assert job.attempts == 1 and job.tokens_used == 360
        assert job.result["verified"] and len(job.result["evidence"]) == 2
    assert len(requests) == 3


def test_preflight_after_a_real_request_in_same_attempt_does_not_refund_attempt(client, monkeypatch):
    cfg = ProviderConfig(kind="ollama", model="local", base_url="http://localhost:11434")
    monkeypatch.setattr(orchestrator, "load_routes", lambda: {"default": cfg})
    class ActiveThenReject:
        def __init__(self, config):
            pass
        def complete(self, messages, tools, budget, before_request=None):
            before_request()  # a request was attempted, including uncertain billing
            raise PreflightRejected("A retry cannot fit after an attempted request")
    monkeypatch.setattr(orchestrator, "ChatProvider", ActiveThenReject)
    with SessionLocal() as db:
        from serverhub.auth import Principal
        job = submit_job(db, Principal("owner", "owner", "owner"), "autonomous", {"prompt": "Read inventory"}, host_id="node1")
        identity = job.id
        db.commit()
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.state == "failed" and job.attempts == 1
        assert job.failure_class == "budget"


def test_pending_tool_work_before_model_preflight_does_not_refund_claim(client, monkeypatch):
    from serverhub.auth import Principal
    config = ProviderConfig(kind="ollama", model="local", base_url="http://127.0.0.1:1", context_limit=1024)
    monkeypatch.setattr(orchestrator, "load_routes", lambda: {"default": config})
    with SessionLocal() as db:
        job = submit_job(db, Principal("owner", "owner", "owner"), "autonomous", {"prompt": "Read inventory"}, host_id="node1")
        job.checkpoint = {"ai": {"specialist": "infrastructure", "step": 1,
            "messages": [{"role": "system", "content": "Read only"}, {"role": "user", "content": "Inspect"}],
            "evidence": [], "completed_calls": {}, "pending_calls": [{"id": "read1", "name": "inventory__read", "operation": "inventory.read", "arguments": {}}]}}
        identity = job.id
        db.commit()
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.state == "failed" and job.failure_class == "budget"
        assert job.attempts == 1 and "read1" in job.checkpoint["ai"]["completed_calls"]


def test_replaying_cached_tool_result_before_preflight_does_not_spend_an_attempt(client, monkeypatch):
    from serverhub.auth import Principal
    config = ProviderConfig(kind="ollama", model="local", base_url="http://127.0.0.1:1", context_limit=1024)
    monkeypatch.setattr(orchestrator, "load_routes", lambda: {"default": config})
    with SessionLocal() as db:
        job = submit_job(db, Principal("owner", "owner", "owner"), "autonomous", {"prompt": "Read inventory"}, host_id="node1")
        job.checkpoint = {"ai": {"specialist": "infrastructure", "step": 1,
            "messages": [{"role": "system", "content": "Read only"}], "evidence": [],
            "completed_calls": {"read1": {"inventory": {"os": {"kernel": "test"}}}},
            "pending_calls": [{"id": "read1", "name": "inventory__read", "operation": "inventory.read", "arguments": {}}]}}
        identity = job.id
        db.commit()
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.state == "paused" and job.failure_class == "preflight"
        assert job.attempts == 0 and job.tokens_used == 0


def running_context(db):
    from datetime import timedelta
    from serverhub.auth import Principal
    from serverhub.database import utcnow
    from serverhub.jobs import JobContext
    actor = Principal("owner", "owner", "owner")
    job = submit_job(db, actor, "autonomous", {"prompt": "Read inventory"}, host_id="node1")
    job.state, job.worker_id, job.attempts = "running", "old-worker", 1
    job.started_at, job.lease_until = utcnow(), utcnow() + timedelta(minutes=1)
    db.commit()
    return JobContext(db, job, actor)


def test_durable_reservation_is_charged_once_after_interruption_and_no_actual_reply(client, monkeypatch):
    from datetime import timedelta
    from serverhub.database import utcnow
    with SessionLocal() as db:
        context = running_context(db)
        context.reserve_model_request(500, .01)
        identity = context.job.id
        context.job.lease_until = utcnow() - timedelta(seconds=1)
        db.commit()
    cfg = ProviderConfig(kind="ollama", model="local", base_url="http://127.0.0.1:1", context_limit=1024)
    monkeypatch.setattr(orchestrator, "load_routes", lambda: {"default": cfg})
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert (job.state, job.attempts, job.tokens_used) == ("paused", 1, 500)
        assert job.cost_used == .01
        assert "model_request_reservation" not in job.checkpoint
        assert job.result["preflight"]["remaining_job_budget"] == 19500
        headers = bearer(db)
    assert client.post(f"/api/jobs/{identity}/resume", headers=headers).status_code == 200
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.tokens_used == 500 and job.cost_used == .01 and job.attempts == 1


def test_cancellation_still_records_reported_usage_and_cannot_refund_earlier_work(client):
    import pytest
    with SessionLocal() as db:
        context = running_context(db)
        context.job.tokens_used, context.job.cost_used = 200, .01
        db.commit()
        context.reserve_model_request(500, .1)
        context.job.state = "cancel_requested"
        db.commit()
        with pytest.raises(ValueError, match="earlier requests"):
            context.record_model_usage(199, .01)
        context.record_model_usage(240, .02)
        identity = context.job.id
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.tokens_used == 240 and job.cost_used == .02
        assert job.state == "cancel_requested" and "model_request_reservation" not in job.checkpoint


def test_late_old_worker_cannot_refund_reservation_after_lease_owner_changed(client):
    import pytest
    from serverhub.jobs import LeaseLost
    with SessionLocal() as db:
        context = running_context(db)
        context.reserve_model_request(500, .01)
        context.job.worker_id = "new-worker"
        db.commit()
        with pytest.raises(LeaseLost):
            context.record_model_usage(10, 0)
        assert context.job.tokens_used == 500


def test_context_compaction_survives_resume_and_retains_full_verification_evidence(client, monkeypatch):
    cfg = ProviderConfig(kind="ollama", model="qwen2.5:3b", base_url="http://localhost:11434", context_limit=16384)
    monkeypatch.setattr(orchestrator, "load_routes", lambda: {"default": cfg})
    requests = []
    def handle(request):
        body = json.loads(request.content)
        requests.append(body)
        if len(requests) == 1:
            assert any('"compacted": true' in str(message.get("content", "")) for message in body["messages"])
            reply = {"content": "", "tool_calls": [{"function": {"name": "task__verify", "arguments": {
                "checks": [{"kind": "inventory.fresh"}]}}}]}
        else:
            reply = {"content": "Freshness independently verified after retained observation compaction"}
        return httpx.Response(200, json={"message": reply, "prompt_eval_count": 100, "eval_count": 20})
    monkeypatch.setattr(orchestrator, "ChatProvider", lambda config: ChatProvider(config, transport=httpx.MockTransport(handle)))
    with SessionLocal() as db:
        from serverhub.auth import Principal
        job = submit_job(db, Principal("owner", "owner", "owner"), "autonomous", {"prompt": "Inspect and verify inventory"}, host_id="node1", token_budget=20000)
        identity = job.id
        full = {"observation": "disk observation " * 4000}
        job.tokens_used = 200
        job.checkpoint = {"ai": {"specialist": "infrastructure", "step": 1,
            "messages": [{"role": "system", "content": orchestrator.BASE_INSTRUCTIONS},
                         {"role": "user", "content": "Inspect and verify inventory"},
                         {"role": "assistant", "tool_calls": [{"id": "large", "type": "function", "function": {
                             "name": "inventory__read", "arguments": "{}"}}]},
                         {"role": "tool", "name": "inventory__read", "tool_call_id": "large", "content": json.dumps(full)}],
            "completed_calls": {"large": full}, "evidence": [{"operation": "inventory.read", "result": full}]}}
        db.add(InventorySample(host_id="node1", metrics={}))
        db.commit()
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.state == "succeeded", job.error
        assert job.result["verified"] and job.tokens_used == 440
        assert job.checkpoint["ai"]["completed_calls"]["large"] == full
        assert job.checkpoint["ai"]["compactions"][0]["compacted_calls"] == ["large"]
    assert len(requests) == 2
