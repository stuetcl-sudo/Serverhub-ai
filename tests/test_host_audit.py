"""Deterministic audit evidence, persistent progress and no-write boundaries."""
import copy
import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from serverhub.database import SessionLocal, utcnow
from serverhub.host_audit import AuditArguments, ReportedBaseline, analyze_host
from serverhub.jobs import Worker, submit_job
from serverhub.models import Host, Job, Policy
from serverhub.node import broker, discovery
from serverhub.telemetry import ingest_inventory
from test_control_plane import control as control, oauth_flow, enroll_node  # noqa: F401
from test_core import core_env as core_env, owner as owner, client as client, bearer  # noqa: F401


def observations():
    return {"os": {"hostname": "disposable"}, "observed_at": "2026-10-22T00:00:00Z", "errors": [],
            "hardware": {"disks": [{"mountpoint": "/data", "fstype": "ntfs", "total": 1000, "used": 970, "free": 30, "percent": 97}]},
            "docker": {"available": True, "complete": True, "containers": [{"id": "app", "name": "homeassistant", "privileged": True,
                "image": "app:latest", "network_mode": "host", "mounts": [{"source": "/var/run/docker.sock", "rw": False}],
                "security_opt": ["apparmor=unconfined"], "networks": {"home": {}}, "dependencies": ["db"], "compose_project": "home"}]},
            "services": [{"name": "fancontrol.service", "active": "failed"}], "ports": [{"protocol": "tcp", "port": 11434, "scope": "all_interfaces", "address": "0.0.0.0"}],
            "firewall": {"available": False}, "updates": {"available": True, "upgradable_count": 3, "reboot_required": True}}


def test_capacity_first_and_every_plan_requires_separate_approval_without_actions():
    source = observations()
    original = copy.deepcopy(source)
    report = analyze_host(source, received_at=utcnow())
    assert report["findings"][0]["category"] == "disk_capacity"
    assert report["findings"][0]["severity"] == "critical"
    assert report["changes_executed"] == [] and report["mode"] == "read_only_dry_run"
    assert all(row["action_plan"]["approval_required"] and not row["action_plan"]["automatic_action"] for row in report["findings"])
    assert source == original
    assert "delete" in json.dumps(report["findings"][0]["action_plan"])
    assert report["exposure"]["wan_exposure"] == "unverified"
    assert report["zone_proposal"][0]["confidence"] == "inferred_from_name"
    assert report["zone_proposal"][0]["host_network_exception"]


def test_privilege_socket_apparmor_health_tags_and_failed_services_have_specific_evidence():
    source = observations()
    source["docker"]["containers"][0]["health"] = "unhealthy"
    report = analyze_host(source, received_at=utcnow())
    rows = {row["category"]: row for row in report["findings"]}
    assert {"docker_socket", "apparmor_unconfined", "privileged_container", "container_health", "failed_service", "update_plan", "mutable_image"} <= rows.keys()
    assert rows["docker_socket"]["evidence"]["mounts"][0]["rw"] is False
    assert "read-only socket" in json.dumps(rows["docker_socket"]["action_plan"])
    assert rows["update_plan"]["action_plan"]["approval_required"]


def test_reported_baseline_never_becomes_current_telemetry_and_unknown_stays_unknown():
    baseline = ReportedBaseline(observed_at="2020-01-01T00:00:00Z", disk_percent={"/data": 80, "/missing": 99}, container_count=99)
    report = analyze_host(observations(), received_at=utcnow(), baseline=baseline)
    comparison = report["baseline_comparison"]
    assert comparison["verified"] is False and comparison["status"] == "historical_caller_report"
    assert comparison["disk_percent"]["/data"]["change_percentage_points"] == 17
    assert comparison["disk_percent"]["/missing"]["current"] is None
    assert comparison["containers"]["reported"] == 99 and comparison["containers"]["current"] == 1
    source = observations()
    source["docker"]["complete"] = False
    assert analyze_host(source, received_at=utcnow(), baseline=baseline)["baseline_comparison"]["containers"]["current"] is None


@pytest.mark.parametrize("bad", [{"repair": True}, {"storage_target": "/etc"}, {"baseline": {"observed_at": "2999-01-01T00:00:00Z"}}, {"baseline": {"observed_at": "2020-01-01T00:00:00"}}, {"baseline": {"observed_at": "2020-01-01T00:00:00Z", "disk_percent": {"/": float("nan")}}}])
def test_audit_arguments_cannot_request_writes_arbitrary_paths_or_invalid_baselines(bad):
    with pytest.raises(ValueError):
        AuditArguments.model_validate(bad)


def test_growth_needs_observed_time_and_never_uses_reported_baseline_for_rate():
    now = utcnow()
    samples = [SimpleNamespace(created_at=now-timedelta(seconds=120), metrics={"disk_usage": {"/data": {"used": 850}}}),
               SimpleNamespace(created_at=now, metrics={"disk_usage": {"/data": {"used": 970}}})]
    report = analyze_host(observations(), received_at=now, samples=samples)
    trend = report["findings"][0]["evidence"]["trend"]
    assert trend["bytes_per_second"] == 1 and trend["estimated_seconds_to_full"] == 30
    assert analyze_host(observations(), received_at=now)["findings"][0]["evidence"]["trend"]["status"] == "insufficient_history"


def test_audit_never_turns_missing_collectors_into_clean_bill_of_health():
    report = analyze_host({"errors": [{"collector": "docker"}]}, received_at=utcnow())
    assert report["status"] == "partial_audit" and report["completed"] is False
    assert "docker_complete_inventory" in report["coverage_gaps"]
    assert "disk_capacity" in report["coverage_gaps"]
    assert report["changes_executed"] == []


def fake_node(monkeypatch):
    from serverhub.extensions import register
    register()
    calls = []
    def execute(ctx, operation, arguments, **kwargs):
        ctx.require(operation, arguments=arguments)
        calls.append(operation)
        if operation != "inventory.refresh":
            pytest.fail("A default audit must not issue mutations or unapproved storage scans")
        ingest_inventory(ctx.db, ctx.db.get(Host, ctx.job.host_id), observations())
        ctx.db.commit()
        return {"inventory": observations()}
    monkeypatch.setattr("serverhub.node_api.execute_node", execute)
    return calls


def test_durable_audit_job_collects_fresh_evidence_and_finishes_honestly_partial(core_env, owner, monkeypatch):
    calls = fake_node(monkeypatch)
    with SessionLocal() as db:
        job = submit_job(db, owner, "operation", {"operation": "host.audit", "arguments": {}}, host_id="node1", token_budget=0, cost_budget=0)
        identity = job.id
        db.commit()
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.state == "partial", job.error
        assert job.checkpoint["host_audit"]["sample_id"] == job.result["inventory_sample_id"]
        assert job.result["findings"][0]["category"] == "disk_capacity"
        assert job.tokens_used == 0 and job.cost_used == 0
    assert calls == ["inventory.refresh"]


def test_resume_uses_saved_fresh_collection_and_does_not_repeat_node_scan(core_env, owner, monkeypatch):
    calls = fake_node(monkeypatch)
    with SessionLocal() as db:
        job = submit_job(db, owner, "operation", {"operation": "host.audit", "arguments": {}}, host_id="node1")
        identity = job.id
        db.commit()
    import serverhub.host_audit as module
    actual = module.analyze_host
    monkeypatch.setattr(module, "analyze_host", lambda *a, **kw: (_ for _ in ()).throw(ConnectionError("simulated interruption after committed collection")))
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.state == "retry" and job.checkpoint["host_audit"]["inventory"]
        job.run_after = utcnow()-timedelta(seconds=1)
        db.commit()
    monkeypatch.setattr(module, "analyze_host", actual)
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        assert db.get(Job, identity).state == "partial"
    assert calls == ["inventory.refresh"]


def test_unauthorized_audit_and_unscoped_storage_are_rejected(client, monkeypatch):
    with SessionLocal() as db:
        headers = bearer(db, "adult")
    assert client.post("/api/jobs", headers=headers, json={"kind": "operation", "host_id": "node1", "spec": {"operation": "host.audit"}}).status_code == 403
    with SessionLocal() as db:
        db.add(Policy(name="audit only", subject_id="adult", host_id="node1", operations=["host.audit", "inventory.read", "inventory.refresh"], constraints={}, expires_at=utcnow()+timedelta(hours=1), created_by="owner"))
        db.commit()
    calls = fake_node(monkeypatch)
    response = client.post("/api/jobs", headers=headers, json={"kind": "operation", "host_id": "node1", "spec": {"operation": "host.audit", "arguments": {"storage_target": "data"}}})
    assert response.status_code == 202
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, response.json()["id"])
        assert job.state == "waiting_approval"
        assert job.result["denial"]["operation"] == "diagnostics.storage"
        assert job.result["denial"]["arguments"] == {"target": "data"}
    assert calls == ["inventory.refresh"]


def test_storage_broker_refuses_unapproved_targets_and_extra_arguments(monkeypatch):
    monkeypatch.setattr(broker, "command", lambda *a, **kw: pytest.fail("must reject before execution"))
    for args in ({"target": "unknown"}, {"target": "data", "path": "/etc"}, {"target": "/etc"}):
        with pytest.raises(broker.BrokerDenied):
            broker.execute("diagnostics.storage", args, {})


def test_storage_and_updates_collectors_use_only_fixed_read_commands(monkeypatch):
    seen = []
    def command(name, *args, **kwargs):
        seen.append((name, args))
        if name == "apt":
            return "Listing...\nexample/stable 2 amd64 [upgradable from: 1]\n"
        return json.dumps({"filesystems": []} if name == "findmnt" else {"loopdevices": [{"name": "/dev/loop0", "back-file": "/data/docker.ext4"}]})
    monkeypatch.setattr(discovery, "command", command)
    assert discovery.storage_inventory()["loops"][0]["name"] == "/dev/loop0"
    assert discovery.update_inventory()["upgradable_count"] == 1
    assert [name for name, _ in seen] == ["findmnt", "losetup", "apt"]
    assert seen[-1][1] == ("list", "--upgradable")


@pytest.mark.parametrize("scope", ["serverhub:read", "serverhub:read serverhub:jobs"])
def test_mcp_audit_is_async_persistent_and_checks_oauth_scope(control, scope):
    client, headers, _ = control
    node, _ = enroll_node(client, headers)
    token, _, _ = oauth_flow(client, headers, scope)
    response = client.post("/mcp", headers={"Authorization": "Bearer " + token["access_token"]}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "audit_host", "arguments": {"host_id": node["host_id"]}}})
    if "serverhub:jobs" not in scope:
        assert response.status_code == 403
        with SessionLocal() as db:
            assert db.scalar(select(Job)) is None
    else:
        result = response.json()["result"]
        assert result["isError"] is False
        job = json.loads(result["content"][0]["text"])
        assert job["state"] == "queued" and job["result"] == {}
        assert job["spec"]["operation"] == "host.audit"
        with SessionLocal() as db:
            assert db.get(Job, job["id"]).host_id == node["host_id"]


def test_loopback_ntfs_and_nvidia_failures_remain_readonly_and_not_assumed_docker():
    source = observations()
    source["storage"] = {"mounts": [{"target": "/data", "fstype": "ntfs"}], "loops": [{"name": "/dev/loop0", "back-file": "/data/docker.ext4"}]}
    source["hardware"]["gpus"] = {"nvidia": {"pci_devices": ["0000:00:01.0"], "status": "probe_failed"}}
    report = analyze_host(source, received_at=utcnow())
    rows = {row["category"]: row for row in report["findings"]}
    assert rows["loopback_storage_layer"]["evidence"]["docker_relationship"] == "unverified"
    assert "gpu_diagnostics" in rows
    assert report["changes_executed"] == []


def test_storage_du_measures_only_root_reviewed_disposable_directory():
    import os
    import tempfile
    from pathlib import Path
    if os.geteuid() != 0:
        pytest.skip("Root-owned broker target test requires disposable root test runner")
    with tempfile.TemporaryDirectory(prefix="serverhub-audit-qa-", dir="/opt") as temporary:
        directory = Path(temporary)
        (directory / "sample.bin").write_bytes(b"test" * 1024)
        result = broker.execute("diagnostics.storage", {"target": "data"}, {"storage_targets": {"data": temporary}})
        assert result["verified"] and result["entries"][0]["allocated_bytes"] >= 4096
        assert result["entries"][0]["path"] == temporary
        assert (directory / "sample.bin").stat().st_size == 4096


def test_docker_published_ports_do_not_claim_wan_and_missing_provenance_is_not_deleted():
    source = observations()
    item = source["docker"]["containers"][0]
    item["ports"] = {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
    item.pop("compose_project")
    report = analyze_host(source, received_at=utcnow())
    rows = {row["category"]: row for row in report["findings"]}
    assert rows["published_container_ports"]["evidence"]["wan_exposure"] == "unverified"
    assert rows["compose_unknown"]["action_plan"]["automatic_action"] is False
    assert report["changes_executed"] == []
