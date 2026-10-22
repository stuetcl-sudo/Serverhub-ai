"""Read-only discovery, lifecycle diffs and negative visibility regression tests."""
import copy
import json

import pytest
from sqlalchemy import select

from serverhub.database import SessionLocal
from serverhub.inventory_history import resource_state, structural_diff
from serverhub.models import GraphEdge, Host, InventorySample
from serverhub.node import agent, broker, discovery
from serverhub.telemetry import ingest_inventory
from test_core import core_env as core_env, client as client, bearer  # noqa: F401


def container(identifier="one", project="home"):
    return {"Id": identifier, "Name": "/app", "Image": "sha256:fixed", "Config": {"Image": "app:v1", "Env": ["SECRET=hidden"],
            "Labels": {"password": "hidden", "com.docker.compose.project": project, "com.docker.compose.service": "web",
                       "com.docker.compose.depends_on": "db:service_healthy:true,cache:service_started:false"}},
            "State": {"Status": "running", "Running": True, "Health": {"Status": "healthy", "Log": ["hidden"]}},
            "HostConfig": {}, "Mounts": [{"Type": "volume", "Name": "data", "Source": "/data", "Destination": "/app/data", "RW": True}],
            "NetworkSettings": {"Networks": {"home": {"IPAddress": "172.18.0.2"}}, "Ports": {}}}


def fake_docker(monkeypatch, *, race=False):
    calls = []
    def command(name, *args, **kwargs):
        calls.append((name, args))
        assert name == "docker"
        if args[:3] == ("container", "ls", "--all"):
            return "one two" if race else "one"
        if args[:2] == ("container", "inspect"):
            if race and (len(args) > 3 or args[-1] == "two"):
                raise discovery.CollectionError("removed")
            return json.dumps([container()])
        return {"image": '{"ID":"sha256:fixed","Repository":"app","Tag":"v1"}',
                "volume": '{"Name":"data","Driver":"local"}',
                "network": '{"ID":"net1","Name":"home","Driver":"bridge"}'}[args[0]]
    monkeypatch.setattr(discovery, "command", command)
    return calls


def test_docker_complete_inventory_allowlists_labels_and_dependency_names(monkeypatch):
    calls = fake_docker(monkeypatch)
    observed = discovery.docker_inventory()
    assert observed["complete"] and observed["available"]
    assert observed["containers"][0]["dependencies"] == ["cache", "db"]
    assert observed["containers"][0]["mounts"][0]["name"] == "data"
    assert observed["compose_projects"][0]["relationship"] == "verified_label"
    assert "hidden" not in json.dumps(observed)
    assert {args[0] for _, args in calls} == {"container", "image", "volume", "network"}


def test_container_removed_during_inspect_does_not_discard_other_containers(monkeypatch):
    fake_docker(monkeypatch, race=True)
    observed = discovery.docker_inventory()
    assert observed["containers"][0]["id"] == "one"
    assert not observed["complete"] and observed["gaps"][0]["id"] == "two"
    assert "containers" not in resource_state({"docker": observed})


def test_docker_collection_has_container_cap(monkeypatch):
    fake_docker(monkeypatch, race=True)
    monkeypatch.setattr(discovery, "MAX_CONTAINERS", 1)
    observed = discovery.docker_inventory()
    assert observed["truncated"] and not observed["complete"]
    assert len(observed["containers"]) == 1


def inventory(containers):
    return {"observed_at": "2026-10-22T18:00:00Z", "errors": [], "services": [], "ports": [],
            "docker": {"available": True, "complete": True, "containers": containers, "networks": [], "images": [], "volumes": []}}


def test_authenticated_inventory_tracks_add_change_remove_and_no_stale_graph(client):
    with SessionLocal() as db:
        headers = bearer(db)
        host = db.get(Host, "node1")
        observed = inventory([{"id": "one", "name": "web", "health": "healthy", "compose_project": "home", "dependencies": ["db"]}])
        ingest_inventory(db, host, observed)
        db.commit()
        observed["docker"]["containers"][0]["health"] = "unhealthy"
        ingest_inventory(db, host, observed)
        db.commit()
        ingest_inventory(db, host, inventory([]))
        db.commit()
        assert not any("container:one" in edge.source or "container:one" in edge.target for edge in db.scalars(select(GraphEdge)))
    response = client.get("/api/hosts/node1/inventory/history", headers=headers)
    assert response.status_code == 200
    history = response.json()
    assert history[0]["diff"]["sections"]["containers"]["removed"] == ["one"]
    assert history[1]["diff"]["sections"]["containers"]["changed"] == ["one"]
    assert history[2]["diff"]["sections"]["containers"]["added"] == ["one"]
    assert client.get("/api/hosts/node1/inventory", headers=headers).json()["docker"]["containers"] == []
    with SessionLocal() as db:
        unauthorized = bearer(db, "adult")
    assert client.get("/api/hosts/node1/inventory/history", headers=unauthorized).status_code == 403


def test_collection_gap_does_not_claim_removal_or_recovery():
    previous = resource_state(inventory([{"id": "one"}]))
    gap = inventory([])
    gap["docker"]["available"] = False
    diff = structural_diff(previous, resource_state(gap))
    assert diff["sections"]["containers"]["status"] == "unavailable"
    assert "removed" not in diff["sections"]["containers"]
    recovered = structural_diff(resource_state(gap), previous)
    assert recovered["sections"]["containers"]["status"] == "first_observation"


def test_dependency_edges_are_project_scoped_and_declarations_not_runtime_health(core_env):
    with SessionLocal() as db:
        rows = [{"id": name, "compose_project": name, "compose_service": "web", "dependencies": ["db"]} for name in ["home", "staging"]]
        ingest_inventory(db, db.get(Host, "node1"), inventory(rows))
        db.commit()
        dependencies = db.scalars(select(GraphEdge).where(GraphEdge.relation == "declares_dependency")).all()
        assert {edge.target for edge in dependencies} == {"host:node1:compose:home:service:db", "host:node1:compose:staging:service:db"}
        assert all(edge.verified and edge.evidence["runtime_health"] == "unverified" for edge in dependencies)


def test_retention_is_host_scoped(core_env, monkeypatch):
    import serverhub.inventory_history as history
    monkeypatch.setattr(history, "HISTORY_LIMIT", 2)
    with SessionLocal() as db:
        db.add(InventorySample(host_id="node2", metrics={"preserve": True}))
        for _ in range(4):
            ingest_inventory(db, db.get(Host, "node1"), inventory([]))
            db.commit()
        assert len(db.scalars(select(InventorySample).where(InventorySample.host_id == "node1")).all()) == 2
        assert db.scalar(select(InventorySample).where(InventorySample.host_id == "node2")).metrics == {"preserve": True}


def test_caddy_extracts_only_configured_listeners_and_hosts():
    document = {"apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [
        {"match": [{"host": ["home.example"]}], "handle": [{"handler": "reverse_proxy", "headers": {"Authorization": "hidden"}, "upstreams": [{"dial": "private:8123"}]}]}]}}}}}
    endpoints = discovery.caddy_endpoints(document)
    assert endpoints[0]["hosts"] == ["home.example"] and endpoints[0]["reachability"] == "unverified"
    assert "hidden" not in json.dumps(endpoints) and "private:8123" not in json.dumps(endpoints)


def test_broker_event_probe_has_no_arguments_or_executable_escape(monkeypatch):
    monkeypatch.setattr(broker, "docker_events", lambda: {"changed": True})
    assert broker.execute("inventory.events", {}, {}) == {"changed": True}
    with pytest.raises(broker.BrokerDenied):
        broker.execute("inventory.events", {"since": "arbitrary"}, {})
    assert "inventory.events" not in agent.ALLOWED_OPERATIONS  # not a controller command/tool


def test_event_probe_debounces_full_discovery_and_periodic_recovers(tmp_path, monkeypatch):
    node = agent.NodeAgent({"controller_url": "https://controller.test", "state_dir": str(tmp_path), "broker_socket": "/test.sock", "interval": 120})
    reports, probes = [], []
    clock = [100.0]
    monkeypatch.setattr(agent.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(node, "enroll", lambda: None)
    monkeypatch.setattr(node, "inventory", lambda: inventory([]))
    def request(method, path, payload=None):
        if path == "/api/nodes/report":
            reports.append(copy.deepcopy(payload))
        return [] if path == "/api/nodes/commands" else {}
    monkeypatch.setattr(node, "_request", request)
    def probe(*args):
        probes.append(args)
        return {"changed": True}
    monkeypatch.setattr(agent, "call_broker", probe)
    node.run_once()
    clock[0] = 115
    node.run_once()
    assert len(reports) == 1  # cannot refresh every event
    clock[0] = 130
    node.run_once()
    assert len(reports) == 2 and len(probes) == 2
    monkeypatch.setattr(agent, "call_broker", lambda *a: {"changed": False})
    clock[0] = 250
    node.run_once()
    assert len(reports) == 3
    node.close()


def test_inspection_deadline_keeps_observation_explicitly_incomplete(monkeypatch):
    fake_docker(monkeypatch)
    clock = iter([0, 31])
    monkeypatch.setattr(discovery.time, "monotonic", lambda: next(clock))
    observed = discovery.docker_inventory()
    assert not observed["complete"] and observed["containers"] == []
    assert observed["gaps"][0]["reason"] == "inspect time budget exhausted"


def test_chart_metrics_excludes_structural_payload_but_keeps_measured_metrics(client):
    with SessionLocal() as db:
        headers = bearer(db)
        observed = inventory([{"id": "one"}])
        observed["hardware"] = {"memory": {"percent": 42}}
        ingest_inventory(db, db.get(Host, "node1"), observed)
        db.commit()
    metrics = client.get("/api/hosts/node1/metrics", headers=headers).json()[0]["metrics"]
    assert metrics["memory_percent"] == 42
    assert "inventory_state" not in metrics and "inventory_diff" not in metrics
