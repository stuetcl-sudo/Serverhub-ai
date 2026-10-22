from __future__ import annotations
import hashlib
import time
from pathlib import Path

import httpx
import pytest

from serverhub.node import agent, broker, discovery, security


def envelope(operation="systemd.restart", arguments=None, key="one", expires=None):
    return {"id": "command-1", "operation": operation, "arguments": arguments or {"service": "demo.service"},
            "idempotency_key": key, "expires_at": expires or time.time()+120}


@pytest.mark.parametrize("url", ["http://example.com", "https://u:p@example.com", "https://example.com?x=1", "https://example.com/#f", "ftp://example.com", "https://example.com/nested"])
def test_controller_url_rejects_unsafe_origins(url):
    with pytest.raises(agent.AgentError):
        agent.validate_controller_url(url)


def test_loopback_http_is_explicit():
    with pytest.raises(agent.AgentError):
        agent.validate_controller_url("http://127.0.0.1:9080")
    assert agent.validate_controller_url("http://127.0.0.1:9080", allow_loopback_http=True).endswith("9080")


def test_durable_journal_does_not_repeat_completed_changes(tmp_path):
    path = tmp_path / "commands.db"
    journal = agent.CommandJournal(path)
    assert journal.begin("one", "digest", retry_read=False) == ("running", None)
    journal.finish("one", "succeeded", {"verified": True})
    journal.close()
    reopened = agent.CommandJournal(path)
    assert reopened.begin("one", "digest", retry_read=False) == ("succeeded", {"verified": True})
    with pytest.raises(agent.AgentError, match="different operation"):
        reopened.begin("one", "other-digest", retry_read=False)
    reopened.close()


def test_interrupted_mutation_is_in_doubt_not_reexecuted(tmp_path):
    path = tmp_path / "commands.db"
    journal = agent.CommandJournal(path)
    journal.begin("one", "digest", retry_read=False)
    journal.close()
    reopened = agent.CommandJournal(path)
    state, result = reopened.begin("one", "digest", retry_read=False)
    assert state == "failed"
    assert result["failure_class"] == "in_doubt"
    assert result["retry_safe"] is False
    reopened.close()


def test_node_rejects_unsupported_and_expired_operations_before_broker(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "call_broker", lambda *args, **kwargs: pytest.fail("broker must not be called"))
    node = agent.NodeAgent({"controller_url": "https://controller.test", "state_dir": str(tmp_path)})
    assert node.execute(envelope("shell.exec"))["state"] == "failed"
    assert node.execute(envelope(expires=time.time()-1))["result"]["failure_class"] == "expired"
    node.close()


def test_node_enrollment_poll_report_and_command_result(tmp_path, monkeypatch):
    calls = []
    def transport(request):
        calls.append((request.method, request.url.path, dict(request.headers)))
        path = request.url.path
        if path == "/api/nodes/enroll":
            assert "authorization" not in request.headers
            return httpx.Response(201, json={"host_id": "node-1", "token": "individual-secret"})
        assert request.headers["authorization"] == "Bearer individual-secret"
        if path == "/api/nodes/commands":
            return httpx.Response(200, json=[envelope("inventory.refresh", arguments={}) | {"arguments": {}}])
        return httpx.Response(200, json={"accepted": True})
    node = agent.NodeAgent({"controller_url": "https://controller.test", "state_dir": str(tmp_path), "name": "node", "enrollment_token": "one-use"}, transport=httpx.MockTransport(transport))
    monkeypatch.setattr(node, "inventory", lambda: {"os": {"hostname": "disposable"}, "errors": []})
    node.run_once()
    node.close()
    assert len(calls) == 4
    assert calls[-1][1] == "/api/nodes/commands/command-1/result"
    assert (tmp_path / "identity.json").stat().st_mode & 0o777 == 0o600
    assert "individual-secret" in (tmp_path / "identity.json").read_text()


def test_tls_validation_cannot_be_disabled(tmp_path):
    with pytest.raises(agent.AgentError, match="TLS validation"):
        agent.NodeAgent({"controller_url": "https://controller.test", "state_dir": str(tmp_path), "ca_bundle": False})


def test_broker_rejects_arbitrary_exec_and_protected_units(monkeypatch):
    monkeypatch.setattr(broker, "command", lambda *args, **kwargs: pytest.fail("no command permitted"))
    with pytest.raises(broker.BrokerDenied):
        broker.execute("shell.exec", {"command": "id"}, {})
    with pytest.raises(broker.BrokerDenied, match="protected"):
        broker.execute("systemd.restart", {"service": "serverhub-api.service"}, {"allowed_services": ["serverhub-api.service"]})
    with pytest.raises(broker.BrokerDenied, match="unexpected"):
        broker.execute("systemd.restart", {"service": "demo.service", "command": "id"}, {"allowed_services": ["demo.service"]})


def test_broker_container_change_checks_immutable_image_first(monkeypatch):
    monkeypatch.setattr(broker, "_safe_container", lambda name: {"Image": "sha256:changed"})
    monkeypatch.setattr(broker, "command", lambda *args, **kwargs: pytest.fail("no docker mutation permitted"))
    with pytest.raises(broker.BrokerDenied, match="image differs"):
        broker.execute("docker.restart", {"container": "demo"}, {"allowed_containers": {"demo": {"image_id": "sha256:approved"}}})


def test_broker_manifest_digest_and_security_requirements(tmp_path, monkeypatch):
    monkeypatch.setattr(broker, "trusted_file", lambda path: Path(path))
    path = tmp_path / "compose.yaml"
    path.write_text("services:\n  demo:\n    image: demo:latest\n")
    config = {"path": str(tmp_path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    with pytest.raises(broker.BrokerDenied, match="digest"):
        broker._compose_file(config)
    config["sha256"] = "0" * 64
    with pytest.raises(broker.BrokerDenied, match="hash differs"):
        broker._compose_file(config)


def test_discovery_real_linux_reports_gaps_honestly():
    inventory = discovery.discover()
    assert inventory["os"]["kernel"]
    assert inventory["os"]["architecture"]
    assert inventory["hardware"]["memory"]["total"] > 0
    assert isinstance(inventory["packages"], list)
    assert inventory["observed_at"]
    assert isinstance(inventory["errors"], list)
    assert inventory["docker"]["available"] is False
    for port in inventory["ports"]:
        assert port["internet_exposure"] == "unverified"


def test_security_does_not_equate_bind_with_internet_exposure():
    result = security.analyze({"ports": [{"address": "0.0.0.0", "port": 6379, "scope": "all_interfaces", "process": "redis"}], "firewall": {"available": True}})
    assert result[0]["severity"] == "high"
    assert result[0]["internet_exposure"] == "unverified"
    assert "unverified" in result[0]["evidence"]["interpretation"]


def test_trivy_findings_include_package_evidence():
    result = security.vulnerability_findings({"Results": [{"Target": "image", "Vulnerabilities": [{"VulnerabilityID": "CVE-TEST", "PkgName": "demo", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"}]}]}, service="demo")
    assert result[0]["evidence"]["package"] == "demo"
    assert result[0]["evidence"]["scanner_reachability"] == "not_evaluated"


def test_independent_checkpoint_reverts_exact_bytes_and_commit_preserves_changes(monkeypatch):
    import os
    import tempfile
    from serverhub.node import watchdog
    if os.geteuid() != 0:
        pytest.skip("root-owned checkpoint file test requires isolated root environment")
    # The production trust check correctly rejects world-writable /tmp ancestors.
    with tempfile.TemporaryDirectory(prefix="serverhub-recovery-test-", dir="/root") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        target = root / "application.conf"
        target.write_bytes(b"original\n")
        target.chmod(0o640)
        recovery = root / "recovery"
        clock = [1000.0]
        monkeypatch.setattr(watchdog.time, "time", lambda: clock[0])
        armed = watchdog.arm(recovery, target, timeout=10)
        target.write_bytes(b"changed\n")
        assert watchdog.tick(recovery) == []
        clock[0] += 11
        assert watchdog.tick(recovery)[0]["state"] == "reverted"
        assert target.read_bytes() == b"original\n"
        assert target.stat().st_mode & 0o777 == 0o640
        armed = watchdog.arm(recovery, target, timeout=10)
        target.write_bytes(b"verified change\n")
        with pytest.raises(watchdog.RecoveryError, match="commit token"):
            watchdog.commit(recovery, armed["id"], "invalid")
        watchdog.commit(recovery, armed["id"], armed["commit_token"])
        clock[0] += 11
        assert watchdog.tick(recovery) == []
        assert target.read_bytes() == b"verified change\n"
