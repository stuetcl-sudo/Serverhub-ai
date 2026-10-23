"""Production readiness regressions, using isolated local state only."""
from copy import deepcopy
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from test_core import core_env as core_env
from serverhub.ai.orchestrator import compact_context
from serverhub.ai.providers import ProviderConfig, UsageBudget, estimate_prompt
from serverhub.settings import Settings, get_settings


def test_compaction_preserves_goal_call_linkage_and_external_evidence():
    cfg = ProviderConfig(kind="ollama", base_url="http://localhost:11434", model="qwen2.5:3b",
                         context_limit=4096, max_output_tokens=256)
    messages = [{"role": "system", "content": "Safety instructions"}, {"role": "user", "content": "Diagnose disk"},
        {"role": "assistant", "tool_calls": [{"id": "c1", "type": "function", "function": {
            "name": "inventory__read", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c1", "name": "inventory__read", "content": "observation " * 4000}]
    original = deepcopy(messages)
    compacted, report = compact_context(messages, [], cfg, 10000)
    assert report["input_after"] < report["input_before"]
    assert report["compacted_calls"] == ["c1"]
    assert messages == original  # Durable evidence must not be mutated in place.
    assert compacted[:3] == original[:3]
    assert compacted[3]["tool_call_id"] == "c1"
    assert "ai.completed_calls" in compacted[3]["content"]
    budget = UsageBudget(10000, 0, tokens_used=1000)
    budget.preflight(cfg, compacted, tools=[])
    assert budget.tokens_used == 1000
    again, report = compact_context(compacted, [], cfg, 10000)
    assert again == compacted and report is None


def test_compaction_never_truncates_instructions_or_operator_request():
    cfg = ProviderConfig(base_url="https://provider.example", model="model", context_limit=1024)
    messages = [{"role": "user", "content": "x" * 10000}]
    result, report = compact_context(messages, [], cfg, 100)
    assert result == messages and report is None
    assert estimate_prompt(result, [], kind=cfg.kind)["estimated_input_tokens"] > 1024


@pytest.mark.parametrize("origin", ["https://serverhub.example", "http://127.0.0.1:19080", "http://localhost:9080"])
def test_public_and_tunnel_assets_load_without_authentication(core_env, monkeypatch, origin):
    from serverhub.main import create_app
    web = core_env / "web"
    (web / "assets").mkdir(parents=True)
    (web / "index.html").write_text('<script src="/assets/app.js"></script>')
    (web / "assets/app.js").write_text("window.ready=true;")
    monkeypatch.setenv("SERVERHUB_PUBLIC_URL", "https://serverhub.example")
    # Legacy allowed_origins can still contain the old hostname after installation.
    monkeypatch.setenv("SERVERHUB_ALLOWED_ORIGINS", '["https://serverhub.local"]')
    monkeypatch.setenv("SERVERHUB_DEV_MODE", "false")
    monkeypatch.setenv("SERVERHUB_DATABASE_URL", "postgresql+psycopg://unused@/unused")
    get_settings.cache_clear()
    with TestClient(create_app(), base_url=origin) as browser:
        response = browser.get("/assets/app.js", headers={"Origin": origin})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/javascript")
        assert browser.get("/assets/missing.js").status_code == 404
        assert browser.get("/api").status_code == 404
        assert browser.get("/api/hosts").status_code == 401
        assert browser.get("/assets/app.js", headers={"Origin": "https://evil.example"}).status_code == 403
        assert browser.get("/hosts/node1").status_code == 200


@pytest.mark.parametrize("url", ["https://x.example/path", "https://user:secret@x.example", "https://x.example?key=value"])
def test_public_origin_rejects_path_and_credentials(url):
    with pytest.raises(ValueError, match="origin"):
        Settings(public_url=url)


def test_non_loopback_requires_tls_and_does_not_enable_proxy_header_trust(core_env, monkeypatch, tmp_path):
    from serverhub.cli import main
    monkeypatch.setenv("SERVERHUB_DEV_MODE", "false")
    monkeypatch.setenv("SERVERHUB_DATABASE_URL", "postgresql+psycopg://unused@/unused")
    monkeypatch.setenv("SERVERHUB_PUBLIC_URL", "https://serverhub.example")
    get_settings.cache_clear()
    with patch("uvicorn.run") as run:
        with pytest.raises(SystemExit):
            main(["serve", "--host", "192.168.122.10"])
        run.assert_not_called()
        cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
        cert.write_text("fixture")
        key.write_text("fixture")
        main(["serve", "--host", "192.168.122.10", "--tls-cert", str(cert), "--tls-key", str(key)])
        assert run.call_args.kwargs["proxy_headers"] is False
        assert run.call_args.kwargs["ssl_keyfile"] == str(key)
        with pytest.raises(SystemExit):
            main(["serve", "--tls-cert", str(cert)])


def test_dedicated_ai_identity_is_opt_in_and_keeps_broker_separate(tmp_path):
    from pathlib import Path
    from serverhub.ops.installer import Installer
    source = Path(__file__).resolve().parents[1]
    default = Installer(source, root=tmp_path / "default")
    default.stage()
    assert not (default.root / "etc/systemd/system/serverhub-worker.service.d").exists()
    dedicated = Installer(source, root=tmp_path / "dedicated", ai_identity=True)
    dedicated.stage()
    dropin = (dedicated.root / "etc/systemd/system/serverhub-worker.service.d/10-ai-identity.conf").read_text()
    assert "User=serverhub-ai" in dropin
    assert "Group=serverhub-worker" in dropin
    assert "User=root" in (dedicated.root / "etc/systemd/system/serverhub-broker.service").read_text()
    assert "allowed_services: []" in (dedicated.root / "etc/serverhub/broker.yaml").read_text()
    assert not (dedicated.root / "etc/sudoers.d").exists()


def test_failed_read_tools_become_observations_with_bounded_identical_retries(monkeypatch):
    from types import SimpleNamespace
    from serverhub.ai import orchestrator
    from serverhub.integrations.registry import IntegrationError
    executions = []
    def fail(*args):
        executions.append(1)
        raise IntegrationError("Read-only API unavailable", retryable=True)
    monkeypatch.setattr(orchestrator, "_run_tool", fail)
    ctx = SimpleNamespace(job=SimpleNamespace(checkpoint={}, spec={}),
                          save_checkpoint=lambda *a, **kw: None, log=lambda *a, **kw: None)
    state = {"specialist": "infrastructure", "messages": [], "completed_calls": {}, "evidence": []}
    for index in range(4):
        state["pending_calls"] = [{"id": str(index), "name": "inventory__read", "operation": "inventory.read", "arguments": {}}]
        orchestrator._pending_tools(ctx, state)
    assert len(executions) == 2
    assert state["completed_calls"]["3"]["requires_changed_strategy"] is True
    assert state["completed_calls"]["3"]["verified"] is False
    assert state["pending_calls"] == [] and "in_flight" not in state


def test_real_tls_listener_serves_assets_and_rejects_unauthenticated_api(tmp_path):
    import os
    import shutil
    import socket
    import ssl
    import subprocess
    import sys
    import time
    import httpx
    if not shutil.which("openssl"):
        pytest.skip("openssl unavailable for disposable TLS certificate")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    web = tmp_path / "web"
    (web / "assets").mkdir(parents=True)
    (web / "assets/app.js").write_text("window.ready=true;")
    (web / "index.html").write_text('<script src="/assets/app.js"></script>')
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    url = f"https://127.0.0.1:{port}"
    env = dict(os.environ, SERVERHUB_DEV_MODE="false", SERVERHUB_PUBLIC_URL=url,
               SERVERHUB_DATABASE_URL="postgresql+psycopg://unused@127.0.0.1:1/unused",
               SERVERHUB_FRONTEND_DIR=str(web))
    with (tmp_path / "api.log").open("w") as log:
        process = subprocess.Popen([sys.executable, "-m", "serverhub.cli", "serve", "--port", str(port),
            "--tls-cert", str(cert), "--tls-key", str(key)], env=env, stdout=log, stderr=log)
        try:
            with httpx.Client(verify=ssl.create_default_context(cafile=str(cert)), trust_env=False, timeout=1) as client:
                for _ in range(100):
                    try:
                        response = client.get(url + "/assets/app.js", headers={"Origin": url})
                        break
                    except httpx.TransportError:
                        if process.poll() is not None:
                            pytest.fail((tmp_path / "api.log").read_text())
                        time.sleep(.1)
                else:
                    pytest.fail("Disposable HTTPS listener did not start")
                assert response.status_code == 200
                assert response.text == "window.ready=true;"
                assert client.get(url + "/api/hosts").status_code == 401
                assert client.get(url + "/assets/app.js", headers={"Origin": "https://evil.example"}).status_code == 403
        finally:
            process.terminate()
            process.wait(timeout=10)


def test_broker_chain_detects_tampering_and_marks_legacy_prefix(tmp_path):
    import hashlib
    import json
    from serverhub.node.broker import verify_broker_audit
    path = tmp_path / "events.jsonl"
    legacy = b'{"phase":"before"}'
    previous = hashlib.sha256(legacy).hexdigest()
    body = {"format": 2, "previous_hash": previous, "record": {"phase": "after", "effective_uid": 0}}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    path.write_bytes(legacy + b"\n" + json.dumps({**body, "hash": digest}).encode() + b"\n")
    assert verify_broker_audit(path) == {"valid": True, "checked": 2, "legacy_unlinked": 1, "head": digest}
    path.write_text(path.read_text().replace('"effective_uid": 0', '"effective_uid": 1'))
    assert not verify_broker_audit(path)["valid"]


def test_root_broker_append_protects_and_hashes_real_file():
    import os
    import tempfile
    from pathlib import Path
    from serverhub.node.broker import append_broker_audit, verify_broker_audit, BrokerDenied
    if os.geteuid() != 0:
        pytest.skip("Root-only disposable protected audit fixture")
    with tempfile.TemporaryDirectory(prefix="serverhub-audit-test-", dir="/opt") as directory:
        path = Path(directory) / "events.jsonl"
        config = {"audit_log": str(path)}
        append_broker_audit(config, {"phase": "before", "password": "PRIVATE_SENTINEL", "privilege": {"effective_uid": 0}})
        append_broker_audit(config, {"phase": "after", "ok": True})
        assert verify_broker_audit(path)["valid"]
        assert verify_broker_audit(path)["checked"] == 2
        assert "PRIVATE_SENTINEL" not in path.read_text()
        path.chmod(0o666)
        with pytest.raises(BrokerDenied, match="protected"):
            append_broker_audit(config, {"phase": "before"})


@pytest.mark.parametrize("url,expected", [("https://SERVERHUB.example:443/", "https://serverhub.example"),
                                        ("https://[::1]:9080/", "https://[::1]:9080")])
def test_public_origin_uses_browser_canonical_host_and_port(url, expected):
    assert Settings(public_url=url).public_url == expected


def test_critical_service_diagnostics_require_exact_allowlist_but_restarts_stay_protected(monkeypatch):
    from serverhub.node import broker
    calls = []
    def status(service):
        calls.append(service)
        return {"service": service, "active": "active"}
    monkeypatch.setattr(broker, "_systemd_status", status)
    with pytest.raises(broker.BrokerDenied, match="allowlisted"):
        broker.execute("systemd.status", {"service": "serverhub-api.service"}, {})
    config = {"allowed_services": ["serverhub-api.service"]}
    assert broker.execute("systemd.status", {"service": "serverhub-api.service"}, config)["verified"]
    with pytest.raises(broker.BrokerDenied, match="protected"):
        broker.execute("systemd.restart", {"service": "serverhub-api.service"}, config)
    assert calls == ["serverhub-api.service"]
