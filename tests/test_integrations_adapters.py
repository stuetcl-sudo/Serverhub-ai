import json

import httpx
import pytest

from serverhub.integrations.registry import IntegrationConfig, IntegrationError, execute


def test_home_assistant_write_is_checkpointed_verified_and_reversible():
    calls, snapshots, state = [], [], {"power": "off"}
    def handler(request):
        calls.append(request.url.path)
        if request.method == "GET":
            return httpx.Response(200, json={"entity_id": "light.kitchen", "state": state["power"]})
        assert snapshots, "write occurred without prechange checkpoint"
        state["power"] = "on" if request.url.path.endswith("turn_on") else "off"
        return httpx.Response(200, json=[])
    cfg = {"ha": IntegrationConfig(kind="home_assistant", base_url="https://ha.example", allowed_entities=["light.kitchen"], allowed_operations=["home_assistant.set_power"])}
    result = execute("home_assistant.set_power", {"integration_id": "ha", "entity_id": "light.kitchen", "power": True}, config=cfg,
                     transport=httpx.MockTransport(handler), checkpoint=snapshots.append)
    assert result["verified"] and not result["physical_state_verified"]
    assert snapshots[0]["previous_state"] == "off" and len(calls) == 3
    with pytest.raises(IntegrationError, match="allowlist"):
        execute("home_assistant.set_power", {"integration_id": "ha", "entity_id": "light.other", "power": True}, config=cfg, checkpoint=snapshots.append)


def test_adguard_canary_failure_restores_exact_rules():
    rules = ["||old.example^"]
    snapshots = []
    def handler(request):
        nonlocal rules
        path = request.url.path
        if path.endswith("check_host"):
            name = request.url.params["name"]
            blocked = name == "ads.example"
            if rules == ["||new.example^"] and name == "allowed.example":
                blocked = True
            return httpx.Response(200, json={"reason": "FilteredBlackList" if blocked else "NotFilteredNotFound"})
        if path.endswith("set_rules"):
            assert snapshots
            rules = json.loads(request.content)["rules"]
            return httpx.Response(200)
        return httpx.Response(200, json={"user_rules": rules})
    cfg = {"dns": IntegrationConfig(kind="adguard", base_url="https://dns.example", allowed_operations=["adguard.set_rules"],
                                    validation_domains={"ads.example": "blocked", "allowed.example": "allowed"})}
    with pytest.raises(IntegrationError, match="rollback attempted") as error:
        execute("adguard.set_rules", {"integration_id": "dns", "rules": ["||new.example^"]}, config=cfg,
                transport=httpx.MockTransport(handler), checkpoint=snapshots.append)
    assert rules == ["||old.example^"] and error.value.rollback == {"verified": True}


def test_writes_require_operator_allowlist_and_durable_checkpoint():
    cfg = {"dns": IntegrationConfig(kind="adguard", base_url="https://dns.example", allowed_operations=["adguard.set_rules"])}
    with pytest.raises(IntegrationError, match="checkpoint"):
        execute("adguard.set_rules", {"integration_id": "dns", "rules": []}, config=cfg)
    with pytest.raises(IntegrationError, match="arguments"):
        execute("adguard.set_rules", {"integration_id": "dns", "rules": ["1.2.3.4 rewrite.example"]}, config=cfg, checkpoint=lambda _: None)
    with pytest.raises(IntegrationError, match="registered"):
        execute("http.exec", {"url": "https://anywhere"}, config=cfg)


def test_unifi_scopes_fixed_paths_and_no_credentials_leak(monkeypatch):
    monkeypatch.setenv("UNIFI_TOKEN", "test-key")
    def handler(request):
        assert request.headers["X-API-Key"] == "test-key"
        assert request.url.path == "/proxy/network/integration/v1/sites/siteA/devices"
        return httpx.Response(200, json={"data": [{"id": "ap1"}], "password": "never expose"})
    cfg = {"net": IntegrationConfig(kind="unifi", base_url="https://unifi.example/proxy/network/integration/v1",
                                    token_env="UNIFI_TOKEN", allowed_sites=["siteA"], allowed_operations=["unifi.devices"])}
    result = execute("unifi.devices", {"integration_id": "net", "site_id": "siteA"}, config=cfg, transport=httpx.MockTransport(handler))
    assert result["inventory"]["password"] == "[redacted]"
    with pytest.raises(IntegrationError, match="allowlist"):
        execute("unifi.devices", {"integration_id": "net", "site_id": "siteB"}, config=cfg)


def test_legacy_mcp_metadata_negotiates_and_notifies():
    methods = []
    def handler(request):
        assert request.url.path == "/mcp"
        payload = json.loads(request.content)
        methods.append(payload["method"])
        if payload["method"] == "initialize":
            return httpx.Response(200, headers={"Mcp-Session-Id": "session-1"}, json={"result": {"protocolVersion": "2025-11-25"}})
        assert request.headers["Mcp-Session-Id"] == "session-1"
        assert request.headers["MCP-Protocol-Version"] == "2025-11-25"
        if payload["method"] == "notifications/initialized":
            return httpx.Response(202)
        return httpx.Response(200, json={"result": {"tools": []}})
    cfg = {"old": IntegrationConfig(kind="serverhub_mcp", base_url="https://serverhub.example/mcp", allowed_operations=["serverhub_mcp.tools"])}
    assert execute("serverhub_mcp.tools", {"integration_id": "old"}, config=cfg, transport=httpx.MockTransport(handler))["result"]["tools"] == []
    assert methods == ["initialize", "notifications/initialized", "tools/list"]
