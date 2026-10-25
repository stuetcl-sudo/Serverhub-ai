"""Cross-component authorization, node delivery, telemetry and OAuth tests."""

import base64
import hashlib
import re
import secrets
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from serverhub.auth import create_session, hash_password, hash_secret
from serverhub.database import SessionLocal, engine_for, get_engine, utcnow
from serverhub.models import (
    AgentCommand,
    Base,
    Finding,
    GraphEdge,
    Host,
    Incident,
    InventorySample,
    Job,
    Policy,
    User,
)
from serverhub.node_api import dispatch_command
from serverhub.policy import PermissionDenied
from serverhub.settings import get_settings
from serverhub.telemetry import ingest_inventory


@pytest.fixture
def control(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVERHUB_DEV_MODE", "true")
    monkeypatch.setenv("SERVERHUB_DATABASE_URL", "sqlite:///" + str(tmp_path / "control.db"))
    monkeypatch.setenv("SERVERHUB_PUBLIC_URL", "http://testserver")
    monkeypatch.setenv("SERVERHUB_ALLOWED_ORIGINS", '["http://testserver"]')
    get_settings.cache_clear()
    from serverhub.main import create_app
    from serverhub.oauth_models import OAuthClient  # noqa: F401 register metadata

    Base.metadata.create_all(get_engine())
    with SessionLocal() as db:
        owner = User(username="owner", role="owner", password_hash=hash_password("strong-test-password-42"))
        db.add(owner)
        db.flush()
        token = create_session(db, owner)
        owner_id = owner.id
        db.commit()
    with TestClient(create_app()) as client:
        headers = {"Authorization": "Bearer " + token, "Origin": "http://testserver"}
        yield client, headers, owner_id
    get_engine().dispose()
    engine_for.cache_clear()
    get_settings.cache_clear()


def enroll_node(client, headers, name="node-one"):
    response = client.post("/api/nodes/enrollment", headers=headers, json={"name": name})
    assert response.status_code == 201, response.text
    enrollment = response.json()
    response = client.post(
        "/api/nodes/enroll", json={"token": enrollment["token"], "name": name, "identity": "identity-" + name}
    )
    assert response.status_code == 201, response.text
    return response.json(), enrollment


def test_node_enrollment_is_one_use_and_revocation_takes_effect(control):
    client, headers, _ = control
    node, enrollment = enroll_node(client, headers)
    assert (
        client.post(
            "/api/nodes/enroll", json={"token": enrollment["token"], "name": "node-one", "identity": "x"}
        ).status_code
        == 401
    )
    node_headers = {"Authorization": "Bearer " + node["token"]}
    assert client.post("/api/nodes/heartbeat", headers=node_headers).status_code == 200
    assert client.post("/api/hosts/" + node["host_id"] + "/revoke", headers=headers).status_code == 200
    assert client.get("/api/nodes/commands", headers=node_headers).status_code == 401
    assert client.get("/api/auth/me", headers=node_headers).status_code == 401


def test_node_delivery_reauthorizes_policy_and_isolates_results(control):
    client, headers, owner_id = control
    node, _ = enroll_node(client, headers)
    second, _ = enroll_node(client, headers, "node-two")
    with SessionLocal() as db:
        grant = Policy(
            name="one restart",
            subject_id=owner_id,
            host_id=node["host_id"],
            operations=["systemd.restart"],
            constraints={"service_names": ["example.service"]},
            expires_at=utcnow() + timedelta(minutes=10),
            created_by=owner_id,
        )
        job = Job(owner_id=owner_id, host_id=node["host_id"], kind="operation", state="running", spec={})
        db.add_all([grant, job])
        db.commit()
        cmd = dispatch_command(db, node["host_id"], "systemd.restart", {"service": "example.service"}, job.id)
        command_id = cmd.id
        grant.enabled = False
        db.commit()
    result = client.get("/api/nodes/commands", headers={"Authorization": "Bearer " + node["token"]})
    assert result.status_code == 200 and result.json() == []
    with SessionLocal() as db:
        assert db.get(AgentCommand, command_id).state == "failed"
    assert (
        client.post(
            "/api/nodes/commands/" + command_id + "/result",
            headers={"Authorization": "Bearer " + second["token"]},
            json={"state": "succeeded", "result": {}},
        ).status_code
        == 404
    )


def test_node_read_command_lifecycle_and_duplicate_report(control):
    client, headers, owner_id = control
    node, _ = enroll_node(client, headers)
    with SessionLocal() as db:
        job = Job(owner_id=owner_id, host_id=node["host_id"], kind="operation", state="running", spec={})
        db.add(job)
        db.commit()
        command = dispatch_command(
            db, node["host_id"], "systemd.status", {"service": "example.service"}, job.id
        )
        command_id = command.id
        assert (
            dispatch_command(db, node["host_id"], "systemd.status", {"service": "example.service"}, job.id).id
            == command_id
        )
        with pytest.raises(PermissionDenied):
            dispatch_command(db, node["host_id"], "shell.exec", {"command": "id"}, job.id)
    node_headers = {"Authorization": "Bearer " + node["token"]}
    commands = client.get("/api/nodes/commands", headers=node_headers).json()
    assert commands[0]["id"] == command_id and commands[0]["expires_at"].endswith("Z")
    result = client.post(
        "/api/nodes/commands/" + command_id + "/result",
        headers=node_headers,
        json={"state": "succeeded", "result": {"active": "active"}},
    )
    assert result.status_code == 200
    duplicate = client.post(
        "/api/nodes/commands/" + command_id + "/result",
        headers=node_headers,
        json={"state": "failed", "result": {"error": "overwrite"}},
    )
    assert duplicate.json()["duplicate"]
    with SessionLocal() as db:
        assert db.get(AgentCommand, command_id).state == "succeeded"


def sample_inventory():
    return {
        "os": {"hostname": "real-observation"},
        "hardware": {
            "cpu_count": 2,
            "load_average": [0.5],
            "memory": {"percent": 94},
            "disks": [{"percent": 92}],
        },
        "interfaces": [{"name": "eth0", "addresses": [{"family": "AF_INET", "address": "192.0.2.12"}]}],
        "ports": [
            {
                "port": 6379,
                "address": "0.0.0.0",
                "scope": "all_interfaces",
                "protocol": "tcp",
                "process": "redis",
            }
        ],
        "services": [{"name": "example.service", "active": "failed"}],
        "docker": {"containers": []},
        "firewall": {"available": False},
        "packages": [{"name": "package" + str(index)} for index in range(1200)],
        "environment": {"secret": "do-not-expose"},
        "errors": [],
    }


def test_inventory_ingestion_preserves_evidence_and_does_not_invent_exposure(control):
    client, headers, _ = control
    node, _ = enroll_node(client, headers)
    response = client.post(
        "/api/nodes/report",
        headers={"Authorization": "Bearer " + node["token"]},
        json={"inventory": sample_inventory()},
    )
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        host = db.get(Host, node["host_id"])
        assert len(host.inventory["packages"]) == 1200
        assert host.inventory["environment"] == "[REDACTED]"
        assert db.scalar(select(InventorySample)).metrics["load_per_core"] == 0.25
        assert db.scalar(select(GraphEdge)).verified
        assert len(db.scalars(select(Incident)).all()) == 3
        finding = next(x for x in db.scalars(select(Finding)) if x.service == "redis")
        assert isinstance(finding.confidence, float)
        assert "unverified" in finding.evidence["interpretation"]
        ingest_inventory(db, host, sample_inventory())
        db.commit()
        assert len(db.scalars(select(Incident)).all()) == 3


def begin_oauth(client, headers, scopes="serverhub:read serverhub:jobs", state="test-state"):
    # Browser signs in using its normal account; its cookie is never used as an MCP token.
    response = client.post(
        "/api/auth/login",
        json={"username": "owner", "password": "strong-test-password-42"},
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 200
    registered = client.post(
        "/api/mcp/clients",
        headers=headers,
        json={"name": "test connector", "redirect_uris": ["https://client.example/callback"]},
    ).json()
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    parameters = {
        "client_id": registered["client_id"],
        "redirect_uri": "https://client.example/callback",
        "response_type": "code",
        "scope": scopes,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "resource": "http://testserver/mcp",
    }
    response = client.get("/oauth/authorize", params=parameters)
    assert response.status_code == 200, response.text
    nonce = re.search(r'name="consent_nonce" value="([^"]+)"', response.text).group(1)
    return nonce, response, parameters, verifier, registered


def oauth_flow(client, headers, scopes="serverhub:read serverhub:jobs"):
    nonce, _, parameters, verifier, registered = begin_oauth(client, headers, scopes)
    response = client.post(
        "/oauth/authorize",
        data={"consent_nonce": nonce, "decision": "approve"},
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
    form = {
        "grant_type": "authorization_code",
        "client_id": registered["client_id"],
        "redirect_uri": parameters["redirect_uri"],
        "code": code,
        "code_verifier": verifier,
        "resource": parameters["resource"],
    }
    token = client.post("/oauth/token", data=form, headers={"Origin": "http://testserver"})
    assert token.status_code == 200, token.text
    return token.json(), form, registered


def post_consent(client, nonce, decision="approve"):
    return client.post(
        "/oauth/authorize", data={"consent_nonce": nonce, "decision": decision},
        headers={"Origin": "http://testserver"}, follow_redirects=False,
    )


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_consent_valid_cookie_attributes_and_single_use(control, decision):
    from serverhub.mcp import _consent_cookie
    from serverhub.oauth_models import OAuthCode, OAuthPending

    client, headers, _ = control
    nonce, page, _, _, _ = begin_oauth(client, headers)
    cookie = page.headers["set-cookie"]
    assert cookie.startswith(_consent_cookie(nonce) + "=" + nonce)
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert "Max-Age=300" in cookie and "Path=/oauth/authorize" in cookie
    assert "Domain=" not in cookie
    assert page.headers["cache-control"] == "no-store"
    response = post_consent(client, nonce, decision)
    assert response.status_code == 303, response.text
    values = parse_qs(urlsplit(response.headers["location"]).query)
    assert values["state"] == ["test-state"]
    assert ("code" in values) == (decision == "approve")
    if decision == "deny":
        assert values["error"] == ["access_denied"]
    assert _consent_cookie(nonce) not in client.cookies
    with SessionLocal() as db:
        assert db.get(OAuthPending, hash_secret(nonce)) is None
        assert len(db.scalars(select(OAuthCode)).all()) == (decision == "approve")
    # Even replaying the original browser cookie cannot consume a request twice.
    client.cookies.set(_consent_cookie(nonce), nonce, path="/oauth/authorize")
    assert post_consent(client, nonce, decision).status_code == 400


@pytest.mark.parametrize("cookie_value", [None, "wrong", "legacy"])
def test_consent_rejects_missing_wrong_and_legacy_cookie(control, cookie_value):
    from serverhub.mcp import _consent_cookie
    from serverhub.oauth_models import OAuthCode, OAuthPending

    client, headers, _ = control
    nonce, _, _, _, _ = begin_oauth(client, headers)
    client.cookies.clear()
    if cookie_value is not None:
        name = "serverhub_oauth_consent" if cookie_value == "legacy" else _consent_cookie(nonce)
        client.cookies.set(name, nonce if cookie_value == "legacy" else cookie_value, path="/oauth/authorize")
    # Authenticate independently so this tests CSRF rather than missing login.
    response = client.post(
        "/oauth/authorize", data={"consent_nonce": nonce, "decision": "approve"}, headers=headers,
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Consent CSRF check failed"
    with SessionLocal() as db:
        assert db.get(OAuthPending, hash_secret(nonce)) is not None
        assert db.scalars(select(OAuthCode)).all() == []


def test_consent_expired_nonce_and_wrong_user(control):
    from serverhub.oauth_models import OAuthPending

    client, headers, _ = control
    nonce, _, _, _, _ = begin_oauth(client, headers)
    with SessionLocal() as db:
        pending = db.get(OAuthPending, hash_secret(nonce))
        pending.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert post_consent(client, nonce).status_code == 400
    nonce, _, _, _, _ = begin_oauth(client, headers)
    with SessionLocal() as db:
        other = User(username="other", role="owner", password_hash=hash_password("other-test-password-42"))
        db.add(other)
        db.flush()
        db.get(OAuthPending, hash_secret(nonce)).user_id = other.id
        db.commit()
    assert post_consent(client, nonce).status_code == 400


@pytest.mark.parametrize("reverse", [False, True])
def test_consent_parallel_tabs_do_not_overwrite_or_delete_other_flows(control, reverse):
    from serverhub.mcp import _consent_cookie

    client, headers, _ = control
    first, _, _, _, _ = begin_oauth(client, headers, state="first")
    second, _, _, _, _ = begin_oauth(client, headers, state="second")
    assert client.cookies[_consent_cookie(first)] == first
    assert client.cookies[_consent_cookie(second)] == second
    flows = [(first, "first"), (second, "second")]
    if reverse:
        flows.reverse()
    for nonce, state in flows:
        response = post_consent(client, nonce)
        assert response.status_code == 303, response.text
        assert parse_qs(urlsplit(response.headers["location"]).query)["state"] == [state]


def test_consent_code_remains_pkce_and_resource_bound(control):
    client, headers, _ = control
    nonce, _, parameters, verifier, registered = begin_oauth(client, headers)
    response = post_consent(client, nonce)
    code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
    form = {
        "grant_type": "authorization_code", "client_id": registered["client_id"],
        "redirect_uri": parameters["redirect_uri"], "code": code,
        "code_verifier": verifier, "resource": parameters["resource"],
    }
    for override in ({"code_verifier": "a" * 64}, {"resource": "https://other.example/mcp"},
                     {"redirect_uri": "https://other.example/callback"}):
        assert client.post("/oauth/token", data=form | override, headers=headers).status_code == 400
    assert client.post("/oauth/token", data=form, headers=headers).status_code == 200
    for override in ({"code_challenge_method": "plain"}, {"resource": "https://other.example/mcp"},
                     {"scope": "serverhub:admin"}, {"scope": ""}):
        assert client.get("/oauth/authorize", params=parameters | override).status_code == 400


@pytest.mark.parametrize("scopes", [
    "serverhub:read", "serverhub:jobs", "serverhub:policies",
    "serverhub:read serverhub:jobs", "serverhub:read serverhub:policies",
    "serverhub:jobs serverhub:policies", "serverhub:read serverhub:jobs serverhub:policies",
])
def test_oauth_scope_roundtrip_and_tool_authorization(control, scopes):
    from serverhub.mcp import TOOLS

    client, headers, _ = control
    token, _, _ = oauth_flow(client, headers, scopes)
    assert set(token["scope"].split()) == set(scopes.split())
    bearer = {"Authorization": "Bearer " + token["access_token"]}
    tools = client.post("/mcp", headers=bearer, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
    }).json()["result"]["tools"]
    assert {tool["name"] for tool in tools} == {name for name, _, _, scope in TOOLS if scope in scopes.split()}
    for name, _, _, scope in TOOLS:
        if scope not in scopes.split():
            response = client.post("/mcp", headers=bearer, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": name, "arguments": {}},
            })
            assert response.status_code == 403, name


def test_oauth_pkce_code_replay_audience_and_mcp_tools(control):
    client, headers, _ = control
    token, form, _ = oauth_flow(client, headers)
    bearer = {"Authorization": "Bearer " + token["access_token"], "MCP-Protocol-Version": "2025-11-25"}
    assert client.post("/oauth/token", data=form, headers={"Origin": "http://testserver"}).status_code == 400
    assert client.get("/api/auth/me", headers=bearer).status_code == 401
    assert (
        client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code
        == 401
    )
    response = client.post(
        "/mcp",
        headers=bearer,
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
    )
    assert response.json()["result"]["protocolVersion"] == "2025-11-25"
    tools = client.post(
        "/mcp", headers=bearer, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    ).json()["result"]["tools"]
    assert "submit_job" in [x["name"] for x in tools]
    assert not any("exec" in x["name"] for x in tools)
    result = client.post(
        "/mcp",
        headers=bearer,
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "list_hosts", "arguments": {"command": "id"}},
        },
    )
    assert result.json()["result"]["isError"]


def test_oauth_refresh_rotation_replay_and_scope_restriction(control):
    client, headers, _ = control
    token, _, registered = oauth_flow(client, headers, "serverhub:read")
    bearer = {"Authorization": "Bearer " + token["access_token"]}
    assert (
        client.post(
            "/mcp",
            headers=bearer,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "submit_job", "arguments": {"kind": "inventory", "spec": {}}},
            },
        ).status_code
        == 403
    )
    form = {
        "grant_type": "refresh_token",
        "client_id": registered["client_id"],
        "refresh_token": token["refresh_token"],
        "resource": "http://testserver/mcp",
    }
    replacement = client.post("/oauth/token", data=form, headers={"Origin": "http://testserver"})
    assert replacement.status_code == 200
    assert client.post("/oauth/token", data=form, headers={"Origin": "http://testserver"}).status_code == 400
    assert (
        client.post(
            "/mcp",
            headers={"Authorization": "Bearer " + replacement.json()["access_token"]},
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
        ).status_code
        == 401
    )


def test_oauth_rejects_wrong_resource_and_unsafe_redirect(control):
    client, headers, _ = control
    assert (
        client.post(
            "/api/mcp/clients",
            headers=headers,
            json={"name": "evil", "redirect_uris": ["http://remote.example/callback"]},
        ).status_code
        == 422
    )
    token, form, _ = oauth_flow(client, headers)
    form["resource"] = "https://evil.example/mcp"
    assert client.post("/oauth/token", data=form, headers={"Origin": "http://testserver"}).status_code == 400
    assert (
        client.post(
            "/mcp",
            headers={"Authorization": "Bearer " + token["access_token"], "Origin": "https://evil.example"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        ).status_code
        == 403
    )


def test_mcp_predefined_approval_cannot_expand_hosts_or_production(control, monkeypatch):
    from serverhub import mcp
    from serverhub.auth import Principal

    client, headers, owner_id = control
    node, _ = enroll_node(client, headers)
    monkeypatch.setattr(
        mcp,
        "policy_templates",
        lambda: {
            "repair": {
                "name": "Household repair",
                "allowed_hosts": [node["host_id"]],
                "maximum_seconds": 600,
                "operations": ["systemd.restart"],
                "constraints": {"service_names": ["example.service"]},
                "production": True,
            }
        },
    )
    actor = Principal(owner_id, "owner", "owner")
    with SessionLocal() as db:
        with pytest.raises(PermissionDenied):
            mcp.activate_policy(
                {"template_id": "repair", "host_id": "other-host", "duration_seconds": 300}, actor, db
            )
        with pytest.raises(ValueError):
            mcp.activate_policy(
                {"template_id": "repair", "host_id": node["host_id"], "duration_seconds": 601}, actor, db
            )
        result = mcp.activate_policy(
            {"template_id": "repair", "host_id": node["host_id"], "duration_seconds": 300}, actor, db
        )
        assert result["production"] is False
        assert result["constraints"] == {"service_names": ["example.service"]}


def test_interval_schedule_persists_coalesces_and_does_not_overlap(control):
    from serverhub.jobs import Worker
    from serverhub.models import Schedule

    client, headers, _ = control
    node, _ = enroll_node(client, headers)
    created = client.post(
        "/api/schedules",
        headers=headers,
        json={
            "name": "Inventory review",
            "kind": "inventory",
            "host_id": node["host_id"],
            "spec": {},
            "interval_seconds": 60,
        },
    )
    assert created.status_code == 201, created.text
    schedule_id = created.json()["id"]
    worker = Worker(isolated=False)
    assert worker.run_once()
    with SessionLocal() as db:
        row = db.get(Schedule, schedule_id)
        first_job = row.last_job_id
        row.next_run = utcnow() - timedelta(hours=1)
        db.commit()
    # A separate Worker instance creates one coalesced scheduled run after restart.
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        row = db.get(Schedule, schedule_id)
        assert row.last_job_id != first_job
        assert db.get(Job, row.last_job_id).state == "succeeded"
        assert len(db.scalars(select(Job)).all()) == 2
    assert (
        client.patch("/api/schedules/" + schedule_id, headers=headers, json={"enabled": False}).status_code
        == 200
    )


def test_concrete_schedule_stops_when_policy_expires(control):
    from serverhub.models import Schedule
    from serverhub.scheduling import tick

    client, headers, owner_id = control
    node, _ = enroll_node(client, headers)
    with SessionLocal() as db:
        job = Job(owner_id=owner_id, host_id=node["host_id"], kind="operation", spec={}, state="succeeded")
        db.add(job)
        db.flush()
        row = Schedule(
            owner_id=owner_id,
            name="Denied repair",
            host_id=node["host_id"],
            kind="operation",
            spec={"operation": "systemd.restart", "arguments": {"service": "example.service"}},
            interval_seconds=60,
            next_run=utcnow() - timedelta(minutes=1),
            last_job_id=job.id,
        )
        db.add(row)
        db.commit()
        tick(db)
        db.commit()
        assert "policy" in row.last_error
        assert row.last_job_id == job.id
        assert len(db.scalars(select(Job)).all()) == 1


def test_scanner_evidence_is_persistent_without_internet_exposure_claim(control):
    from serverhub.telemetry import ingest_scanner_result

    client, headers, _ = control
    node, _ = enroll_node(client, headers)
    with SessionLocal() as db:
        host = db.get(Host, node["host_id"])
        result = {
            "scanner": "trivy",
            "coverage": "supported installed image packages",
            "findings": [
                {
                    "key": "known-cve-1",
                    "summary": "Known package vulnerability",
                    "service": "example-image",
                    "severity": "high",
                    "evidence": {"id": "CVE-example", "package": "example", "installed": "1", "fixed": "2"},
                    "remediation": ["Test fixed package"],
                }
            ],
        }
        ingest_scanner_result(db, host, result)
        db.commit()
        ingest_scanner_result(db, host, result)
        db.commit()
        findings = db.scalars(select(Finding)).all()
        assert len(findings) == 1
        assert findings[0].evidence["internet_exposure"] == "unverified"
        assert findings[0].evidence["fixed"] == "2"


def test_consent_csp_callback_is_scoped_and_cannot_inject_directives(control):
    from serverhub.oauth_models import OAuthClient

    client, headers, _ = control
    _, page, parameters, _, registered = begin_oauth(client, headers)
    baseline = client.get('/api/auth/me', headers=headers).headers['content-security-policy']
    assert baseline.endswith("form-action 'self'")
    assert page.headers['content-security-policy'] == baseline + ' https://client.example/callback'
    callback = "https://client.example/callback; form-action *; script-src 'unsafe-eval'?next=x"
    with SessionLocal() as db:
        db.get(OAuthClient, registered['client_id']).redirect_uris = [callback]
        db.commit()
    response = client.get('/oauth/authorize', params=parameters | {'redirect_uri': callback})
    assert response.status_code == 200
    policy = response.headers['content-security-policy']
    assert policy == baseline + " https://client.example/callback%3B%20form-action%20%2A%3B%20script-src%20%27unsafe-eval%27"
    assert len(policy.split(';')) == len(baseline.split(';'))
    response = client.get('/oauth/authorize', params=parameters | {'resource': 'https://other.example/mcp'})
    assert response.status_code == 400
    assert response.headers['content-security-policy'] == baseline
