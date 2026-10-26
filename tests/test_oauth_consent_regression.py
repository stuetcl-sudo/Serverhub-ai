"""OAuth regression tests ported onto the exact installed production source."""
# ruff: noqa: F811 -- imported pytest fixture is injected by parameter name
import base64
import hashlib
import re
import secrets
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select
from test_control_plane import control  # noqa: F401
from serverhub.auth import hash_password, hash_secret
from serverhub.database import SessionLocal, utcnow
from serverhub.models import User

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


def test_overlapping_pending_consent_requests_both_complete(control):
    client, headers, _ = control
    first, _, _, _, _ = begin_oauth(client, headers, state="first")
    second, _, _, _, _ = begin_oauth(client, headers, state="second")
    assert post_consent(client, first).status_code == 303
    assert post_consent(client, second).status_code == 303
