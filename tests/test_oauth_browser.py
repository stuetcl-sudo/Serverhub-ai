"""WebKit/iPhone regression against real isolated HTTPS, without external accounts.

Run: pip install playwright && playwright install --with-deps webkit
     pytest tests/test_oauth_browser.py
"""

import base64
import hashlib
import html
import ipaddress
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from test_control_plane import control  # noqa: F401 fixture

from serverhub.settings import get_settings

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(params=["https://connector.example/callback", "https://connector.example/callback/space%20name?existing=1"])
def oauth_https(control, tmp_path, request):  # noqa: F811 fixture
    client, headers, _ = control
    registered = client.post("/api/mcp/clients", headers=headers, json={
        "name": "ChatGPT regression", "redirect_uris": [request.param],
    }).json()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    key_path.chmod(0o600)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    root = f"https://127.0.0.1:{sock.getsockname()[1]}"
    settings = get_settings()
    # Exercise production cookie flags; only the DB stays isolated SQLite.
    settings.dev_mode = False
    settings.public_url = root
    settings.allowed_origins = [root]
    server = uvicorn.Server(uvicorn.Config(
        client.app, ssl_certfile=str(cert_path), ssl_keyfile=str(key_path),
        lifespan="off", access_log=False, log_level="error",
    ))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started, "Isolated HTTPS server failed to start"
        yield root, registered
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_iphone_webkit_cross_site_entry_and_parallel_consent(oauth_https, reverse, decision):
    root, registered = oauth_https
    verifier = "a" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    parameters = {
        "client_id": registered["client_id"], "redirect_uri": registered["redirect_uris"][0],
        "response_type": "code", "scope": "serverhub:read serverhub:jobs serverhub:policies",
        "code_challenge": challenge, "code_challenge_method": "S256", "resource": root + "/mcp",
    }
    links = "".join(
        f'<a id="{state}" href="{html.escape(root + "/oauth/authorize?" + urlencode(parameters | {"state": state}))}">{state}</a>'
        for state in ("first", "second")
    )
    with playwright.sync_playwright() as pw:
        browser = pw.webkit.launch()
        context = browser.new_context(**pw.devices["iPhone 13"], ignore_https_errors=True)
        # Only external entry/callback and the dashboard stub are intercepted.
        # Auth requests use real HTTPS so WebKit alone handles all cookies.
        context.route("https://entry.example/**", lambda route: route.fulfill(
            status=200, content_type="text/html", body=links))
        context.route("https://connector.example/**", lambda route: route.fulfill(
            status=200, content_type="text/html", body="Callback"))
        context.route(root + "/", lambda route: route.fulfill(
            status=200, content_type="text/html", body="Test dashboard"))
        first = context.new_page()
        first.goto(root + "/")
        status = first.evaluate("""async () => (await fetch('/api/auth/login', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: 'owner', password: 'strong-test-password-42'})
        })).status""")
        assert status == 200
        assert context.cookies(), "Login did not set a browser cookie"
        for cookie in context.cookies():
            assert cookie["secure"] and cookie["httpOnly"] and cookie["sameSite"] == "Strict"

        pages = [(first, "first"), (context.new_page(), "second")]
        for page, state in pages:
            page.goto("https://entry.example/")
            page.locator("#" + state).click()
            assert "Sign in to ServerHub" in page.content()
            with page.expect_popup() as popup:
                page.get_by_text("Open dashboard").click()
            popup.value.wait_for_load_state()
            popup.value.close()
            page.get_by_text("Continue authorization").click()
            assert page.locator('button[value="approve"]').count() == 1, page.content()
        cookies = [c for c in context.cookies() if c["name"].startswith("serverhub_oauth_consent_")]
        assert len(cookies) == 2
        assert len({c["name"] for c in cookies}) == 2
        for cookie in cookies:
            assert cookie["secure"] and cookie["httpOnly"] and cookie["sameSite"] == "Strict"
            assert cookie["path"] == "/oauth/authorize"
        if reverse:
            pages.reverse()
        for page, state in pages:
            page.bring_to_front()
            page.locator(f'button[value="{decision}"]').click()
            page.wait_for_url("https://connector.example/**", timeout=10000)
            values = parse_qs(urlsplit(page.url).query)
            assert values["state"] == [state]
            assert bool(values.get("code")) == (decision == "approve")
            if decision == "deny":
                assert values["error"] == ["access_denied"]
            if "existing=1" in parameters["redirect_uri"]:
                assert values["existing"] == ["1"]
        assert not [c for c in context.cookies() if c["name"].startswith("serverhub_oauth_consent_")]
        browser.close()
