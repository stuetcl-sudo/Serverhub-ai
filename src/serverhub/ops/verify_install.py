"""Operator-run installed-system checks; never enroll capabilities or repair a host.

Default checks only read the controller. Explicit options may make a bounded
model probe or queue exactly inventory.refresh, never a model-selected action.
"""
import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time
import warnings
from urllib.parse import urlsplit

import httpx

from serverhub.diagnostics import verify_frontend_http


def controller_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
        raise ValueError("Use the controller origin without credentials, paths or query parameters")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if parsed.scheme == "http" and not loopback:
        raise ValueError("Remote controllers require HTTPS; plain HTTP is loopback-only")
    # Force port validation before any request.
    parsed.port
    return value.rstrip("/")


def read_token(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or not 1 <= info.st_size <= 8192):
            raise ValueError("Token file must be a private regular file owned by the current user (0600)")
        value = os.read(descriptor, 8193).decode().strip()
        if not value or len(value) > 8192 or any(char.isspace() for char in value):
            raise ValueError("Token file must contain one bearer token")
        return value
    finally:
        os.close(descriptor)


def verify(client, token, *, host_id=None, model_route=None, timeout=180,
           poll=None, clock=time.monotonic, sleep=time.sleep):
    """Return credential-free evidence. poll is a disposable-test hook, not a tool."""
    if not 1 <= timeout <= 3600:
        raise ValueError("Verification timeout must be 1..3600 seconds")
    if host_id and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", host_id):
        raise ValueError("Invalid host identity")
    if model_route and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", model_route):
        raise ValueError("Invalid model route")
    checks = []
    headers = {"Authorization": "Bearer " + token, "Origin": str(client.base_url).rstrip("/")}
    # A login cookie must not accidentally authenticate the anonymous-access check.
    client.cookies.clear()

    def add(name, state, detail, **evidence):
        checks.append({"id": name, "status": state, "message": detail, **evidence})

    def request(method, path, **kwargs):
        response = client.request(method, path, **kwargs)
        if response.is_redirect:
            raise ValueError("Unexpected redirect; verify the canonical controller origin")
        response.raise_for_status()
        return response

    def run(name, action):
        try:
            action()
        except httpx.HTTPStatusError as error:
            add(name, "failed", "HTTP " + str(error.response.status_code)
                + "; inspect Setup diagnostics and the authenticated account's permissions")
        except httpx.HTTPError:
            add(name, "failed", "Connection, TLS or timeout failure; verify routing, certificate trust and service health")
        except (ValueError, KeyError, TypeError, AttributeError):
            add(name, "failed", "Acceptance response invalid; inspect the named check in Setup diagnostics")

    def health():
        data = request("GET", "/health").json()
        if data.get("status") != "ok":
            raise ValueError("Unhealthy controller")
        add("api", "passed", "Controller health endpoint reports ok")

    def anonymous():
        response = client.get("/api/hosts")
        if response.status_code != 401:
            raise ValueError("Managed inventory was not protected by authentication")
        add("authentication_required", "passed", "Anonymous managed-host request rejected with HTTP 401")

    def frontend():
        verify_frontend_http(client)
        add("frontend", "passed", "HTML and referenced JavaScript/CSS delivered without authentication")

    run("api", health)
    run("authentication_required", anonymous)
    run("frontend", frontend)
    authenticated = False

    def account():
        nonlocal authenticated
        data = request("GET", "/api/auth/me", headers=headers).json()
        if data.get("role") != "owner":
            raise ValueError("Owner diagnostics require an owner identity")
        authenticated = True
        add("owner_authentication", "passed", "Authenticated owner session verified")

    run("owner_authentication", account)
    if authenticated:
        def diagnostics():
            data = request("GET", "/api/diagnostics", headers=headers).json()
            values = data["checks"]
            if not isinstance(values, list) or not values:
                raise ValueError("Missing installed diagnostics")
            if not {"database", "worker", "models", "frontend"} <= {item["id"] for item in values}:
                raise ValueError("Missing database/worker/model/frontend checks")
            for item in values:
                state = {"ok": "passed", "warning": "partial", "error": "failed"}[item["status"]]
                # Never copy raw prompt, route configuration, credentials or log bodies.
                remedies = {
                    "database": "Use the reviewed backed-up repair workflow to validate connectivity and migrations",
                    "worker": "Inspect journalctl -u serverhub-worker and worker.env/sandbox permissions",
                    "models": "Open Setup, configure a route and run Test connection & tools",
                    "frontend": "Rebuild frontend assets and run the reviewed repair workflow; check API read permissions",
                    "policies": "Use Approval policies to enroll an exact expiring grant if needed",
                    "hosts": "Complete host enrollment, start the agent and inspect its observations",
                }
                add("diagnostic:" + str(item["id"])[:128], state,
                    "Controller diagnostic: " + item["status"],
                    remediation=remedies.get(item["id"], "Open Setup diagnostics for this check") if state != "passed" else "")

        run("diagnostics", diagnostics)
        if model_route:
            def model():
                routes = request("GET", "/api/settings/models", headers=headers).json()["routes"]
                config = routes[model_route]
                result = request("POST", "/api/settings/models/test", headers=headers,
                                 json=config, timeout=90).json()
                if result.get("ready") is not True or result.get("tool_calling") is not True:
                    raise ValueError("Model did not pass the actual structured-tool probe")
                add("model_probe", "passed", "Actual harmless structured-tool probe passed", route=model_route)
            run("model_probe", model)
        if host_id:
            def job():
                response = request("POST", "/api/jobs", headers=headers, json={
                    "kind": "operation", "host_id": host_id, "token_budget": 0, "cost_budget": 0,
                    "time_limit": timeout, "max_attempts": 1,
                    "spec": {"operation": "inventory.refresh", "arguments": {}}}).json()
                identity = response["id"]
                if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity):
                    raise ValueError("Invalid job receipt")
                deadline = clock() + timeout
                while clock() < deadline:
                    if poll:
                        poll()
                    result = request("GET", "/api/jobs/" + identity, headers=headers).json()
                    if result.get("host_id") != host_id:
                        raise ValueError("Job target differs from requested host")
                    state = result["state"]
                    if state in {"succeeded", "failed", "cancelled", "partial", "paused", "waiting_approval"}:
                        inventory = result.get("result", {}).get("inventory")
                        valid = state == "succeeded" and isinstance(inventory, dict) and bool(inventory.get("os"))
                        gaps = inventory.get("errors", []) if isinstance(inventory, dict) else []
                        add("persistent_inventory_job", "passed" if valid and not gaps else "partial" if valid else "failed",
                            "Fixed read-only inventory job finished; collector gaps remain explicit",
                            job_id=identity, job_state=state, collector_gaps=len(gaps))
                        return
                    sleep(1)
                # Never cancel another operator's work or discard a durable receipt.
                add("persistent_inventory_job", "failed", "Local wait expired; job remains queryable in Active jobs",
                    job_id=identity)
            run("persistent_inventory_job", job)
    states = {check["status"] for check in checks}
    state = "failed" if "failed" in states else "partial" if "partial" in states else "passed"
    return {"format": 1, "state": state, "checks": checks,
            "scope": "Installed controller checks; optional harmless model probe and fixed inventory refresh. Not a production-readiness certification."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Canonical controller origin; HTTPS or loopback HTTP")
    parser.add_argument("--ca-file", type=Path)
    authentication = parser.add_mutually_exclusive_group(required=True)
    authentication.add_argument("--username", help="Owner login; password is prompted, never a command-line argument")
    authentication.add_argument("--token-file", type=Path, help="Existing private bearer token file, owned by this user")
    parser.add_argument("--host", help="Explicit enrolled host identity; queue only inventory.refresh")
    parser.add_argument("--probe-model", metavar="ROUTE", help="Opt in to a live harmless provider probe (existing $0.10 cap)")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)
    if args.username and not sys.stdin.isatty():
        parser.error("Password login requires an interactive terminal; use --token-file for unattended checks")
    created_session = False
    token = None
    try:
        origin = controller_url(args.url)
        trust = ssl.create_default_context(cafile=str(args.ca_file)) if args.ca_file else True
        with httpx.Client(base_url=origin, verify=trust, trust_env=False, follow_redirects=False, timeout=15) as client:
            try:
                if args.token_file:
                    token = read_token(args.token_file)
                else:
                    with warnings.catch_warnings():
                        # getpass must never fall back to an echoing password read.
                        warnings.simplefilter("error", getpass.GetPassWarning)
                        password = getpass.getpass("Owner password: ")
                    response = client.post("/api/auth/login", headers={"Origin": origin},
                                           json={"username": args.username, "password": password})
                    del password
                    response.raise_for_status()
                    token = response.json()["token"]
                    created_session = True
                report = verify(client, token, host_id=args.host, model_route=args.probe_model, timeout=args.timeout)
            finally:
                if created_session and token:
                    try:
                        client.post("/api/auth/logout", headers={"Authorization": "Bearer " + token, "Origin": origin}).raise_for_status()
                    except httpx.HTTPError:
                        if "report" not in locals():
                            report = {"state": "failed", "checks": []}
                        report["state"] = "failed"
                        report["checks"].append({"id": "logout", "status": "failed",
                                                 "message": "Temporary session revocation failed; revoke it through account administration"})
        print(json.dumps(report, indent=2))
        return {"passed": 0, "failed": 1, "partial": 2}[report["state"]]
    except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError, getpass.GetPassWarning, httpx.HTTPError):
        print(json.dumps({"state": "failed", "message": "Unable to authenticate or verify; check the origin, TLS CA, private token permissions and owner credentials. No response bodies or credentials are printed."}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
