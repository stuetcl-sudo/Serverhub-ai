"""Destructive only to the named disposable GitHub runner's fresh ServerHub install.

Never run this against an existing ServerHub installation. CI supplies the explicit
confirmation and an ephemeral Ubuntu 24.04 runner; this file is not an AI tool.
"""

import json
import pwd
import httpx
from serverhub.ops.repair import repair
import os
from pathlib import Path
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

if (
    os.environ.get("SERVERHUB_DISPOSABLE_TEST") != "fresh-ubuntu-ci"
    or not os.environ.get("GITHUB_ACTIONS")
    or os.geteuid() != 0
):
    raise SystemExit("Refusing native test without explicit disposable GitHub Ubuntu VM confirmation")
if Path("/etc/serverhub/api.env").exists():
    raise SystemExit("Refusing test: an existing installation was found")

from serverhub.ops.installer import Installer, InstallError

source = Path(__file__).resolve().parents[1]
interrupted = False


def runner(command, **kwargs):
    global interrupted
    if command[-1:] == ["migrate"] and not interrupted:
        interrupted = True
        raise subprocess.CalledProcessError(
            1, command, stderr="Intentional disposable install interruption before migration"
        )
    return subprocess.run(command, **kwargs)


installer = Installer(source, public_url="https://serverhub.test", runner=runner)
try:
    installer.apply(
        install_dependencies=True, owner="ciowner", owner_password="isolated-native-owner-password-42"
    )
    raise AssertionError("Expected deliberate interruption")
except InstallError:
    assert interrupted
before = Path("/etc/serverhub/api.env").read_bytes()
assert json.loads(Path("/var/lib/serverhub-install/state.json").read_text())["state"] == "interrupted"
assert installer.apply(install_dependencies=True)["state"] == "installed"
assert installer.apply(install_dependencies=True)["state"] == "installed"
assert Path("/etc/serverhub/api.env").read_bytes() == before


# A loopback fixture implements only documented Ollama HTTP API messages. It never
# reaches the public internet or executes tool output.
class Ollama(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_json({"models": [{"name": "native-fixture"}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/api/show":
            return self.send_json({"capabilities": ["completion", "tools"]})
        if body["tools"][0]["function"]["name"] == "serverhub_probe":
            nonce = body["tools"][0]["function"]["parameters"]["properties"]["nonce"]["enum"][0]
            name, args = "serverhub_probe", {"nonce": nonce}
        elif not any(m["role"] == "tool" for m in body["messages"]):
            name, args = "inventory__query", {"section": "hardware", "query": "", "limit": 30}
        elif body["messages"][-1].get("tool_name") != "task__verify":
            name, args = "task__verify", {"checks": [{"kind": "inventory.fresh"}]}
        else:
            return self.send_json(
                {
                    "message": {
                        "role": "assistant",
                        "content": "CPU, memory and disk observations collected; inventory freshness independently checked.",
                    },
                    "prompt_eval_count": 100,
                    "eval_count": 30,
                }
            )
        self.send_json(
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"function": {"name": name, "arguments": args}}],
                },
                "prompt_eval_count": 100,
                "eval_count": 30,
            }
        )


mock = ThreadingHTTPServer(("127.0.0.1", 11439), Ollama)
threading.Thread(target=mock.serve_forever, daemon=True).start()
client = httpx.Client(base_url="http://127.0.0.1:9080", timeout=90, trust_env=False)
login = client.post(
    "/api/auth/login", json={"username": "ciowner", "password": "isolated-native-owner-password-42"}
)
login.raise_for_status()
assert "Secure" not in login.headers.get("set-cookie", "")  # narrowly scoped loopback tunnel login
headers = {"Authorization": "Bearer " + login.json()["token"], "Origin": "https://serverhub.test"}
model = {"kind": "ollama", "base_url": "http://127.0.0.1:11439", "model": "native-fixture"}
for endpoint in ("discover", "test"):
    response = client.post("/api/settings/models/" + endpoint, json=model, headers=headers)
    response.raise_for_status()
response = client.put("/api/settings/models/default", json=model, headers=headers)
response.raise_for_status()
enroll = client.post("/api/nodes/enrollment", json={"name": "native-ci-node"}, headers=headers)
enroll.raise_for_status()
nodeconfig = {
    "name": "native-ci-node",
    "state_dir": "/var/lib/serverhub-node",
    "controller_url": "http://127.0.0.1:9080",
    "allow_loopback_http": True,
    "enrollment_token": enroll.json()["token"],
}
config = Path("/etc/serverhub/native-ci-node.json")
config.write_text(json.dumps(nodeconfig))
config.chmod(0o640)
node = pwd.getpwnam("serverhub-node")
os.chown(config, 0, node.pw_gid)
python = "/opt/serverhub/current/venv/bin/python"
subprocess.run(
    [
        "runuser",
        "-u",
        "serverhub-node",
        "--",
        python,
        "-c",
        'import json;from serverhub.node.agent import NodeAgent;NodeAgent(json.load(open("/etc/serverhub/native-ci-node.json"))).run_once()',
    ],
    cwd="/",
    check=True,
)
host = client.get("/api/hosts", headers=headers).json()[0]["id"]
user = client.post(
    "/api/users",
    headers=headers,
    json={"username": "native-adult", "password": "isolated-adult-password-42", "role": "adult"},
)
user.raise_for_status()
profile = client.post(
    "/api/policies/profiles",
    headers=headers,
    json={"profile": "read_only", "subject_id": user.json()["id"], "host_id": host, "hours": 1},
)
profile.raise_for_status()
adult = client.post(
    "/api/auth/login",
    headers={"Origin": "https://serverhub.test"},
    json={"username": "native-adult", "password": "isolated-adult-password-42"},
)
adult.raise_for_status()
adult_headers = {"Authorization": "Bearer " + adult.json()["token"], "Origin": "https://serverhub.test"}
unauthorized = client.post(
    "/api/jobs",
    headers=adult_headers,
    json={
        "kind": "operation",
        "host_id": host,
        "spec": {"operation": "systemd.restart", "arguments": {"service": "ssh.service"}},
    },
)
assert unauthorized.status_code == 403
job = client.post(
    "/api/jobs",
    headers=adult_headers,
    json={
        "kind": "autonomous",
        "host_id": host,
        "spec": {"prompt": "Read CPU, memory and disk usage and verify fresh inventory."},
        "token_budget": 100000,
    },
)
job.raise_for_status()
for _ in range(60):
    result = client.get("/api/jobs/" + job.json()["id"], headers=adult_headers).json()
    if result["state"] in ("succeeded", "partial", "failed", "waiting_approval"):
        break
    time.sleep(1)
assert result["state"] == "succeeded", result
assert result["result"]["verified"]
# The deterministic read-only audit must also work without a model call, under
# the real worker DB role and native node UID. Poll only this disposable node.
audit_job = client.post("/api/jobs", headers=adult_headers, json={"kind": "operation", "host_id": host,
    "spec": {"operation": "host.audit", "arguments": {}}, "token_budget": 0, "cost_budget": 0, "time_limit": 180})
audit_job.raise_for_status()
for _ in range(30):
    subprocess.run(["runuser", "-u", "serverhub-node", "--", python, "-c",
        'import json;from serverhub.node.agent import NodeAgent;NodeAgent(json.load(open("/etc/serverhub/native-ci-node.json"))).run_once()'],
        cwd="/", check=True)
    audit_result = client.get("/api/jobs/" + audit_job.json()["id"], headers=adult_headers).json()
    if audit_result["state"] in ("succeeded", "partial", "failed", "waiting_approval"):
        break
    time.sleep(1)
assert audit_result["state"] == "partial", audit_result
assert audit_result["result"]["mode"] == "read_only_dry_run"
assert audit_result["result"]["changes_executed"] == []
assert audit_result["tokens_used"] == 0
diag = client.get("/api/diagnostics", headers=headers)
diag.raise_for_status()
checks = {check["id"]: check for check in diag.json()["checks"]}
assert checks["worker"]["status"] == "ok", checks["worker"]
assert checks["database"]["status"] == "ok", checks["database"]
# Upgrade the same reviewed source to exercise backups, role grants, directory
# traversal and activation/health in a real native systemd environment.
legacy_models = Path("/etc/serverhub/models.yaml")
legacy_models.write_text("routes:\n  default: obsolete-provider-reference\n")
legacy_models.chmod(0o600)
upgraded = repair(source)
assert upgraded["state"] == "upgraded"
assert upgraded["models_configuration"] == "needs_setup"
assert legacy_models.stat().st_mode & 0o777 == 0o600
assert client.get("/api/settings/models", headers=headers).json()["configured"]
assert Path("/etc/serverhub/api.env").read_bytes() == before
# Prove a failed post-upgrade healthcheck restores the previous release,
# credentials and native units. This runs only inside the confirmed disposable VM.
previous = Path("/opt/serverhub/current").resolve()
healthchecks = Installer._healthchecks
try:

    def fail_health(self, release):
        raise InstallError("Intentional isolated post-upgrade verification failure")

    Installer._healthchecks = fail_health
    try:
        repair(source)
        raise AssertionError("Expected failed upgrade")
    except InstallError:
        pass
finally:
    Installer._healthchecks = healthchecks
assert Path("/opt/serverhub/current").resolve() == previous
assert Path("/etc/serverhub/api.env").read_bytes() == before
assert json.loads(Path("/var/lib/serverhub-release/pending.json").read_text())["state"] == "reverted"
installer._healthchecks(previous)
# No production systems are contacted. Emit only non-secret result evidence.
print(
    json.dumps(
        {
            "native_install": "passed",
            "interruption_resume": "passed",
            "idempotency": "passed",
            "api_worker": "healthy",
            "model_setup": "mock Ollama API verified",
            "read_only_autonomous_job": result["state"],
            "read_only_host_audit": audit_result["state"],
            "unauthorized_restart": unauthorized.status_code,
            "upgrade": upgraded["state"],
            "failed_upgrade_rollback": "passed",
            "database_backup_id": upgraded["backup_id"],
        }
    )
)
mock.shutdown()
