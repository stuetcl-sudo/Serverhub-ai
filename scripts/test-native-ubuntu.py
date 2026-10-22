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
diag = client.get("/api/diagnostics", headers=headers)
diag.raise_for_status()
checks = {check["id"]: check for check in diag.json()["checks"]}
assert checks["worker"]["status"] == "ok", checks["worker"]
assert checks["database"]["status"] == "ok", checks["database"]
# Upgrade the same reviewed source to exercise backups, role grants, directory
# traversal and activation/health in a real native systemd environment.
upgraded = repair(source)
assert upgraded["state"] == "upgraded"
assert Path("/etc/serverhub/api.env").read_bytes() == before
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
            "unauthorized_restart": unauthorized.status_code,
            "upgrade": upgraded["state"],
            "database_backup_id": upgraded["backup_id"],
        }
    )
)
mock.shutdown()
