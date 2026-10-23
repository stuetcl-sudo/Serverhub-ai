"""Destructive only to the named disposable GitHub runner's fresh ServerHub install.

Never run this against an existing ServerHub installation. CI supplies the explicit
confirmation and an ephemeral Ubuntu 24.04 runner; this file is not an AI tool.
"""

import json
import grp
import ssl
import yaml
import pwd
import httpx
from serverhub.ops.repair import repair
from serverhub.node.broker import verify_broker_audit
from serverhub.ops.verify_install import verify as verify_installed
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

print(json.dumps({"audit_parent_modes": {str(path): oct(path.stat().st_mode & 0o777)
    for path in (Path("/var/log"), Path("/var/lib"))}}), flush=True)
source = Path(__file__).resolve().parents[1]
import runpy
control_fixture = runpy.run_path(str(source / 'scripts/coexistence-fixture.py'))
control_fixture['start']()
control_fixture['conflicts'](source)
interrupted = False


def runner(command, **kwargs):
    global interrupted
    if Path(command[0]).name == "apt-get":
        assert kwargs.get("env", {}).get("NEEDRESTART_SUSPEND") == "1"
    if command[-1:] == ["migrate"] and not interrupted:
        interrupted = True
        raise subprocess.CalledProcessError(
            1, command, stderr="Intentional disposable install interruption before migration"
        )
    return subprocess.run(command, **kwargs)


installer = Installer(source, public_url="https://serverhub.test", runner=runner, ai_identity=True)
try:
    installer.apply(
        install_dependencies=True, owner="ciowner", owner_password="isolated-native-owner-password-42", enable_broker=True
    )
    raise AssertionError("Expected deliberate interruption")
except InstallError:
    assert interrupted
before = Path("/etc/serverhub/api.env").read_bytes()
assert json.loads(Path("/var/lib/serverhub-install/state.json").read_text())["state"] == "interrupted"
assert installer.apply(install_dependencies=True, enable_broker=True)["state"] == "installed"
assert installer.apply(install_dependencies=True, enable_broker=True)["state"] == "installed"
assert Path("/etc/serverhub/api.env").read_bytes() == before
assert subprocess.check_output(["systemctl", "show", "serverhub-ai-worker", "--property=User", "--value"], text=True).strip() == "serverhub-ai"
assert pwd.getpwnam("serverhub-ai").pw_shell.endswith("nologin")
assert (Path('/opt/serverhub/current').resolve() / 'installed.json').stat().st_mode & 0o777 == 0o644
for tree in [Path('/opt/serverhub/current').resolve(), Path('/opt/serverhub/recovery-ai')]:
    assert all(not (p.stat().st_mode & 0o022) for p in tree.rglob('*') if not p.is_symlink())


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
    "state_dir": "/var/lib/serverhub-ai-node",
    "controller_url": "http://127.0.0.1:9080",
    "allow_loopback_http": True,
    "broker_socket": "/run/serverhub-ai-broker/control.sock",
    "enrollment_token": enroll.json()["token"],
}
config = Path("/etc/serverhub/native-ci-node.json")
config.write_text(json.dumps(nodeconfig))
config.chmod(0o640)
node = pwd.getpwnam("serverhub-ai-node")
os.chown(config, 0, node.pw_gid)
python = "/opt/serverhub/current/venv/bin/python"
subprocess.run(
    [
        "runuser",
        "-u",
        "serverhub-ai-node",
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
    json={"profile": "read_only", "subject_id": user.json()["id"], "host_id": host, "hours": 1, "services": ["serverhub-ai-api.service"]},
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
# The separately authenticated root broker executes a read-only status probe.
# Critical service diagnostics may be granted; restarts remain protected.
broker_path = Path("/etc/serverhub/broker.yaml")
broker_config = yaml.safe_load(broker_path.read_text())
broker_config["allowed_services"] = ["serverhub-ai-api.service"]
broker_path.write_text(yaml.safe_dump(broker_config))
subprocess.run(["systemctl", "restart", "serverhub-ai-broker"], check=True)
status_job = client.post("/api/jobs", headers=adult_headers, json={"kind": "operation", "host_id": host,
    "spec": {"operation": "systemd.status", "arguments": {"service": "serverhub-ai-api.service"}}})
status_job.raise_for_status()
for _ in range(30):
    subprocess.run(["runuser", "-u", "serverhub-ai-node", "--", python, "-c",
        'import json;from serverhub.node.agent import NodeAgent;NodeAgent(json.load(open("/etc/serverhub/native-ci-node.json"))).run_once()'],
        cwd="/", check=True)
    broker_result = client.get("/api/jobs/" + status_job.json()["id"], headers=adult_headers).json()
    if broker_result["state"] in ("succeeded", "failed", "waiting_approval"):
        break
    time.sleep(1)
assert broker_result["state"] == "succeeded", broker_result
assert broker_result["result"]["execution_context"]["effective_uid"] == 0
assert broker_result["result"]["execution_context"]["peer_uid"] == node.pw_uid
assert verify_broker_audit("/var/lib/serverhub-broker/audit/events.jsonl")["valid"]
records = [json.loads(line)["record"] for line in Path("/var/lib/serverhub-broker/audit/events.jsonl").read_text().splitlines()]
assert any(record.get("correlation", {}).get("job_id") == status_job.json()["id"] for record in records)
# The AI runtime cannot connect directly to the privileged socket.
probe = subprocess.run(["runuser", "-u", "serverhub-ai", "--", python, "-c",
    'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/serverhub-ai-broker/control.sock")'],
    cwd="/", capture_output=True, text=True)
assert probe.returncode != 0 and "PermissionError" in probe.stderr
# A local admission failure must pause without spending a model/job attempt.
limited = client.put("/api/settings/models/default", headers=headers, json={**model, "context_limit": 1024})
limited.raise_for_status()
job = client.post(
    "/api/jobs",
    headers=adult_headers,
    json={
        "kind": "autonomous",
        "host_id": host,
        "spec": {"prompt": "Read CPU, memory and disk usage and verify fresh inventory."},
        "token_budget": 20000,
    },
)
job.raise_for_status()
for _ in range(60):
    result = client.get("/api/jobs/" + job.json()["id"], headers=adult_headers).json()
    if result["state"] in ("succeeded", "partial", "failed", "waiting_approval", "paused"):
        break
    time.sleep(1)
assert result["state"] == "paused", result
assert result["attempts"] == 0 and result["tokens_used"] == 0
corrected = client.put("/api/settings/models/default", headers=headers, json={**model, "context_limit": 16384})
corrected.raise_for_status()
client.post("/api/jobs/" + job.json()["id"] + "/resume", headers=adult_headers).raise_for_status()
for _ in range(60):
    result = client.get("/api/jobs/" + job.json()["id"], headers=adult_headers).json()
    if result["state"] in ("succeeded", "partial", "failed", "waiting_approval", "paused"):
        break
    time.sleep(1)
assert result["state"] == "succeeded", result
assert result["result"]["verified"]
assert result["attempts"] == 1 and result["tokens_used"] <= 20000

# The deterministic read-only audit must also work without a model call, under
# the real worker DB role and native node UID. Poll only this disposable node.
audit_job = client.post("/api/jobs", headers=adult_headers, json={"kind": "operation", "host_id": host,
    "spec": {"operation": "host.audit", "arguments": {}}, "token_budget": 0, "cost_budget": 0, "time_limit": 180})
audit_job.raise_for_status()
for _ in range(30):
    subprocess.run(["runuser", "-u", "serverhub-ai-node", "--", python, "-c",
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
# Model an older installation which lacks the new staging account/recovery unit.
subprocess.run(["systemctl","disable","--now","serverhub-ai-operation-watchdog.timer"],check=True)
for unit in ("serverhub-ai-operation-watchdog.service","serverhub-ai-operation-watchdog.timer"):
    Path("/etc/systemd/system",unit).unlink()
subprocess.run(["systemctl","daemon-reload"],check=True)
subprocess.run(["userdel","serverhub-ai-staging"],check=True)
legacy_models = Path("/etc/serverhub/models.yaml")
legacy_models.write_text("routes:\n  default: obsolete-provider-reference\n")
legacy_models.chmod(0o600)
legacy_projects = Path("/etc/serverhub/projects.yaml")
legacy_projects.write_text("projects: {}\n")
legacy_projects.chmod(0o644)
project_gid = pwd.getpwnam("serverhub-ai-worker").pw_gid
os.chown(legacy_projects, 0, project_gid)
assert client.get("/api/projects", headers=headers).json() == []
upgraded = repair(source)
assert legacy_projects.read_text().endswith("projects: []\n")
assert legacy_projects.stat().st_gid == project_gid and legacy_projects.stat().st_mode & 0o777 == 0o644
assert client.get("/api/projects", headers=headers).status_code == 200
assert upgraded["state"] == "upgraded"
assert subprocess.run(["id","serverhub-ai-staging"],capture_output=True).returncode==0
assert subprocess.check_output(["systemctl","is-active","serverhub-ai-operation-watchdog.timer"],text=True).strip()=="active"
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
# Verify persistent direct TLS with the actual systemd API identity. Temporary
# certificates and access configuration belong only to this disposable runner.
cert_dir = Path("/etc/serverhub/tls")
cert_dir.mkdir(mode=0o750)
api_gid = grp.getgrnam("serverhub-ai-api").gr_gid
os.chown(cert_dir, 0, api_gid)
cert, key = cert_dir / "cert.pem", cert_dir / "key.pem"
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
for path in (cert, key):
    os.chown(path, 0, api_gid)
    path.chmod(0o640)
access = Path("/etc/serverhub/access.env")
access.write_text("SERVERHUB_API_BIND=127.0.0.1\nSERVERHUB_PUBLIC_URL=https://127.0.0.1:9080\n"
    + f"SERVERHUB_TLS_CERTFILE={cert}\nSERVERHUB_TLS_KEYFILE={key}\n"
    + f"SERVERHUB_HEALTH_URL=https://127.0.0.1:9080\nSERVERHUB_HEALTH_CA={cert}\n")
os.chown(access, 0, api_gid)
access.chmod(0o640)
subprocess.run(["systemctl", "restart", "serverhub-ai-api"], check=True)
installer._healthchecks(previous)
with httpx.Client(base_url="https://127.0.0.1:9080", verify=ssl.create_default_context(cafile=str(cert)), trust_env=False) as tls:
    assert tls.get("/api/hosts").status_code == 401
    assert tls.get("/").status_code == 200
    from serverhub.diagnostics import verify_frontend_http
    verify_frontend_http(tls)
# Exercise the installed-system acceptance command against actual TLS/API/worker
# and the disposable native node. The provider here is explicitly an HTTP fixture;
# separate workflows test actual qwen inference. Collector gaps must remain partial.
public_ca = Path('/etc/serverhub/native-public-ca.pem')
public_ca.write_bytes(cert.read_bytes())
public_ca.chmod(0o644)
nodeconfig.update(controller_url='https://127.0.0.1:9080', ca_bundle=str(public_ca))
config.write_text(json.dumps(nodeconfig))


def poll_acceptance_node():
    subprocess.run(['runuser', '-u', 'serverhub-ai-node', '--', python, '-c',
        'import json;from serverhub.node.agent import NodeAgent;NodeAgent(json.load(open("/etc/serverhub/native-ci-node.json"))).run_once()'],
        cwd='/', check=True)


with httpx.Client(base_url='https://127.0.0.1:9080',
                  verify=ssl.create_default_context(cafile=str(cert)), trust_env=False) as acceptance_client:
    acceptance = verify_installed(acceptance_client, headers['Authorization'].removeprefix('Bearer '),
                                  host_id=host, model_route='default', poll=poll_acceptance_node)
acceptance_checks = {item['id']: item for item in acceptance['checks']}
for check in ('api', 'authentication_required', 'frontend', 'owner_authentication',
              'diagnostic:database', 'diagnostic:worker', 'diagnostic:model_file', 'model_probe'):
    assert acceptance_checks[check]['status'] == 'passed', acceptance
assert acceptance_checks['persistent_inventory_job']['job_state'] == 'succeeded', acceptance
temporary_token = Path('/var/lib/serverhub-install/acceptance.token')
try:
    temporary_token.write_text(headers['Authorization'].removeprefix('Bearer '))
    temporary_token.chmod(0o600)
    acceptance_process = subprocess.run([python, '-m', 'serverhub.ops.verify_install',
        '--url', 'https://127.0.0.1:9080', '--ca-file', str(cert),
        '--token-file', str(temporary_token), '--probe-model', 'default'],
        text=True, capture_output=True, check=False, timeout=120)
    cli_acceptance = json.loads(acceptance_process.stdout)
    assert acceptance_process.returncode in (0, 2) and cli_acceptance['state'] in ('passed', 'partial'), cli_acceptance
    assert headers['Authorization'].removeprefix('Bearer ') not in acceptance_process.stdout + acceptance_process.stderr
finally:
    temporary_token.unlink(missing_ok=True)
print('INSTALLED_ACCEPTANCE_EVIDENCE=' + json.dumps({'state': acceptance['state'],
      'checks': {name: value['status'] for name, value in acceptance_checks.items()},
      'cli_state': cli_acceptance['state'], 'model_provider': 'HTTP fixture, not actual inference',
      'managed_configuration_changed': False}), flush=True)
# Restart again to prove no terminal-held tunnel or inherited TLS process exists.
subprocess.run(["systemctl", "restart", "serverhub-ai-api"], check=True)
installer._healthchecks(previous)
# Exercise the independent systemd watchdog in a separate root process with
# the activation process absent. Only this disposable runner's releases are used.
subprocess.run(["systemctl", "stop", "serverhub-ai-release-watchdog.timer"], check=True)
pending_path = Path("/var/lib/serverhub-release/pending.json")
abandoned = json.loads(pending_path.read_text())
assert Path(abandoned["previous"]).resolve() == previous
candidate = Path(abandoned["candidate"])
assert candidate.is_relative_to(Path("/opt/serverhub/releases")) and candidate.is_dir()
abandoned["state"], abandoned["deadline"] = "armed", time.time() - 1
pending_path.write_text(json.dumps(abandoned))
installer._activate(candidate)
subprocess.run(["systemctl", "start", "serverhub-ai-release-watchdog.service"], check=True)
assert Path("/opt/serverhub/current").resolve() == previous
assert json.loads(pending_path.read_text())["state"] == "reverted"
installer._healthchecks(previous)
assert verify_broker_audit("/var/lib/serverhub-broker/audit/events.jsonl")["valid"]
subprocess.run(["systemctl", "start", "serverhub-ai-release-watchdog.timer"], check=True)
# No production systems are contacted. Emit only non-secret result evidence.
print(
    json.dumps(
        {
            "native_install": "passed",
            "dedicated_ai_identity": "serverhub-ai",
            "persistent_authenticated_tls": "passed",
            "correlated_root_broker_audit": "passed",
            "ai_direct_broker_access": "denied",
            "interruption_resume": "passed",
            "idempotency": "passed",
            "api_worker": "healthy",
            "model_setup": "mock Ollama API verified",
            "preflight_pause_refund_resume": "passed",
            "read_only_autonomous_job": result["state"],
            "read_only_host_audit": audit_result["state"],
            "unauthorized_restart": unauthorized.status_code,
            "upgrade": upgraded["state"],
            "failed_upgrade_rollback": "passed",
            "independent_watchdog_rollback": "passed",
            "database_backup_id": upgraded["backup_id"],
        }
    )
)
mock.shutdown()

control_fixture['verify']()
