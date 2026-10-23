"""Native unprivileged node agent with durable command deduplication.

Agent communication always verifies HTTPS. Plain HTTP is allowed only for
loopback development when explicitly configured, never for remote agents.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import logging
import os
import signal
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import yaml

from .broker import ALLOWED_OPERATIONS, BrokerDenied, call_broker
from .discovery import discover

LOG = logging.getLogger("serverhub.node")
READ_OPERATIONS = {"inventory.refresh", "discovery.refresh", "systemd.status", "systemd.logs", "diagnostics.network", "diagnostics.storage", "security.scan"}


class AgentError(RuntimeError):
    pass


def validate_controller_url(value: str, *, allow_loopback_http: bool = False) -> str:
    url = urlsplit(value)
    if url.username or url.password or url.query or url.fragment or url.path not in {"", "/"} or not url.hostname:
        raise AgentError("controller URL must not contain credentials, query or fragment")
    if url.scheme != "https":
        if not (allow_loopback_http and url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost", "::1"}):
            raise AgentError("controller requires verified HTTPS")
    return value.rstrip("/")


def _private_write(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(".new")
    fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(payload, output, separators=(",", ":"))
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


class CommandJournal:
    def __init__(self, path: Path):
        if path.is_symlink():
            raise AgentError("journal must not be a symlink")
        self.db = sqlite3.connect(path, timeout=10)
        os.chmod(path, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS commands (key TEXT PRIMARY KEY, digest TEXT NOT NULL, state TEXT NOT NULL, result TEXT, updated REAL NOT NULL)")
        self.db.commit()

    def begin(self, key: str, digest: str, *, retry_read: bool) -> tuple[str, dict | None]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT digest,state,result FROM commands WHERE key=?", (key,)).fetchone()
            if row:
                if row[0] != digest:
                    raise AgentError("idempotency key reused with different operation")
                if row[1] in {"succeeded", "failed"}:
                    self.db.commit()
                    return row[1], json.loads(row[2])
                if not retry_read:
                    result = {"error": "interrupted command has uncertain outcome; operator reconciliation required", "failure_class": "in_doubt", "retry_safe": False}
                    self.db.execute("UPDATE commands SET state='failed', result=?, updated=? WHERE key=?", (json.dumps(result), time.time(), key))
                    self.db.commit()
                    return "failed", result
                self.db.execute("UPDATE commands SET updated=? WHERE key=?", (time.time(), key))
            else:
                self.db.execute("INSERT INTO commands VALUES (?,?,'running',NULL,?)", (key, digest, time.time()))
            self.db.commit()
            return "running", None
        except Exception:
            self.db.rollback()
            raise

    def finish(self, key: str, state: str, result: dict) -> None:
        self.db.execute("UPDATE commands SET state=?,result=?,updated=? WHERE key=?", (state, json.dumps(result), time.time(), key))
        self.db.commit()

    def close(self) -> None:
        self.db.close()


def _expiry(value: str | float | int | None) -> float:
    if isinstance(value, (float, int)):
        return float(value)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    raise AgentError("command missing expiration")


class NodeAgent:
    def __init__(self, config: dict, *, transport: httpx.BaseTransport | None = None):
        self.config = config
        self.controller = validate_controller_url(config.get("controller_url", ""), allow_loopback_http=config.get("allow_loopback_http", False))
        self.state = Path(config.get("state_dir", "/var/lib/serverhub-node"))
        if not self.state.is_absolute() or self.state.is_symlink():
            raise AgentError("state directory must be absolute and not a symlink")
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state, 0o700)
        self.identity_path = self.state/"identity.json"
        if self.identity_path.is_symlink():
            raise AgentError("identity must not be a symlink")
        self.identity = json.loads(self.identity_path.read_text()) if self.identity_path.exists() else {"identity": str(uuid.uuid4())}
        if self.identity_path.exists():
            os.chmod(self.identity_path, 0o600)
        verify = config.get("ca_bundle", True)
        if verify is False or not isinstance(verify, (str, bool)):
            raise AgentError("TLS validation cannot be disabled")
        self.client = httpx.Client(base_url=self.controller, timeout=httpx.Timeout(25, connect=5), verify=verify,
                                   transport=transport, follow_redirects=False, trust_env=False)
        self.journal = CommandJournal(self.state/"commands.db")
        self.stopping = False
        self.last_inventory = 0.0
        self.last_event_poll = 0.0

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict | list:
        headers = {"Authorization": f"Bearer {self.identity['token']}"} if self.identity.get("token") else {}
        response = self.client.request(method, path, json=payload, headers=headers)
        if response.status_code in {401, 403}:
            raise AgentError("node identity rejected or revoked; re-enrollment requires owner")
        response.raise_for_status()
        if len(response.content) > 20*1024*1024:
            raise AgentError("controller response exceeds limit")
        return response.json() if response.content else {}

    def enroll(self) -> None:
        if self.identity.get("token"):
            return
        token = self.config.get("enrollment_token")
        if not token:
            raise AgentError("owner-issued one-use enrollment_token required")
        response = self._request("POST", "/api/nodes/enroll", {"token": token, "name": self.config.get("name", os.uname().nodename), "identity": self.identity["identity"]})
        if not isinstance(response, dict) or not response.get("host_id") or not response.get("token"):
            raise AgentError("invalid enrollment response")
        self.identity.update({"host_id": response["host_id"], "token": response["token"]})
        _private_write(self.identity_path, self.identity)
        self.config.pop("enrollment_token", None)
        LOG.info("enrolled native node identity")

    def inventory(self) -> dict:
        broker = self.config.get("broker_socket")
        if broker:
            try:
                return call_broker(broker, "inventory.refresh", {})["inventory"]
            except (BrokerDenied, OSError, ValueError):
                inventory = discover()
                inventory["errors"].append({"collector": "broker", "error": "Unavailable", "detail": "privileged observations unavailable"})
                return inventory
        return discover()

    def execute(self, cmd: dict) -> dict:
        if not isinstance(cmd, dict) or not isinstance(cmd.get("id"), str):
            raise AgentError("invalid command envelope")
        operation, arguments = cmd.get("operation"), cmd.get("arguments", {})
        if operation not in ALLOWED_OPERATIONS or not isinstance(arguments, dict):
            return {"state": "failed", "result": {"error": "operation is not allowlisted", "failure_class": "policy"}}
        if _expiry(cmd.get("expires_at")) <= time.time():
            return {"state": "failed", "result": {"error": "command expired", "failure_class": "expired"}}
        key = cmd.get("idempotency_key")
        if not isinstance(key, str) or not key or len(key) > 256:
            return {"state": "failed", "result": {"error": "idempotency key required", "failure_class": "policy"}}
        digest = hashlib.sha256(json.dumps([operation, arguments], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        state, cached = self.journal.begin(key, digest, retry_read=operation in READ_OPERATIONS)
        if state in {"succeeded", "failed"}:
            return {"state": state, "result": cached}
        try:
            if operation in {"inventory.refresh", "discovery.refresh"}:
                if arguments:
                    raise AgentError("inventory operation accepts no arguments")
                result = {"inventory": self.inventory()}
            else:
                broker = self.config.get("broker_socket")
                if not broker:
                    raise AgentError("privileged operation requires the separately configured broker")
                if cmd.get("audit_context") is not None:
                    result = call_broker(broker, operation, arguments, audit_context=cmd["audit_context"])
                else:
                    result = call_broker(broker, operation, arguments)
            state = "succeeded"
        except (AgentError, BrokerDenied, OSError, ValueError) as exc:
            state, result = "failed", {"error": str(exc)[:256], "failure_class": "execution", "retry_safe": operation in READ_OPERATIONS}
        self.journal.finish(key, state, result)
        return {"state": state, "result": result}

    def run_once(self) -> None:
        self.enroll()
        now = time.monotonic()
        interval = min(max(float(self.config.get("interval", 60)), 30), 3600)
        refresh = not self.last_inventory or now - self.last_inventory >= interval
        # No worker Docker socket. The root broker exposes a no-argument event
        # hint, at most every 15s; full collections are debounced to >=30s.
        if not refresh and self.config.get("broker_socket") and now - self.last_event_poll >= 15:
            self.last_event_poll = now
            try:
                changed = call_broker(self.config["broker_socket"], "inventory.events", {}).get("changed", False)
                refresh = bool(changed) and now - self.last_inventory >= 30
            except (BrokerDenied, OSError, ValueError):
                pass  # Older/offline broker: periodic full reconciliation remains.
        if refresh:
            self._request("POST", "/api/nodes/report", {"inventory": self.inventory(), "agent_version": "1.0.0"})
            self.last_inventory = time.monotonic()
        commands = self._request("GET", "/api/nodes/commands")
        if not isinstance(commands, list):
            raise AgentError("invalid controller command list")
        for cmd in commands[:10]:
            if self.stopping:
                break
            try:
                result = self.execute(cmd)
            except (AgentError, ValueError, TypeError):
                result = {"state": "failed", "result": {"error": "invalid or conflicting command", "failure_class": "policy"}}
            self._request("POST", f"/api/nodes/commands/{cmd['id']}/result", result)

    def run(self) -> None:
        interval = min(max(float(self.config.get("interval", 60)), 5), 3600)
        failures = 0
        while not self.stopping:
            try:
                self.run_once()
                failures = 0
            except (AgentError, httpx.HTTPError, OSError):
                failures += 1
                # URLs, tokens, payloads and exception tracebacks are deliberately excluded.
                LOG.warning("node controller unavailable or identity rejected; retry pending (%s)", failures)
            delay = min(min(interval, 15) * max(1, 2 ** min(failures, 5)), 300)
            deadline = time.monotonic()+delay
            while not self.stopping and time.monotonic() < deadline:
                time.sleep(min(1, max(0, deadline-time.monotonic())))

    def close(self) -> None:
        self.client.close()
        self.journal.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/serverhub/node.yaml")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--print-inventory", action="store_true", help="read-only local inventory, no enrollment or network call")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.print_inventory:
        print(json.dumps(discover(), indent=2))
        return
    path = Path(args.config)
    if path.is_symlink() or path.stat().st_mode & 0o022 or path.stat().st_uid != 0:
        raise SystemExit("agent configuration must be root-owned and not writable by group/other")
    config = yaml.safe_load(path.read_text())
    if not isinstance(config, dict):
        raise SystemExit("invalid node configuration")
    if os.geteuid() == 0:
        raise SystemExit("native agent must run as its dedicated unprivileged service account")
    agent = NodeAgent(config)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: setattr(agent, "stopping", True))
    try:
        agent.run_once() if args.once else agent.run()
    finally:
        agent.close()


if __name__ == "__main__":
    main()
