"""Root-owned, Unix-socket execution boundary. This is not a shell endpoint.

Only root's configured node UID can connect. All targets are root-owned allowlists.
The AI worker must not be in the node group and has no access to this socket.
"""
from __future__ import annotations
import argparse
import fcntl
import uuid
import hashlib
import hmac
import json
import logging
import os
import re
import socket
import socketserver
import stat
import struct
import time
from pathlib import Path
from typing import Any

import yaml

from .discovery import CollectionError, command, discover, docker_events, caddy_endpoints
from .security import vulnerability_findings

MAX_REQUEST = 65536
ALLOWED_OPERATIONS = frozenset({"inventory.refresh", "discovery.refresh", "diagnostics.network", "diagnostics.storage", "systemd.status", "systemd.logs", "systemd.restart",
                                "docker.restart", "docker.compose.apply", "security.scan", "docker.backup.create", "docker.backup.list", "docker.backup.verify", "docker.restore.plan", "docker.restore.apply", "package.plan", "package.apply", "configuration.plan", "configuration.apply", "docker.compose.update", "development.deploy"})
PROTECTED_UNITS = re.compile(r"^(serverhub|ssh|sshd|network|systemd-network|NetworkManager|docker|containerd|ufw|nftables|postgresql|dbus|polkit|sudo|cron)", re.I)
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")


class BrokerDenied(RuntimeError):
    pass


def trusted_file(path: str | Path, *, root: bool = True) -> Path:
    p = Path(path)
    if not p.is_absolute() or p.is_symlink():
        raise BrokerDenied("configuration path must be absolute and not a symlink")
    # Resolve every parent and require trusted ownership/permissions, not just leaf.
    for part in [p, *p.parents]:
        st = part.lstat()
        if stat.S_ISLNK(st.st_mode) or (root and st.st_uid != 0) or st.st_mode & 0o022:
            raise BrokerDenied("configuration or parent has unsafe owner/permissions")
    if not p.is_file():
        raise BrokerDenied("configuration must be a regular file")
    return p


def load_config(path: str) -> dict:
    p = trusted_file(path)
    raw = yaml.safe_load(p.read_text()) or {}
    if not isinstance(raw, dict):
        raise BrokerDenied("invalid broker configuration")
    if not isinstance(raw.get("allowed_uids"), list) or any(not isinstance(x, int) or x <= 0 for x in raw["allowed_uids"]):
        raise BrokerDenied("allowed_uids must contain explicit unprivileged numeric identities")
    return raw


def _name(value: Any) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value) or value.startswith("-"):
        raise BrokerDenied("invalid target name")
    return value


def _exact_args(arguments: dict, keys: set[str]) -> None:
    if set(arguments) - keys:
        raise BrokerDenied("unexpected operation arguments")


def _systemd_status(service: str) -> dict:
    text = command("systemctl", "show", service, "--property=Id,ActiveState,SubState,Result,MainPID", "--no-pager")
    data = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    return {"service": service, "active": data.get("ActiveState"), "sub": data.get("SubState"),
            "result": data.get("Result"), "pid": data.get("MainPID"), "verified_at": time.time()}


def _safe_container(container: str) -> dict:
    raw = json.loads(command("docker", "inspect", "--type=container", container))[0]
    host = raw.get("HostConfig", {})
    if host.get("Privileged") or host.get("PidMode") == "host" or host.get("UsernsMode") == "host":
        raise BrokerDenied("privileged or host-process containers cannot be mutated")
    forbidden = {"/", "/etc", "/root", "/proc", "/sys", "/dev", "/var/run/docker.sock", "/run/docker.sock"}
    for mount in raw.get("Mounts", []):
        source = mount.get("Source", "")
        if source in forbidden or any(source.startswith(prefix + "/") for prefix in forbidden - {"/"}) or source.startswith(("/etc/serverhub", "/opt/serverhub", "/var/lib/serverhub", "/run/serverhub")):
            raise BrokerDenied("sensitive mounted paths cannot be mutated")
    return raw


def _wait_container(container: str, timeout: int = 45) -> dict:
    deadline = time.monotonic() + min(max(timeout, 1), 120)
    while True:
        raw = json.loads(command("docker", "inspect", "--type=container", container))[0]
        state = raw.get("State", {})
        health = state.get("Health", {}).get("Status")
        if state.get("Running") and health in {None, "healthy"}:
            return {"container": container, "running": True, "health": health, "verification": "healthcheck" if health else "process_only"}
        if time.monotonic() >= deadline:
            raise CollectionError("container did not recover before health deadline")
        time.sleep(1)


def _compose_file(entry: dict) -> tuple[Path, Path]:
    project = Path(entry.get("path", ""))
    path = trusted_file(project / entry.get("compose_file", "compose.yaml"))
    if path.parent != project or not project.is_absolute():
        raise BrokerDenied("compose path must be direct file in configured project")
    expected = entry.get("sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or not hmac.compare_digest(hashlib.sha256(path.read_bytes()).hexdigest(), expected):
        raise BrokerDenied("compose manifest hash differs from owner-approved version")
    manifest = yaml.safe_load(path.read_text())
    if not isinstance(manifest, dict) or set(manifest) - {"name", "services", "networks", "volumes"}:
        raise BrokerDenied("unsupported compose features")
    services = manifest.get("services")
    if not isinstance(services, dict) or not services:
        raise BrokerDenied("compose services missing")
    # Compose is a powerful root API; deliberately accept a small declarative subset.
    permitted = {"image", "restart", "read_only", "tmpfs", "user", "cap_drop", "security_opt", "ports", "environment", "volumes", "healthcheck", "networks", "depends_on", "mem_limit", "cpus", "pids_limit", "labels", "logging", "command"}
    for name, service in services.items():
        _name(name)
        if not isinstance(service, dict) or set(service) - permitted:
            raise BrokerDenied("compose service uses unsupported privileges/features")
        if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}", str(service.get("image", ""))):
            raise BrokerDenied("compose images must be pinned by digest")
        if service.get("read_only") is not True or service.get("cap_drop") != ["ALL"] or service.get("security_opt") != ["no-new-privileges:true"]:
            raise BrokerDenied("compose services require read_only, cap_drop ALL and no-new-privileges")
        if not re.fullmatch(r"[1-9][0-9]{0,8}(:[1-9][0-9]{0,8})?", str(service.get("user", ""))):
            raise BrokerDenied("compose services require an explicit numeric non-root UID and optional non-root GID")
        if re.search(r"\$(?:[A-Za-z_]|\{)", json.dumps(service).replace("$$", "")):
            raise BrokerDenied("compose interpolation is not accepted")
        for mount in service.get("volumes", []):
            # Named volumes only. Bind mounts, driver options and secrets are not accepted.
            if not isinstance(mount, str) or len(mount.split(":")) not in {2, 3} or not NAME.fullmatch(mount.split(":")[0]):
                raise BrokerDenied("compose permits only named-volume mounts")
        for port in service.get("ports", []):
            if not isinstance(port, str) or not re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}:[0-9]{1,5}(?:/tcp)?", port):
                raise BrokerDenied("compose publishes only explicitly loopback-bound TCP ports")
        health = service.get("healthcheck")
        if not isinstance(health, dict) or not health.get("test") or health.get("disable"):
            raise BrokerDenied("compose requires working healthchecks")
    for spec in (manifest.get("volumes") or {}).values():
        if spec not in (None, {}):
            raise BrokerDenied("custom volume drivers and external volumes are not accepted")
    for spec in (manifest.get("networks") or {}).values():
        if spec not in (None, {}) and spec != {"internal": True}:
            raise BrokerDenied("custom/external networks are not accepted")
    # An adjacent .env could modify the trusted Compose behavior. Never inherit it.
    return project, path


def execute(operation: str, arguments: dict, config: dict) -> dict:
    if operation not in ALLOWED_OPERATIONS | {"inventory.events"} or not isinstance(arguments, dict):
        raise BrokerDenied("operation is not allowlisted")
    if operation == "development.deploy":
        from .staging import deploy
        from .docker_backup import DockerBackupError
        try:
            return deploy(arguments, config)
        except (DockerBackupError, KeyError) as error:
            raise BrokerDenied(str(error)) from error
    if operation == "docker.compose.update":
        from .compose_update import update
        from .docker_backup import DockerBackupError
        try:
            return update(arguments, config)
        except (DockerBackupError, KeyError) as error:
            raise BrokerDenied(str(error)) from error
    if operation.startswith(("package.", "configuration.")):
        from .administration import execute_administration
        from .docker_backup import DockerBackupError
        try:
            return execute_administration(operation, arguments, config)
        except (DockerBackupError, KeyError) as error:
            raise BrokerDenied(str(error)) from error
    if operation.startswith(("docker.backup.", "docker.restore.")):
        from .docker_backup import execute_backup, DockerBackupError
        try:
            return execute_backup(operation, arguments, config)
        except (DockerBackupError, KeyError) as error:
            raise BrokerDenied(str(error)) from error
    if operation in {"inventory.refresh", "discovery.refresh"}:
        _exact_args(arguments, set())
        inventory = discover(privileged=True)
        inventory["caddy"] = {"available": False, "reason": "reviewed caddy_json path not configured", "endpoints": []}
        if config.get("caddy_json"):
            try:
                path = trusted_file(config["caddy_json"])
                if path.stat().st_size > 1024 * 1024:
                    raise BrokerDenied("Caddy JSON exceeds 1 MiB")
                inventory["caddy"] = {"available": True, "endpoints": caddy_endpoints(json.loads(path.read_text()))}
            except (BrokerDenied, OSError, ValueError, TypeError, AttributeError):
                inventory["errors"].append({"collector": "caddy", "error": "Unavailable", "detail": "check protected adapted JSON path and format"})
        inventory["administration"] = {key: sorted(config.get(key, {})) for key in
            ("docker_backup_plans", "package_plans", "configuration_plans", "compose_updates", "staging_projects")}
        operation_state = Path(config.get("operations_state", "/var/lib/serverhub-broker/operations"))
        transactions = []
        for journal in sorted(operation_state.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)[:100]:
            try:
                record = json.loads(trusted_file(journal).read_text())
                transactions.append({"id": journal.stem, **{key: record.get(key) for key in
                    ("kind", "target_name", "state", "deadline", "restored_at")}})
            except (OSError, ValueError, BrokerDenied):
                transactions.append({"id": journal.stem, "state": "unreadable"})
        inventory["administration"]["transactions"] = transactions
        return {"inventory": inventory}
    if operation == "inventory.events":
        _exact_args(arguments, set())
        return docker_events()
    if operation == "diagnostics.storage":
        _exact_args(arguments, {"target"})
        target = _name(arguments.get("target"))
        configured = config.get("storage_targets", {}).get(target)
        if not isinstance(configured, str):
            raise BrokerDenied("storage target is not explicitly allowlisted")
        path = Path(configured)
        if not path.is_absolute() or path.is_symlink() or not path.is_dir():
            raise BrokerDenied("storage target must be an existing absolute directory")
        # The root-selected directory and all ancestors must be trusted. Never
        # accept a user/model path, follow symlinked directories or cross mounts.
        for part in [path, *path.parents]:
            metadata = part.lstat()
            if part.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise BrokerDenied("storage target or ancestor has unsafe ownership/permissions")
        if str(path) in {"/", "/var", "/var/lib", "/opt", "/home"} or any(path.is_relative_to(prefix) for prefix in
                ("/etc", "/root", "/proc", "/sys", "/dev", "/run", "/opt/serverhub", "/var/lib/serverhub", "/var/lib/serverhub-recovery", "/var/backups/serverhub")):
            raise BrokerDenied("sensitive/broad storage targets are not permitted")
        # du may read a large tree: hard deadline/output bound, fixed depth and
        # filesystem, no dereference, no shell or mutation. No size means partial.
        text = command("du", "--one-file-system", "--max-depth=1", "--block-size=1", "--null", "--", str(path), timeout=10)
        entries = []
        for line in text.split("\0"):
            size, separator, name = line.partition("\t")
            if separator and size.isdigit():
                entries.append({"path": name, "allocated_bytes": int(size)})
        return {"target": target, "entries": sorted(entries, key=lambda item: item["allocated_bytes"], reverse=True)[:100],
                "truncated": len(entries) > 100, "source": "du_allocated_bytes_single_filesystem", "verified": True,
                "limitations": "Allocated blocks, not apparent size; excludes other mounted filesystems and symlink traversal"}
    if operation.startswith("systemd."):
        _exact_args(arguments, {"service"})
        service = _name(arguments.get("service"))
        if not service.endswith(".service") or service not in config.get("allowed_services", []):
            raise BrokerDenied("systemd service not explicitly allowlisted")
        if PROTECTED_UNITS.match(service) and operation == "systemd.restart":
            raise BrokerDenied("control-plane, authentication, database and network services are protected")
        if operation == "systemd.status":
            return {**_systemd_status(service), "verified": True}
        if operation == "systemd.logs":
            from serverhub.audit import redact
            output = command("journalctl", "--unit", service, "--lines", "100", "--no-pager", "--output=short-iso", timeout=10)
            return {"service": service, "lines": redact(output[:32000]), "verified": True,
                    "scope": "explicitly permitted unit; last 100 journal lines"}
        before = _systemd_status(service)
        command("systemctl", "restart", service, timeout=45)
        after = _systemd_status(service)
        if after["active"] != "active":
            raise CollectionError("service restart did not verify active state")
        return {"before": before, "after": after, "verification": "systemd_active_state", "verified": True}
    if operation == "docker.restart":
        _exact_args(arguments, {"container"})
        container = _name(arguments.get("container"))
        allowed = config.get("allowed_containers", {})
        if not isinstance(allowed, dict) or container not in allowed:
            raise BrokerDenied("container not explicitly allowlisted with immutable image id")
        before = _safe_container(container)
        expected = allowed[container].get("image_id") if isinstance(allowed[container], dict) else None
        if not expected or before.get("Image") != expected:
            raise BrokerDenied("container image differs from approved image id")
        command("docker", "restart", "--time", "10", container, timeout=45)
        return {**_wait_container(container), "image_id": before.get("Image"), "verified": True}
    if operation == "docker.compose.apply":
        _exact_args(arguments, {"project"})
        name = _name(arguments.get("project"))
        entry = config.get("compose_projects", {}).get(name)
        if not isinstance(entry, dict):
            raise BrokerDenied("compose project not registered by owner")
        project, path = _compose_file(entry)
        # Initial trusted deployments only. Updating existing projects requires a separately
        # rehearsed data backup/recovery policy, not a false claim of Compose transactional rollback.
        prefix = ["compose", "--project-name", name, "--project-directory", str(project), "--env-file", "/dev/null", "-f", str(path)]
        prior = command("docker", *prefix, "ps", "--all", "--quiet")
        if prior.strip():
            raise BrokerDenied("existing Compose projects require controlled release and data backup; auto-update unavailable")
        command("docker", *prefix, "config", "--quiet")
        try:
            command("docker", *prefix, "up", "--detach", "--wait", "--wait-timeout", str(min(int(entry.get("health_timeout", 60)), 120)), timeout=150)
        except CollectionError:
            command("docker", *prefix, "down", "--timeout", "10", timeout=45)
            raise
        return {"project": name, "state": "running", "verification": "compose_wait_health", "manifest_sha256": entry["sha256"], "volumes_preserved_on_failure": True}
    if operation == "diagnostics.network":
        _exact_args(arguments, {"target"})
        key = _name(arguments.get("target"))
        target = config.get("network_targets", {}).get(key)
        if not isinstance(target, dict) or not target.get("host"):
            raise BrokerDenied("network target not configured by owner")
        host = target["host"]
        port = int(target.get("port", 443))
        if not 1 <= port <= 65535:
            raise BrokerDenied("invalid configured port")
        started = time.monotonic()
        try:
            results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = sorted({x[4][0] for x in results})
        except OSError:
            return {"target": key, "dns": "failed", "tcp": "not_tested", "verified": True}
        try:
            with socket.create_connection((host, port), timeout=5):
                pass
            return {"target": key, "dns": "ok", "addresses": addresses, "port": port, "tcp": "connected", "elapsed_ms": round((time.monotonic()-started)*1000), "verified": True}
        except OSError:
            return {"target": key, "dns": "ok", "addresses": addresses, "port": port, "tcp": "failed", "verified": True}
    if operation == "security.scan":
        _exact_args(arguments, {"scanner", "image"})
        scanner = arguments.get("scanner")
        if scanner == "trivy":
            image = arguments.get("image")
            if not isinstance(image, str) or image not in config.get("allowed_scan_images", []):
                raise BrokerDenied("scanner image not allowlisted")
            report = json.loads(command("trivy", "image", "--quiet", "--scanners", "vuln", "--format", "json", "--timeout", "120s", image, timeout=135))
            return {"scanner": "trivy", "target": image, "findings": vulnerability_findings(report, service=image), "coverage": "installed image packages supported by scanner"}
        if scanner == "lynis":
            if not config.get("enable_lynis", False):
                raise BrokerDenied("Lynis scanning is not enabled by owner")
            command("lynis", "audit", "system", "--quick", "--quiet", "--no-colors", timeout=150)
            report_path = Path("/var/log/lynis-report.dat")
            if not report_path.is_file():
                raise CollectionError("Lynis did not create a report")
            data = report_path.read_text()[:4*1024*1024]
            # Return audit warnings/suggestions only, never discovered usernames or file contents.
            warnings = [line.split("=", 1)[1] for line in data.splitlines() if line.startswith("warning[]=")]
            suggestions = [line.split("=", 1)[1] for line in data.splitlines() if line.startswith("suggestion[]=")]
            return {"scanner": "lynis", "warnings": warnings, "suggestions": suggestions, "coverage": "Lynis local configuration audit"}
        raise BrokerDenied("scanner not allowlisted")
    raise BrokerDenied("operation unavailable")


def call_broker(path: str, operation: str, arguments: dict, *, timeout: int = 180, audit_context: dict | None = None) -> dict:
    envelope = {"operation": operation, "arguments": arguments}
    if audit_context is not None:
        envelope["audit_context"] = audit_context
    payload = json.dumps(envelope, separators=(",", ":")).encode()+b"\n"
    if len(payload) > MAX_REQUEST:
        raise BrokerDenied("request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(path)
        client.sendall(payload)
        chunks = []
        size = 0
        while True:
            block = client.recv(65536)
            if not block:
                break
            size += len(block)
            if size > 20*1024*1024:
                raise BrokerDenied("broker response too large")
            chunks.append(block)
            if block.endswith(b"\n"):
                break
    response = json.loads(b"".join(chunks))
    if not response.get("ok"):
        raise BrokerDenied(response.get("error", "broker rejected operation"))
    return response["result"]


class BrokerServer(socketserver.UnixStreamServer):
    allow_reuse_address = False
    def __init__(self, path: str, config: dict):
        self.config = config
        super().__init__(path, BrokerHandler)


def append_broker_audit(config: dict, record: dict) -> None:
    path = Path(config.get("audit_log", "/var/lib/serverhub-broker/audit/events.jsonl"))
    if not path.is_absolute() or path.is_symlink():
        raise BrokerDenied("unsafe audit path")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for parent in [path.parent, *path.parent.parents]:
        metadata = parent.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise BrokerDenied("unsafe broker audit parent")
    from serverhub.audit import redact
    cleaned = redact(record)
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b") as out:
        metadata = os.fstat(out.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise BrokerDenied("broker audit must be a protected root-owned regular file")
        fcntl.flock(out, fcntl.LOCK_EX)
        size = out.seek(0, os.SEEK_END)
        previous = "0" * 64
        if size:
            out.seek(max(0, size - 65536))
            tail = out.read()
            if not tail.endswith(b"\n"):
                raise BrokerDenied("broker audit has an incomplete trailing record")
            last = tail.splitlines()[-1]
            try:
                prior = json.loads(last)
                previous = prior.get("hash") or hashlib.sha256(last).hexdigest()
            except (ValueError, AttributeError):
                raise BrokerDenied("broker audit trailing record is invalid") from None
        body = {"format": 2, "previous_hash": previous, "record": cleaned}
        digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        encoded = json.dumps({**body, "hash": digest}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if len(encoded) > 65536:
            raise BrokerDenied("broker audit record exceeds bound")
        out.seek(0, os.SEEK_END)
        out.write(encoded)
        out.flush()
        os.fsync(out.fileno())


def verify_broker_audit(path: str | Path) -> dict:
    """Read-only integrity check. Root can rewrite the entire chain; export heads externally."""
    previous, count, legacy = "0" * 64, 0, 0
    with Path(path).open("rb") as stream:
        while raw := stream.readline(65537):
            if len(raw) > 65536 or not raw.endswith(b"\n"):
                return {"valid": False, "checked": count, "reason": "incomplete_or_oversize_record"}
            try:
                row = json.loads(raw)
                if row.get("format") != 2:
                    if count != legacy:  # Legacy records may only precede the new chain.
                        raise ValueError()
                    previous = hashlib.sha256(raw.rstrip(b"\n")).hexdigest()
                    legacy += 1
                else:
                    body = {key: row[key] for key in ("format", "previous_hash", "record")}
                    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                    if row["previous_hash"] != previous or not hmac.compare_digest(row["hash"], digest):
                        raise ValueError()
                    previous = digest
            except (ValueError, KeyError, AttributeError, TypeError):
                return {"valid": False, "checked": count, "reason": "broken_chain"}
            count += 1
    return {"valid": True, "checked": count, "legacy_unlinked": legacy, "head": previous}


class BrokerHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.connection.settimeout(10)
        _, uid, _ = struct.unpack("3i", self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        response = {"ok": False, "error": "operation rejected"}
        operation = "invalid"
        execution_id = uuid.uuid4().hex
        context = {}
        privilege = {"peer_uid": uid, "effective_uid": os.geteuid(), "effective_gid": os.getegid(),
                     "adapter": "root_allowlisted_broker", "execution_id": execution_id}
        try:
            if uid not in self.server.config["allowed_uids"]:
                raise BrokerDenied("peer identity is not allowlisted")
            raw = self.rfile.readline(MAX_REQUEST+1)
            if len(raw) > MAX_REQUEST or not raw.endswith(b"\n"):
                raise BrokerDenied("request exceeds frame limit")
            payload = json.loads(raw)
            if not isinstance(payload, dict) or not {"operation", "arguments"} <= set(payload) or set(payload) - {"operation", "arguments", "audit_context"}:
                raise BrokerDenied("invalid request")
            operation = payload["operation"]
            context = payload.get("audit_context", {})
            if not isinstance(context, dict) or any(not isinstance(value, str) or len(value) > 200 for value in context.values()):
                raise BrokerDenied("invalid audit correlation metadata")
            append_broker_audit(self.server.config, {"at": time.time(), "uid": uid,
                                "operation": operation, "arguments": payload["arguments"], "correlation": context,
                                "privilege": privilege, "phase": "before",
                                "broker_contract_sha256": hashlib.sha256(json.dumps(self.server.config,sort_keys=True,default=str).encode()).hexdigest()})
            result = execute(operation, payload["arguments"], self.server.config)
            result["execution_context"] = privilege
            response = {"ok": True, "result": result}
        except Exception as error:
            from serverhub.audit import redact
            # No raw subprocess output or traceback crosses the broker boundary.
            detail = str(error) if isinstance(error, (BrokerDenied, CollectionError, ValueError, OSError, TypeError, KeyError)) else type(error).__name__
            response = {"ok": False, "error": "Broker operation failed: " + str(redact(detail))[:1000]}
        finally:
            try:
                append_broker_audit(self.server.config, {"at": time.time(), "uid": uid,
                                    "operation": operation if isinstance(operation, str) else "invalid",
                                    "phase": "after", "ok": response["ok"], "correlation": context,
                                    "privilege": privilege, "result": {"verified": response.get("result", {}).get("verified"),
                                    "exit_code": 0 if response["ok"] else 1, "exit_code_kind": "structured_adapter",
                                    "effects": {key:value for key,value in response.get("result",{}).items() if key in
                                        {"target","transaction_id","packages","project","backup_id","id","artifact_id","unit","verified","completed","verification"}},
                                    "error": response.get("error")}})
            except (OSError, BrokerDenied) as error:
                logging.getLogger(__name__).error("Protected broker audit unavailable (%s): %s", type(error).__name__, error)
                response = {"ok": False, "error": "protected broker audit unavailable; action outcome uncertain"}
        self.wfile.write(json.dumps(response, separators=(",", ":")).encode()+b"\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/serverhub/broker.yaml")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("broker requires root; only native systemd service should launch it")
    config = load_config(args.config)
    path = Path(config.get("socket", "/run/serverhub-ai-broker/control.sock"))
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if path.exists():
        if not path.is_socket():
            raise SystemExit("refusing to remove non-socket broker path")
        path.unlink()
    with BrokerServer(str(path), config) as server:
        os.chmod(path, 0o660)
        if config.get("socket_gid") is not None:
            os.chown(path, 0, int(config["socket_gid"]))
        try:
            server.serve_forever(poll_interval=0.5)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
