"""Agent control plane. Nodes pull bounded, reauthorized, durable commands over TLS.

The API never connects to a Docker socket or accepts a command-line string.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select

from .audit import append_audit, redact
from .auth import Principal, current_principal, hash_secret, principal_for_user, require_owner
from .database import get_db, utcnow
from .models import AgentCommand, Enrollment, Host, Job, SystemState, User
from .policy import PermissionDenied, authorize
from .settings import get_settings

router = APIRouter(prefix="/api", tags=["nodes"])
NODE_OPERATIONS = frozenset(
    {
        "inventory.refresh",
        "discovery.refresh",
        "diagnostics.network", "diagnostics.storage",
        "security.scan",
        "systemd.status", "systemd.logs",
        "systemd.restart",
        "docker.restart",
        "package.plan", "package.apply", "configuration.plan", "configuration.apply",
        "development.deploy", "docker.compose.update", "docker.compose.apply", "docker.backup.create", "docker.backup.list", "docker.backup.verify", "docker.restore.plan", "docker.restore.apply",
    }
)
READ_OPERATIONS = frozenset(
    {"inventory.refresh", "discovery.refresh", "diagnostics.network", "security.scan", "systemd.status", "systemd.logs", "package.plan", "configuration.plan", "docker.backup.list", "docker.backup.verify", "docker.restore.plan"}
)


class EnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    group_name: str = Field(default="default", min_length=1, max_length=100)
    ttl_seconds: int = Field(default=900, ge=60, le=3600)


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=24, max_length=256)
    name: str = Field(min_length=1, max_length=200)
    identity: str = Field(min_length=1, max_length=200)


def current_node(request: Request, db=Depends(get_db)) -> Host:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer ") or len(header) > 1024:
        raise HTTPException(401, "Individual node identity required")
    node = db.scalar(select(Host).where(Host.agent_secret_hash == hash_secret(header[7:])))
    if not node or node.revoked:
        raise HTTPException(401, "Unknown or revoked node identity")
    return node


@router.post("/nodes/enrollment", status_code=201)
def create_enrollment(
    body: EnrollmentRequest, actor: Principal = Depends(current_principal), db=Depends(get_db)
):
    require_owner(actor)
    token = secrets.token_urlsafe(48)
    expires = utcnow() + timedelta(seconds=body.ttl_seconds)
    db.add(
        Enrollment(
            digest=hash_secret(token),
            name=body.name,
            group_name=body.group_name,
            expires_at=expires,
            created_by=actor.id,
        )
    )
    append_audit(db, actor.id, "node.enrollment.created", body.name, {"expires_at": expires})
    db.commit()
    return {"token": token, "expires_at": expires.isoformat() + "Z", "name": body.name}


@router.post("/nodes/enroll", status_code=201)
def enroll(body: EnrollRequest, db=Depends(get_db)):
    enrollment = db.scalar(
        select(Enrollment).where(Enrollment.digest == hash_secret(body.token)).with_for_update()
    )
    if not enrollment or enrollment.used_at or enrollment.expires_at <= utcnow():
        raise HTTPException(401, "Invalid, expired, or consumed enrollment token")
    # The owner-selected name/group is authoritative; nodes cannot choose their policy group.
    if enrollment.name != body.name:
        raise HTTPException(400, "Node name must match its enrollment")
    secret = secrets.token_urlsafe(48)
    node = Host(
        name=enrollment.name,
        group_name=enrollment.group_name,
        identity=body.identity,
        agent_secret_hash=hash_secret(secret),
        last_seen=utcnow(),
    )
    db.add(node)
    enrollment.used_at = utcnow()
    db.flush()
    append_audit(db, "node:" + node.id, "node.enrolled", node.id, {"group": node.group_name})
    db.commit()
    return {"host_id": node.id, "token": secret, "report_interval": 60}


@router.post("/hosts/{host_id}/revoke")
def revoke(host_id: str, actor: Principal = Depends(current_principal), db=Depends(get_db)):
    require_owner(actor)
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    host.revoked = True
    for cmd in db.scalars(
        select(AgentCommand).where(
            AgentCommand.host_id == host_id, AgentCommand.state.in_(["queued", "leased"])
        )
    ):
        cmd.state, cmd.result = "failed", {"error": "Node revoked"}
    append_audit(db, actor.id, "node.revoked", host_id)
    db.commit()
    return {"id": host_id, "revoked": True}


@router.post("/nodes/report")
async def report(request: Request, node: Host = Depends(current_node), db=Depends(get_db)):
    raw = await request.body()
    if len(raw) > get_settings().max_inventory_bytes:
        raise HTTPException(413, "Inventory exceeds configured limit")
    try:
        body = json.loads(raw)
        inventory = body["inventory"]
        if not isinstance(inventory, dict) or not isinstance(inventory.get("os", {}), dict):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise HTTPException(422, "Expected an inventory object") from None
    from .telemetry import ingest_inventory

    try:
        ingest_inventory(db, node, inventory)
    except (ValueError, TypeError, AttributeError, KeyError):
        db.rollback()
        raise HTTPException(422, "Malformed inventory observation") from None
    node.agent_version = str(body.get("agent_version", ""))[:50]
    db.commit()
    return {"accepted": True, "host_id": node.id, "observed_at": node.last_seen.isoformat() + "Z"}


@router.post("/nodes/heartbeat")
def heartbeat(node: Host = Depends(current_node), db=Depends(get_db)):
    node.last_seen = utcnow()
    db.commit()
    return {"ok": True}


def _command_authorized(db, command: AgentCommand):
    job = db.get(Job, command.job_id) if command.job_id else None
    if not job or job.state not in {"running", "queued", "retry"}:
        raise PermissionDenied("Originating job is no longer active")
    user = db.get(User, job.owner_id)
    if not user or not user.enabled:
        raise PermissionDenied("Originating account disabled")
    if command.operation not in NODE_OPERATIONS:
        raise PermissionDenied("Unsupported node operation")
    authorize(
        db,
        principal_for_user(user),
        command.operation,
        host_id=command.host_id,
        project=job.project,
        arguments=command.arguments,
    )
    emergency = db.get(SystemState, "emergency_stop")
    if emergency and emergency.value.get("enabled") and command.operation not in READ_OPERATIONS:
        raise PermissionDenied("Emergency stop is active")


@router.get("/nodes/commands")
def commands(node: Host = Depends(current_node), db=Depends(get_db)):
    now = utcnow()
    node.last_seen = now
    rows = db.scalars(
        select(AgentCommand)
        .where(
            AgentCommand.host_id == node.id,
            or_(
                AgentCommand.state == "queued",
                (AgentCommand.state == "leased") & (AgentCommand.lease_until < now),
            ),
        )
        .order_by(AgentCommand.created_at)
        .limit(4)
        .with_for_update(skip_locked=True)
    ).all()
    result = []
    for command in rows:
        try:
            if command.expires_at <= now:
                raise PermissionDenied("Command deadline expired")
            _command_authorized(db, command)
        except (PermissionDenied, HTTPException) as exc:
            command.state = "failed"
            command.result = {"error": str(exc), "failure_class": "authorization"}
            continue
        command.state, command.lease_until = "leased", now + timedelta(seconds=60)
        command.attempts += 1
        result.append(
            {
                "id": command.id,
                "audit_context": {"command_id": command.id, "job_id": command.job_id, "host_id": node.id,
                                  "operator_id": db.get(Job, command.job_id).owner_id},
                "operation": command.operation,
                "arguments": command.arguments,
                "idempotency_key": command.idempotency_key,
                "expires_at": command.expires_at.isoformat() + "Z",
            }
        )
    db.commit()
    return result


class CommandResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: str = Field(pattern="^(succeeded|failed)$")
    result: dict


@router.post("/nodes/commands/{command_id}/result")
def command_result(
    command_id: str, body: CommandResult, node: Host = Depends(current_node), db=Depends(get_db)
):
    command = db.scalar(
        select(AgentCommand)
        .where(AgentCommand.id == command_id, AgentCommand.host_id == node.id)
        .with_for_update()
    )
    if not command:
        raise HTTPException(404, "Command not found for this node")
    if len(json.dumps(body.result, default=str)) > get_settings().max_inventory_bytes:
        raise HTTPException(413, "Command result exceeds configured limit")
    if command.state in {"succeeded", "failed"}:
        # A duplicate report is acknowledged, never replaces an already committed outcome.
        return {"accepted": True, "duplicate": True, "state": command.state}
    if command.state != "leased":
        raise HTTPException(409, "Command has not been dispatched")
    command.state, command.result, command.lease_until = body.state, redact(body.result), None
    node.last_seen = utcnow()
    if body.state == "succeeded" and command.operation in {"inventory.refresh", "discovery.refresh"}:
        inventory = body.result.get("inventory", body.result)
        if isinstance(inventory, dict) and "os" in inventory:
            from .telemetry import ingest_inventory

            ingest_inventory(db, node, inventory)
    if body.state == "succeeded" and command.operation == "security.scan":
        from .telemetry import ingest_scanner_result

        ingest_scanner_result(db, node, body.result)
    append_audit(
        db,
        "node:" + node.id,
        "node.command." + body.state,
        command.id,
        {"operation": command.operation, "job_id": command.job_id, "host_id": node.id,
         "operator_id": db.get(Job, command.job_id).owner_id, "arguments": command.arguments,
         "execution_context": body.result.get("execution_context"), "result": body.result},
    )
    db.commit()
    return {"accepted": True, "state": body.state}


def dispatch_command(
    db,
    host_id: str,
    operation: str,
    arguments: dict,
    job_id: str,
    *,
    idempotency_key: str | None = None,
    timeout: int = 3600,
) -> AgentCommand:
    if operation not in NODE_OPERATIONS:
        raise PermissionDenied("Node operation is not in the compiled allowlist")
    job = db.get(Job, job_id)
    if not job or job.host_id != host_id:
        raise PermissionDenied("Node commands must target the originating job's host")
    # A deterministic key makes process-restart retries converge on the same command.
    key = (
        idempotency_key
        or hashlib.sha256(json.dumps([job_id, operation, arguments], sort_keys=True).encode()).hexdigest()
    )
    existing = db.scalar(
        select(AgentCommand).where(AgentCommand.host_id == host_id, AgentCommand.idempotency_key == key)
    )
    if existing:
        if existing.operation != operation or existing.arguments != arguments or existing.job_id != job_id:
            raise ValueError("Idempotency key already belongs to a different command")
        return existing
    command = AgentCommand(
        host_id=host_id,
        job_id=job_id,
        operation=operation,
        arguments=arguments,
        idempotency_key=key,
        expires_at=utcnow() + timedelta(seconds=min(timeout, 3600)),
    )
    _command_authorized(db, command)
    db.add(command)
    db.flush()
    append_audit(
        db, job.owner_id, "node.command.queued", command.id, {"operation": operation, "job_id": job_id}
    )
    db.commit()
    return command


def execute_node(ctx, operation: str, arguments: dict, *, idempotency_key: str | None = None) -> dict:
    """Job helper: durable command dispatch, result polling, cancellation and live policy checks."""
    ctx.require(operation, arguments=arguments)
    if not ctx.job.host_id:
        raise ValueError("A target host is required")
    command = dispatch_command(
        ctx.db, ctx.job.host_id, operation, arguments, ctx.job.id, idempotency_key=idempotency_key
    )
    ctx.log("Waiting for node command", {"command_id": command.id, "operation": operation})
    while True:
        ctx.check_cancelled()
        ctx.require(operation, arguments=arguments)
        ctx.heartbeat()
        ctx.db.refresh(command)
        if command.state == "succeeded":
            return command.result
        if command.state == "failed":
            raise RuntimeError("Node command failed: " + str(command.result.get("error", "see node result")))
        if command.expires_at <= utcnow():
            raise TimeoutError(
                "Node did not complete its command before the deadline; inspect its journal before retry"
            )
        time.sleep(0.5)
