import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from starlette.responses import StreamingResponse

from .audit import append_audit, verify_chain
from .auth import (Authenticated, PASSWORDS, _DUMMY_HASH, create_session, hash_password,
                   hash_secret, request_token, require_owner, token_principal,
                   verify_password)
from .database import SessionLocal, get_db, utcnow
from .jobs import TERMINAL, submit_job
from .models import (Audit, Backup, Finding, GraphEdge, Host, Incident, InventorySample,
                     Job, JobEvent, Memory, Policy, SessionToken, SystemState, User, to_dict)
from .policy import authorize, visible_host_ids
from .settings import get_settings

router = APIRouter(prefix="/api")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(StrictModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


class NewUser(StrictModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{1,100}$")
    password: str = Field(min_length=14, max_length=1024)
    role: Literal["owner", "administrator", "adult", "user", "readonly"] = "readonly"


class UserUpdate(StrictModel):
    role: Literal["owner", "administrator", "adult", "user", "readonly"] | None = None
    enabled: bool | None = None
    password: str | None = Field(default=None, min_length=14, max_length=1024)


class NewPolicy(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    subject_id: str | None = None
    role: Literal["owner", "administrator", "adult", "user", "readonly"] | None = None
    host_id: str | None = None
    project: str | None = Field(default=None, max_length=200)
    operations: list[str] = Field(min_length=1, max_length=100)
    constraints: dict = Field(default_factory=dict)
    expires_at: datetime
    environment: Literal["any", "read", "maintenance", "development", "staging", "production"] = "any"
    production: bool = False

    @field_validator("operations")
    @classmethod
    def valid_operations(cls, value):
        if any(not re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*(?:\.\*)?", operation) for operation in value):
            raise ValueError("capabilities must be exact operation names or explicit prefix.*")
        return value


class PolicyUpdate(StrictModel):
    enabled: bool


class NewJob(StrictModel):
    kind: str = Field(min_length=1, max_length=60)
    spec: dict
    host_id: str | None = None
    project: str | None = Field(default=None, max_length=200)
    parent_id: str | None = None
    depends_on: list[str] = Field(default_factory=list, max_length=100)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)
    run_after: datetime | None = None
    max_attempts: int = Field(default=3, ge=1, le=10)
    time_limit: int = Field(default=3600, ge=1, le=86400)
    token_budget: int = Field(default=20000, ge=0, le=2_000_000)
    cost_budget: float = Field(default=1.0, ge=0, le=1000, allow_inf_nan=False)


class Emergency(StrictModel):
    enabled: bool
    reason: str = Field(min_length=1, max_length=1000)


def _utc(value):
    if value and value.tzinfo:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _user_dict(user):
    return {"id": user.id, "username": user.username, "role": user.role, "enabled": user.enabled}


def _job_scope(db, principal, job_id):
    job = db.get(Job, job_id)
    if not job or (job.owner_id != principal.id and principal.role != "owner"):
        raise HTTPException(404, "Job not found")
    return job


def _host_scope(db, principal, host_id):
    authorize(db, principal, "inventory.read", host_id)
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    return host


def _host_dict(host):
    result = to_dict(host, {"agent_secret_hash"})
    result["online"] = bool(host.last_seen and not host.revoked and
                            (utcnow() - host.last_seen).total_seconds() < get_settings().offline_seconds)
    return result


@router.post("/auth/login")
def login(body: Login, request: Request, response: Response, db=Depends(get_db)):
    settings = get_settings()
    user = db.scalar(select(User).where(User.username == body.username).with_for_update())
    now = utcnow()
    # Same expensive verification for absent/disabled/locked users limits account enumeration.
    encoded = user.password_hash if user else _DUMMY_HASH
    verified = verify_password(body.password, encoded)
    locked = bool(user and user.locked_until and user.locked_until > now)
    if not user or not verified or not user.enabled or locked:
        if user and not locked:
            user.failed_logins += 1
            if user.failed_logins >= settings.login_failures:
                user.locked_until = now + timedelta(seconds=settings.login_lock_seconds)
            append_audit(db, "authentication", "login.failed", user.id)
            db.commit()
        raise HTTPException(401, "Invalid credentials or account temporarily unavailable")
    user.failed_logins = 0
    user.locked_until = None
    if PASSWORDS.check_needs_rehash(user.password_hash):
        user.password_hash = PASSWORDS.hash(body.password)
    token = create_session(db, user)
    append_audit(db, user.id, "login.succeeded", user.id)
    db.commit()
    local_tunnel = (request.url.scheme == "http" and request.url.hostname in {"localhost", "127.0.0.1", "::1"}
                    and request.client and request.client.host in {"localhost", "127.0.0.1", "::1"})
    response.set_cookie("serverhub_session", token, httponly=True, secure=not settings.dev_mode and not local_tunnel,
                        samesite="strict", max_age=settings.session_hours * 3600, path="/")
    response.headers["Cache-Control"] = "no-store"
    return {"token": token, "user": _user_dict(user)}


@router.get("/auth/me")
def me(principal: Authenticated):
    return {"id": principal.id, "username": principal.username, "role": principal.role}


@router.post("/auth/logout")
def logout(request: Request, response: Response, principal: Authenticated, db=Depends(get_db)):
    token = db.scalar(select(SessionToken).where(SessionToken.digest == hash_secret(request_token(request))))
    if token:
        token.revoked = True
    append_audit(db, principal.id, "logout", principal.id)
    db.commit()
    response.delete_cookie("serverhub_session", path="/", secure=not get_settings().dev_mode, httponly=True, samesite="strict")
    return {"ok": True}


@router.get("/users")
def users(principal: Authenticated, db=Depends(get_db)):
    require_owner(principal)
    return [_user_dict(user) for user in db.scalars(select(User).order_by(User.username)).all()]


@router.post("/users", status_code=201)
def add_user(body: NewUser, principal: Authenticated, db=Depends(get_db)):
    require_owner(principal)
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    try:
        db.flush()
        append_audit(db, principal.id, "user.create", user.id, {"username": user.username, "role": user.role})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Username already exists")
    return _user_dict(user)


@router.patch("/users/{user_id}")
def update_user(user_id: str, body: UserUpdate, principal: Authenticated, db=Depends(get_db)):
    require_owner(principal)
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == principal.id and ((body.role and body.role != "owner") or body.enabled is False):
        raise HTTPException(409, "The active owner cannot disable or demote their own account")
    if body.role:
        user.role = body.role
    if body.enabled is not None:
        user.enabled = body.enabled
    if body.password:
        user.password_hash = hash_password(body.password)
    # Any authorization change invalidates every active session for the affected identity.
    for token in db.scalars(select(SessionToken).where(SessionToken.user_id == user.id)).all():
        token.revoked = True
    append_audit(db, principal.id, "user.update", user.id, body.model_dump(exclude_unset=True))
    db.commit()
    return _user_dict(user)


@router.get("/hosts")
def hosts(principal: Authenticated, db=Depends(get_db)):
    ids = visible_host_ids(db, principal)
    return [_host_dict(host) for host in db.scalars(select(Host).where(Host.id.in_(ids)).order_by(Host.name)).all()]


@router.get("/hosts/{host_id}")
def host(host_id: str, principal: Authenticated, db=Depends(get_db)):
    return _host_dict(_host_scope(db, principal, host_id))


@router.get("/hosts/{host_id}/inventory")
def host_inventory(host_id: str, principal: Authenticated, db=Depends(get_db)):
    host = _host_scope(db, principal, host_id)
    return host.inventory


@router.get("/hosts/{host_id}/metrics")
def host_metrics(host_id: str, principal: Authenticated, limit: int = 120, db=Depends(get_db)):
    _host_scope(db, principal, host_id)
    return [to_dict(row) for row in db.scalars(select(InventorySample).where(InventorySample.host_id == host_id)
                                              .order_by(InventorySample.id.desc()).limit(min(max(limit, 1), 1000))).all()]


@router.get("/topology")
def topology(principal: Authenticated, db=Depends(get_db)):
    ids = visible_host_ids(db, principal)
    nodes = [{"id": host.id, "label": host.name, "type": "host", "online": _host_dict(host)["online"]}
             for host in db.scalars(select(Host).where(Host.id.in_(ids))).all()]
    edges = [to_dict(edge) for edge in db.scalars(select(GraphEdge).where(GraphEdge.host_id.in_(ids))).all()]
    return {"nodes": nodes, "edges": edges}


@router.get("/overview")
def overview(principal: Authenticated, db=Depends(get_db)):
    ids = visible_host_ids(db, principal)
    scoped_hosts = db.scalars(select(Host).where(Host.id.in_(ids))).all()
    job_filter = [] if principal.role == "owner" else [Job.owner_id == principal.id]
    job_counts = dict(db.execute(select(Job.state, func.count()).where(*job_filter).group_by(Job.state)).all())
    finding_counts = dict(db.execute(select(Finding.severity, func.count()).where(Finding.host_id.in_(ids), Finding.status == "open")
                                     .group_by(Finding.severity)).all())
    emergency = db.get(SystemState, "emergency_stop")
    return {"hosts": len(scoped_hosts), "online_hosts": sum(_host_dict(h)["online"] for h in scoped_hosts),
            "jobs": job_counts, "findings": finding_counts,
            "incidents": db.scalar(select(func.count()).select_from(Incident).where(Incident.host_id.in_(ids), Incident.state == "open")),
            "emergency_stop": emergency.value if emergency else {"enabled": False},
            "generated_at": utcnow().isoformat() + "Z"}


@router.get("/jobs")
def jobs(principal: Authenticated, limit: int = 100, offset: int = 0, db=Depends(get_db)):
    query = select(Job)
    if principal.role != "owner":
        query = query.where(Job.owner_id == principal.id)
    return [to_dict(job) for job in db.scalars(query.order_by(Job.created_at.desc()).offset(max(offset, 0))
                                              .limit(min(max(limit, 1), 1000))).all()]


@router.post("/jobs", status_code=202)
def add_job(body: NewJob, principal: Authenticated, db=Depends(get_db)):
    data = body.model_dump()
    data["run_after"] = _utc(body.run_after)
    if len(json.dumps(body.spec, default=str)) > 200_000:
        raise HTTPException(413, "Job specification too large")
    try:
        job = submit_job(db, principal, **data)
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(422, str(exc))
    except IntegrityError:
        db.rollback()
        if body.idempotency_key:
            existing = db.scalar(select(Job).where(Job.owner_id == principal.id, Job.idempotency_key == body.idempotency_key))
            if existing and (existing.kind, existing.spec, existing.host_id, existing.project) == (body.kind, body.spec, body.host_id, body.project):
                return to_dict(existing)
        raise HTTPException(409, "Job idempotency conflict")
    return to_dict(job)


@router.get("/jobs/{job_id}")
def job(job_id: str, principal: Authenticated, db=Depends(get_db)):
    return to_dict(_job_scope(db, principal, job_id))


@router.get("/jobs/{job_id}/events")
def job_events(job_id: str, principal: Authenticated, after: int = 0, db=Depends(get_db)):
    _job_scope(db, principal, job_id)
    return [to_dict(event) for event in db.scalars(select(JobEvent).where(JobEvent.job_id == job_id, JobEvent.id > after)
                                                  .order_by(JobEvent.id).limit(1000)).all()]


@router.post("/jobs/{job_id}/{action}")
def job_action(job_id: str, action: Literal["pause", "resume", "cancel"], principal: Authenticated, db=Depends(get_db)):
    job = _job_scope(db, principal, job_id)
    if job.state in TERMINAL:
        raise HTTPException(409, "Job has already finished")
    if action == "pause":
        job.state = "pause_requested" if job.state == "running" else "paused"
    elif action == "cancel":
        job.state = "cancel_requested" if job.state in {"running", "pause_requested"} else "cancelled"
        if job.state == "cancelled":
            job.finished_at = utcnow()
    elif action == "resume":
        if job.state not in {"paused", "waiting_approval"}:
            raise HTTPException(409, "Only paused or policy-blocked jobs can resume")
        authorize(db, principal, "job.submit", job.host_id, job.project)
        job.state = "queued"
        job.run_after = utcnow()
    append_audit(db, principal.id, "job." + action, job.id)
    db.add(JobEvent(job_id=job.id, message="Operator requested " + action, data={"actor": principal.id}))
    db.commit()
    return to_dict(job)


@router.get("/policies")
def policies(principal: Authenticated, db=Depends(get_db)):
    require_owner(principal)
    return [to_dict(p) for p in db.scalars(select(Policy).order_by(Policy.created_at.desc())).all()]


@router.post("/policies", status_code=201)
def add_policy(body: NewPolicy, principal: Authenticated, db=Depends(get_db)):
    require_owner(principal)
    if bool(body.subject_id) == bool(body.role):
        raise HTTPException(422, "Choose exactly one subject_id or role")
    expires = _utc(body.expires_at)
    if expires <= utcnow() or expires > utcnow() + timedelta(days=366):
        raise HTTPException(422, "Policy expiry must be in the next 366 days")
    if body.subject_id and not db.get(User, body.subject_id):
        raise HTTPException(422, "Unknown policy subject")
    if body.host_id and not db.get(Host, body.host_id):
        raise HTTPException(422, "Unknown target host")
    if body.production and not body.constraints:
        raise HTTPException(422, "Production policies require explicit target constraints")
    if any(key.startswith("max_") and (isinstance(value, bool) or not isinstance(value, (int, float)))
           for key, value in body.constraints.items()):
        raise HTTPException(422, "max_ constraints require numeric ceilings")
    policy = Policy(**{**body.model_dump(), "expires_at": expires}, created_by=principal.id)
    db.add(policy)
    db.flush()
    append_audit(db, principal.id, "policy.create", policy.id, body.model_dump())
    db.commit()
    return to_dict(policy)


@router.patch("/policies/{policy_id}")
def update_policy(policy_id: str, body: PolicyUpdate, principal: Authenticated, db=Depends(get_db)):
    require_owner(principal)
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(404, "Policy not found")
    policy.enabled = body.enabled
    append_audit(db, principal.id, "policy.enable" if body.enabled else "policy.revoke", policy.id)
    db.commit()
    return to_dict(policy)


@router.get("/findings")
def findings(principal: Authenticated, db=Depends(get_db)):
    ids = visible_host_ids(db, principal)
    return [to_dict(row) for row in db.scalars(select(Finding).where(Finding.host_id.in_(ids)).order_by(Finding.last_seen.desc()).limit(1000)).all()]


@router.get("/incidents")
def incidents(principal: Authenticated, db=Depends(get_db)):
    ids = visible_host_ids(db, principal)
    query = select(Incident)
    if principal.role != "owner":
        query = query.where(Incident.host_id.in_(ids))
    return [to_dict(row) for row in db.scalars(query.order_by(Incident.created_at.desc()).limit(1000)).all()]


@router.get("/memory")
def memory(principal: Authenticated, q: str = "", db=Depends(get_db)):
    ids = visible_host_ids(db, principal)
    query = select(Memory)
    if principal.role != "owner":
        query = query.where(Memory.host_id.in_(ids))
    if q:
        query = query.where(Memory.content.ilike("%" + q[:200].replace("%", "\\%").replace("_", "\\_") + "%", escape="\\"))
    return [to_dict(row) for row in db.scalars(query.order_by(Memory.created_at.desc()).limit(500)).all()]


@router.get("/backups")
def backups(principal: Authenticated, db=Depends(get_db)):
    require_owner(principal)
    return [to_dict(row) for row in db.scalars(select(Backup).order_by(Backup.created_at.desc()).limit(500)).all()]


@router.get("/audit")
def audit(principal: Authenticated, limit: int = 200, db=Depends(get_db)):
    require_owner(principal)
    return [to_dict(row) for row in db.scalars(select(Audit).order_by(Audit.id.desc()).limit(min(max(limit, 1), 1000))).all()]


@router.get("/audit/verify")
def audit_verify(principal: Authenticated, db=Depends(get_db)):
    require_owner(principal)
    return verify_chain(db)


@router.get("/emergency-stop")
def emergency_status(principal: Authenticated, db=Depends(get_db)):
    row = db.get(SystemState, "emergency_stop")
    return row.value if row else {"enabled": False}


@router.post("/emergency-stop")
def emergency_stop(body: Emergency, principal: Authenticated, db=Depends(get_db)):
    require_owner(principal)
    value = {"enabled": body.enabled, "reason": body.reason, "actor": principal.id, "at": utcnow().isoformat() + "Z"}
    row = db.get(SystemState, "emergency_stop")
    if row:
        row.value = value
    else:
        db.add(SystemState(key="emergency_stop", value=value))
    append_audit(db, principal.id, "emergency.stop" if body.enabled else "emergency.clear", data=value)
    db.commit()
    return value


@router.get("/events")
def events(request: Request, principal: Authenticated):
    token = request_token(request)
    async def generate():
        while not await request.is_disconnected():
            with SessionLocal() as db:
                try:
                    current = token_principal(db, token)
                except HTTPException:
                    yield 'event: expired\ndata: {"expired":true}\n\n'
                    return
                query = select(Job.state, func.count()).group_by(Job.state)
                if current.role != "owner":
                    query = query.where(Job.owner_id == current.id)
                payload = {"jobs": dict(db.execute(query).all()), "at": utcnow().isoformat() + "Z"}
            yield "event: update\ndata: " + json.dumps(payload) + "\n\n"
            await asyncio.sleep(3)
    return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
