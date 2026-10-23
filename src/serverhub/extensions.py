"""Controlled job adapters and integration metadata, composed with the core API."""

from __future__ import annotations

import httpx

import hashlib
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from .audit import append_audit, redact
from .auth import Principal, current_principal, require_owner
from .database import get_db
from .jobs import RetryableError, register_handler, submit_job
from .models import Host, Incident, Memory, to_dict
from .node_api import NODE_OPERATIONS, execute_node
from .policy import PermissionDenied, authorize

from .scheduling import router as schedules_router

router = APIRouter(prefix="/api", tags=["operations"])

router.include_router(schedules_router, prefix="")


@router.get("/integrations")
def integrations(actor: Principal = Depends(current_principal)):
    require_owner(actor)
    from .integrations.registry import describe_integrations

    return describe_integrations()


@router.get("/catalog")
def catalog(q: str = "", actor: Principal = Depends(current_principal)):
    require_owner(actor)
    from .catalog import search

    return search(q[:200])


@router.get("/projects")
def projects(actor: Principal = Depends(current_principal), db=Depends(get_db)):
    from .development.config import configured_projects
    rows = []
    for project in configured_projects().values():
        if actor.role != "owner":
            try:
                authorize(db, actor, "development.read", project=project.name)
            except PermissionDenied:
                continue
        rows.append({"name": project.name, "base_ref": project.base_ref,
            "build_steps": len(project.build), "test_steps": len(project.tests),
            "independent_checks": len(project.independent_checks), "staging_checks": len(project.staging_checks),
            "dependency_network": project.allow_dependency_network, "production_deployment": False,
            "execution_location": "controller", "isolation": "bubblewrap", "staging_requires_host": True})
    return rows


@router.post("/projects/jobs/{job_id}/publish")
def publish_development(job_id: str, actor: Principal = Depends(current_principal), db=Depends(get_db)):
    from .api import _job_scope
    from .development.config import configured_projects, DevelopmentError
    from .development.publication import publish_candidate
    job = _job_scope(db, actor, job_id)
    db.refresh(job, with_for_update=True)
    project = configured_projects().get(job.project)
    if job.kind not in {"development", "development_autonomous"} or not project:
        raise HTTPException(422, "Select a verified registered development job")
    authorize(db, actor, "development.publish", project=project.name, arguments={"target":project.name})
    if (job.result or {}).get("publication"):
        return job.result["publication"]
    try:
        publication = publish_candidate(project, job)
    except DevelopmentError as exc:
        raise HTTPException(422, str(exc)) from None
    except httpx.HTTPError:
        raise HTTPException(502, "GitHub publication connection failed; retry this same job to reconcile its candidate branch") from None
    job.result = {**job.result, "publication":publication}
    append_audit(db, actor.id, "development.publish", job.id, publication)
    db.commit()
    return publication


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=16000)
    host_id: str | None = None
    project: str | None = None


@router.post("/chat", status_code=202)
def chat(body: ChatRequest, actor: Principal = Depends(current_principal), db=Depends(get_db)):
    try:
        job = submit_job(
            db, actor, "autonomous", {"prompt": body.prompt}, host_id=body.host_id, project=body.project
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    db.commit()
    return to_dict(job)


class IncidentReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=300)
    host_id: str | None = None
    description: str = Field(default="", max_length=4000)


@router.post("/incidents", status_code=201)
def incident_report(body: IncidentReport, actor: Principal = Depends(current_principal), db=Depends(get_db)):
    authorize(db, actor, "incident.report", body.host_id)
    if body.host_id:
        authorize(db, actor, "inventory.read", body.host_id)
    elif actor.role != "owner":
        raise PermissionDenied("A visible host is required for household reports")
    record = Incident(
        host_id=body.host_id,
        title=body.title,
        evidence={"reported_by": actor.id, "description": redact(body.description), "verified": False},
    )
    db.add(record)
    db.flush()
    append_audit(db, actor.id, "incident.reported", record.id)
    db.commit()
    return to_dict(record)


@router.get("/recovery/status")
def recovery_status(actor: Principal = Depends(current_principal)):
    require_owner(actor)
    status = Path("/var/lib/serverhub-status/backups.json")
    if not status.is_file():
        return {"available": False, "reason": "The independent backup service has not published status"}
    if status.stat().st_size > 1024 * 1024:
        raise HTTPException(503, "Backup status exceeds allowed size")
    return {"available": True, "backups": json.loads(status.read_text())}


def execute_operation(ctx, spec):
    operation, arguments = spec.get("operation", ""), spec.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ValueError("Operation arguments must be an object")
    ctx.require(operation, arguments=arguments, production=bool(spec.get("production", False)))
    key = (
        spec.get("idempotency_key")
        or hashlib.sha256(json.dumps([ctx.job.id, operation, arguments], sort_keys=True).encode()).hexdigest()
    )
    if operation == "host.audit":
        from .host_audit import run_audit
        return run_audit(ctx, arguments)
    if operation in NODE_OPERATIONS:
        return execute_node(ctx, operation, arguments, idempotency_key=key)
    if operation == "catalog.search":
        from .catalog import search

        return {"applications": search(str(arguments.get("query", ""))[:200])}
    if operation == "catalog.plan":
        from .catalog import compose_plan

        return compose_plan(arguments["application"], arguments["image_digest"], int(arguments["port"]))
    if operation == "memory.search":
        authorize(ctx.db, ctx.principal, "inventory.read", ctx.job.host_id)
        if not ctx.job.host_id:
            raise ValueError("Memory retrieval requires a scoped host")
        query = str(arguments.get("query", ""))[:200]
        rows = ctx.db.scalars(
            select(Memory)
            .where(Memory.host_id == ctx.job.host_id, Memory.content.ilike("%" + query + "%"))
            .order_by(Memory.created_at.desc())
            .limit(30)
        )
        return {"memories": [to_dict(row) for row in rows]}
    from .integrations.registry import OPERATIONS, IntegrationError, execute

    adapter = OPERATIONS.get(operation)
    if not adapter:
        raise ValueError("Operation has no installed controlled adapter")
    state = dict(ctx.job.checkpoint or {})
    ledger = dict(state.get("operations", {}))
    previous = ledger.get(key)
    if previous and previous.get("state") == "succeeded":
        return previous["result"]
    if previous and adapter.writes:
        raise RuntimeError(
            "A previous integration write has an uncertain outcome; reconcile its durable checkpoint before retry"
        )

    def persist(data):
        state["operations"] = {
            **ledger,
            key: {"state": "in_flight", "operation": operation, "checkpoint": redact(data)},
        }
        ctx.save_checkpoint(state)

    if adapter.writes:
        persist({"status": "before_external_write"})
    try:
        result = execute(operation, arguments, checkpoint=persist if adapter.writes else None)
    except IntegrationError as exc:
        if exc.retryable and not adapter.writes:
            raise RetryableError(str(exc)) from exc
        raise
    state["operations"] = {**ledger, key: {"state": "succeeded", "operation": operation, "result": result}}
    ctx.save_checkpoint(state)
    return result


def monitor(ctx, spec):
    """Diagnostic procedure; repairs use concrete, policy-gated registered restarts."""
    ctx.require("inventory.read")
    if not ctx.job.host_id:
        raise ValueError("Monitoring requires a host")
    execute_node(ctx, "inventory.refresh", {}, idempotency_key=ctx.job.id + ":monitor:before")
    ctx.db.expire_all()
    host = ctx.db.get(Host, ctx.job.host_id)
    inventory = host.inventory
    remedies = [
        {"operation": "systemd.restart", "arguments": {"service": item["name"]}}
        for item in inventory.get("services", [])
        if item.get("active") == "failed"
    ]
    remedies += [
        {"operation": "docker.restart", "arguments": {"container": item["name"]}}
        for item in inventory.get("docker", {}).get("containers", [])
        if item.get("health") == "unhealthy"
    ]
    results = []
    if spec.get("repair"):
        ctx.require("monitoring.repair")
        for index, remedy in enumerate(remedies[:10]):
            # Reauthorization and the independent broker's local allowlist both apply.
            outcome = execute_operation(
                ctx, {**remedy, "idempotency_key": ctx.job.id + ":repair:" + str(index)}
            )
            results.append({**remedy, "outcome": outcome})
        execute_node(ctx, "inventory.refresh", {}, idempotency_key=ctx.job.id + ":monitor:after")
        ctx.db.expire_all()
        inventory = ctx.db.get(Host, ctx.job.host_id).inventory
        for item in results:
            arg = item["arguments"]
            if "service" in arg:
                observed = next(
                    (x for x in inventory.get("services", []) if x.get("name") == arg["service"]), {}
                )
                item["verified"] = observed.get("active") == "active"
            else:
                observed = next(
                    (
                        x
                        for x in inventory.get("docker", {}).get("containers", [])
                        if x.get("name") == arg["container"]
                    ),
                    {},
                )
                item["verified"] = observed.get("health") == "healthy"
            ctx.db.add(
                Memory(
                    host_id=ctx.job.host_id,
                    kind="remediation",
                    content=item["operation"],
                    evidence=redact(item),
                    verified=bool(item["verified"]),
                    success=bool(item["verified"]),
                )
            )
        ctx.db.commit()
    return {
        "source": "fresh_agent_inventory",
        "suggested_procedures": remedies,
        "repairs": results,
        "verified": all(item.get("verified") for item in results) if results else False,
        "scope": "failed allowlisted services/unhealthy containers; no speculative deletion or resource tuning",
    }


def register():
    register_handler("operation", execute_operation)
    register_handler("monitoring", monitor)
