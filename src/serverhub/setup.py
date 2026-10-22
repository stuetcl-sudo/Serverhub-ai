"""Authenticated owner onboarding. AI workers cannot write this configuration."""

from datetime import timedelta
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from .auth import Principal, current_principal, require_owner
from .database import get_db, utcnow
from .models import Host, ModelRoute, Policy, User, to_dict
from .ai.providers import ProviderConfig, ProviderError, load_routes
from .audit import append_audit, redact
from .model_setup import discover_models, test_model

router = APIRouter(prefix="/api", tags=["setup"])


@router.get("/settings/models")
def model_settings(actor: Principal = Depends(current_principal), db=Depends(get_db)):
    require_owner(actor)
    try:
        routes = load_routes()
        saved = {r.name: r for r in db.scalars(select(ModelRoute)).all()}
        return {
            "configured": "default" in routes,
            "editable": True,
            "routes": {name: config.model_dump() for name, config in routes.items()},
            "readiness": {name: row.readiness for name, row in saved.items()},
            "message": "Owner-managed database routes take precedence over the root-owned YAML fallback. Credentials remain environment references.",
        }
    except (ValueError, OSError) as exc:
        return {
            "configured": False,
            "editable": True,
            "routes": {},
            "error": str(exc),
            "message": "Fix the file permission diagnostic or save a database route using Setup.",
        }


@router.post("/settings/models/discover")
def discover(config: ProviderConfig, actor: Principal = Depends(current_principal)):
    require_owner(actor)
    try:
        return {"models": discover_models(config)}
    except ProviderError as exc:
        raise HTTPException(503, str(exc)) from exc


@router.post("/settings/models/test")
def test(config: ProviderConfig, actor: Principal = Depends(current_principal)):
    require_owner(actor)
    try:
        return test_model(config)
    except (ProviderError, ValueError, RuntimeError) as exc:
        raise HTTPException(503, str(exc)) from exc


@router.put("/settings/models/{name}")
def save_model(
    name: str, config: ProviderConfig, actor: Principal = Depends(current_principal), db=Depends(get_db)
):
    require_owner(actor)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
        raise HTTPException(422, "Invalid model route name")
    try:
        readiness = test_model(config)
    except (ProviderError, ValueError, RuntimeError) as exc:
        raise HTTPException(503, str(exc)) from exc
    if not readiness["ready"]:
        raise HTTPException(422, readiness["message"])
    row = db.get(ModelRoute, name)
    if not row:
        row = ModelRoute(name=name, updated_by=actor.id)
        db.add(row)
    row.config, row.enabled, row.updated_by, row.updated_at = config.model_dump(), True, actor.id, utcnow()
    row.readiness = {**readiness, "checked_at": utcnow().isoformat() + "Z"}
    append_audit(
        db,
        actor.id,
        "model.route.saved",
        name,
        {"kind": config.kind, "model": config.model, "endpoint": config.base_url},
    )
    db.commit()
    return {"name": name, "readiness": row.readiness}


PROFILES = {
    "read_only": {
        "name": "Read-only autonomy",
        "description": "Host inventory, CPU/memory/disk, container inspection and fixed diagnostics. Optional service/log targets are explicit.",
    },
    "maintenance": {
        "name": "Maintenance autonomy",
        "description": "Selected service/container restarts and post-change verification. No deletion, arbitrary Compose, firewall, credentials or production release.",
    },
    "development": {
        "name": "Development autonomy",
        "description": "One registered project: workspace, patches, dependencies, tests and configured staging. Production release remains excluded.",
    },
}


@router.get("/policies/profiles")
def profiles(actor: Principal = Depends(current_principal)):
    require_owner(actor)
    return [{"id": key, **value} for key, value in PROFILES.items()]


class ProfileGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: str
    subject_id: str
    host_id: str
    project: str | None = Field(default=None, max_length=200)
    hours: int = Field(default=24, ge=1, le=24 * 366)
    services: list[str] = Field(default_factory=list, max_length=50)
    containers: list[str] = Field(default_factory=list, max_length=50)
    network_targets: list[str] = Field(default_factory=list, max_length=30)
    allow_dependency_network: bool = False


@router.post("/policies/profiles", status_code=201)
def grant_profile(body: ProfileGrant, actor: Principal = Depends(current_principal), db=Depends(get_db)):
    require_owner(actor)
    if body.profile not in PROFILES or not db.get(User, body.subject_id):
        raise HTTPException(422, "Choose a known profile and authenticated account")
    host = db.get(Host, body.host_id)
    if not host or host.revoked:
        raise HTTPException(422, "Choose an enrolled, non-revoked host")
    if any(
        not re.fullmatch(r"[A-Za-z0-9_.@-]{1,160}", value)
        for value in body.services + body.containers + body.network_targets
    ):
        raise HTTPException(422, "Invalid target name")
    if body.profile == "development" and not body.project:
        raise HTTPException(422, "Development profile requires an explicitly registered project")
    if body.profile == "development":
        from .development.config import load_projects

        if body.project not in load_projects():
            raise HTTPException(422, "Project is not registered in the protected project configuration")
    operations = [
        (
            [
                "inventory.read",
                "inventory.query",
                "inventory.refresh",
                "discovery.refresh",
                "task.verify",
                "monitoring.read",
            ],
            {},
            "read",
        )
    ]
    if body.network_targets:
        operations.append((["diagnostics.network"], {"target": body.network_targets}, "read"))
    if body.services:
        operations.append((["systemd.status", "systemd.logs"], {"service_names": body.services}, "read"))
    if body.profile == "maintenance":
        if not (body.services or body.containers):
            raise HTTPException(422, "Maintenance requires at least one explicit service or container")
        if body.services:
            operations.append((["systemd.restart"], {"service_names": body.services}, "maintenance"))
        if body.containers:
            operations.append((["docker.restart"], {"container_names": body.containers}, "maintenance"))
    if body.profile == "development":
        operations.append(
            (
                [
                    "development.workspace",
                    "development.patch",
                    "development.dependencies",
                    "development.test",
                ],
                {},
                "development",
            )
        )
        operations.append((["development.stage"], {}, "staging"))
        if body.allow_dependency_network:
            operations.append((["development.network"], {"phase": ["dependencies"]}, "development"))
    expires = utcnow() + timedelta(hours=body.hours)
    created = []
    for ops, constraints, environment in operations:
        row = Policy(
            name=PROFILES[body.profile]["name"],
            subject_id=body.subject_id,
            host_id=body.host_id,
            project=body.project,
            operations=ops,
            constraints=constraints,
            environment=environment,
            expires_at=expires,
            production=False,
            created_by=actor.id,
        )
        db.add(row)
        db.flush()
        created.append(to_dict(row))
    append_audit(db, actor.id, "policy.profile.granted", body.subject_id, redact(body.model_dump()))
    db.commit()
    return {
        "policies": created,
        "message": "Grant is active without per-tool prompts until expiry. Local broker/project allowlists still apply. Resume a previously blocked job to use it.",
    }


@router.get("/diagnostics")
def diagnostics(actor: Principal = Depends(current_principal), db=Depends(get_db)):
    require_owner(actor)
    from .diagnostics import collect_diagnostics

    return collect_diagnostics(db)
