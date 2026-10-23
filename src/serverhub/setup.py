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
    host_id: str | None = None
    allow_staging: bool = False
    allow_publication: bool = False
    project: str | None = Field(default=None, max_length=200)
    hours: int = Field(default=24, ge=1, le=24 * 366)
    services: list[str] = Field(default_factory=list, max_length=50)
    containers: list[str] = Field(default_factory=list, max_length=50)
    storage_targets: list[str] = Field(default_factory=list, max_length=20)
    backup_targets: list[str] = Field(default_factory=list, max_length=20)
    package_targets: list[str] = Field(default_factory=list, max_length=20)
    configuration_targets: list[str] = Field(default_factory=list, max_length=20)
    compose_targets: list[str] = Field(default_factory=list, max_length=20)
    network_targets: list[str] = Field(default_factory=list, max_length=30)
    allow_dependency_network: bool = False


@router.post("/policies/profiles", status_code=201)
def grant_profile(body: ProfileGrant, actor: Principal = Depends(current_principal), db=Depends(get_db)):
    require_owner(actor)
    if body.profile not in PROFILES or not db.get(User, body.subject_id):
        raise HTTPException(422, "Choose a known profile and authenticated account")
    host = db.get(Host, body.host_id) if body.host_id else None
    if (body.profile != "development" or body.host_id or body.allow_staging) and (not host or host.revoked):
        raise HTTPException(422, "Choose an enrolled, non-revoked host; controller-only development needs no host")
    if any(
        not re.fullmatch(r"[A-Za-z0-9_.@-]{1,160}", value)
        for value in body.services + body.containers + body.network_targets + body.storage_targets + body.backup_targets + body.package_targets + body.configuration_targets + body.compose_targets
    ):
        raise HTTPException(422, "Invalid target name")
    if body.profile == "development" and not body.project:
        raise HTTPException(422, "Development profile requires an explicitly registered project")
    if body.profile == "development":
        if any((body.services, body.containers, body.storage_targets, body.network_targets, body.backup_targets, body.package_targets, body.configuration_targets, body.compose_targets)):
            raise HTTPException(422, "Development grants cannot include infrastructure targets; create a separate host-scoped profile")
        from .development.config import configured_projects

        project_contract = configured_projects().get(body.project)
        if project_contract is None:
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
                "host.audit",
            ],
            {},
            "read",
        )
    ]
    if body.profile == "development":
        operations = []
    if body.storage_targets:
        operations.append((["diagnostics.storage"], {"target": body.storage_targets}, "read"))
    if body.network_targets:
        operations.append((["diagnostics.network"], {"target": body.network_targets}, "read"))
    if body.services:
        operations.append((["systemd.status", "systemd.logs"], {"service_names": body.services}, "read"))
    if body.backup_targets:
        operations.append((["docker.backup.list", "docker.backup.verify", "docker.restore.plan"], {"target": body.backup_targets}, "read"))
    for targets,names in ((body.package_targets,["package.plan"]),(body.configuration_targets,["configuration.plan"])):
        if targets:
            operations.append((names,{"target":targets},"read"))
    if body.profile == "maintenance":
        if not (body.services or body.containers or body.backup_targets or body.package_targets or body.configuration_targets or body.compose_targets):
            raise HTTPException(422, "Maintenance requires at least one explicit service or container")
        for targets, names in ((body.backup_targets, ["docker.backup.create", "docker.restore.apply"]),
                               (body.package_targets, ["package.apply"]),
                               (body.configuration_targets, ["configuration.apply"]),
                               (body.compose_targets, ["docker.compose.update"])):
            if targets:
                operations.append((names, {"target": targets}, "maintenance"))
        if body.services:
            operations.append((["systemd.restart"], {"service_names": body.services}, "maintenance"))
        if body.containers:
            operations.append((["docker.restart"], {"container_names": body.containers}, "maintenance"))
    if body.profile == "development":
        if body.allow_staging:
            operations.append((["development.deploy"], {"target": [body.project]}, "staging"))
        operations.append(
            (
                [
                    "development.workspace", "development.read", "development.artifact",
                    "development.patch",
                    "development.dependencies",
                    "development.test",
                ],
                {},
                "development",
            )
        )
        if body.allow_staging:
            operations.append((["development.stage"], {}, "staging"))
        if body.allow_dependency_network:
            operations.append((["development.network"], {"phase": ["dependencies"]}, "development"))
    if body.allow_publication:
        if body.profile != "development" or not project_contract.publication_paths or not project_contract.publication_token_env:
            raise HTTPException(422, "Draft PR publication requires a root-registered project publisher and a development profile")
        operations.append((["development.publish"], {"target":[body.project]}, "development"))
    expires = utcnow() + timedelta(hours=body.hours)
    created = []
    for ops, constraints, environment in operations:
        row = Policy(
            name=PROFILES[body.profile]["name"],
            subject_id=body.subject_id,
            host_id=None if body.profile == "development" and environment == "development" else body.host_id,
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
