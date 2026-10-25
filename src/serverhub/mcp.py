"""Stateless MCP 2025-11-25 JSON transport and pre-registered OAuth with PKCE.

Every tool reuses REST authorization and host scope. MCP tokens have a distinct
audience and cannot be presented to the REST control plane or agent endpoints.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import secrets
from datetime import timedelta
from urllib.parse import parse_qs, urlencode, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select, update

from . import __version__, api
from .audit import append_audit
from .auth import (
    Principal,
    create_session,
    current_principal,
    hash_secret,
    require_owner,
    token_principal,
    verify_secret,
)
from .database import get_db, utcnow
from .models import SessionToken, User, to_dict
from .oauth_models import OAuthClient, OAuthCode, OAuthPending, OAuthRefresh
from .policy import PermissionDenied
from .settings import get_settings

router = APIRouter(tags=["MCP", "OAuth"])
VERSIONS = {"2025-03-26", "2025-06-18", "2025-11-25"}
SCOPES = {"serverhub:read", "serverhub:jobs", "serverhub:policies"}


def resource_uri():
    return get_settings().public_url.rstrip("/") + "/mcp"


def unauthorized(detail="MCP OAuth bearer token required"):
    metadata = get_settings().public_url.rstrip("/") + "/.well-known/oauth-protected-resource"
    return HTTPException(401, detail, headers={"WWW-Authenticate": f'Bearer resource_metadata="{metadata}"'})


def mcp_actor(request: Request, db=Depends(get_db)):
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer ") or len(header) > 1024:
        raise unauthorized()
    try:
        actor = token_principal(db, header[7:], audience="mcp")
    except HTTPException:
        raise unauthorized("Invalid or expired MCP token") from None
    token = db.scalar(select(SessionToken).where(SessionToken.digest == hash_secret(header[7:])))
    client_id = token.label.removeprefix("oauth:")
    client = db.get(OAuthClient, client_id)
    if not token.label.startswith("oauth:") or not client or not client.enabled:
        raise unauthorized("MCP client is revoked")
    return actor, set(token.scopes)


@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
def protected_metadata():
    return {
        "resource": resource_uri(),
        "authorization_servers": [get_settings().public_url.rstrip("/")],
        "scopes_supported": sorted(SCOPES),
        "bearer_methods_supported": ["header"],
    }


@router.get("/.well-known/oauth-authorization-server")
def authorization_metadata():
    root = get_settings().public_url.rstrip("/")
    return {
        "issuer": root,
        "authorization_endpoint": root + "/oauth/authorize",
        "token_endpoint": root + "/oauth/token",
        "revocation_endpoint": root + "/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": sorted(SCOPES),
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
    }


class NewClient(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=150)
    redirect_uris: list[str] = Field(min_length=1, max_length=5)
    confidential: bool = False


@router.post("/api/mcp/clients", status_code=201)
def register_client(body: NewClient, actor: Principal = Depends(current_principal), db=Depends(get_db)):
    require_owner(actor)
    for uri in body.redirect_uris:
        url = urlsplit(uri)
        dev_local = (
            get_settings().dev_mode and url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1"}
        )
        if (
            len(uri) > 2048
            or not url.hostname
            or url.fragment
            or url.username
            or url.password
            or (url.scheme != "https" and not dev_local)
        ):
            raise HTTPException(422, "Redirects require an exact HTTPS URL without credentials or fragment")
    secret = secrets.token_urlsafe(48) if body.confidential else None
    client = OAuthClient(
        name=body.name,
        redirect_uris=body.redirect_uris,
        created_by=actor.id,
        secret_hash=hash_secret(secret) if secret else None,
    )
    db.add(client)
    db.flush()
    append_audit(db, actor.id, "oauth.client.registered", client.id, {"name": client.name})
    db.commit()
    return {
        "client_id": client.id,
        "client_secret": secret,
        "redirect_uris": body.redirect_uris,
        "token_endpoint_auth_method": "client_secret_post" if secret else "none",
    }


@router.get("/api/mcp/clients")
def clients(actor: Principal = Depends(current_principal), db=Depends(get_db)):
    require_owner(actor)
    return [to_dict(row, exclude={"secret_hash"}) for row in db.scalars(select(OAuthClient))]


@router.delete("/api/mcp/clients/{client_id}")
def revoke_client(client_id: str, actor: Principal = Depends(current_principal), db=Depends(get_db)):
    require_owner(actor)
    client = db.get(OAuthClient, client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    client.enabled = False
    db.execute(update(SessionToken).where(SessionToken.label == "oauth:" + client_id).values(revoked=True))
    db.execute(update(OAuthRefresh).where(OAuthRefresh.client_id == client_id).values(revoked=True))
    append_audit(db, actor.id, "oauth.client.revoked", client.id)
    db.commit()
    return {"revoked": True}


def _validate_authorization(parameters, db):
    client = db.get(OAuthClient, parameters.get("client_id"))
    if not client or not client.enabled or parameters.get("redirect_uri") not in client.redirect_uris:
        raise HTTPException(400, "Unregistered client or redirect URI")
    if parameters.get("response_type") != "code" or parameters.get("code_challenge_method") != "S256":
        raise HTTPException(400, "Authorization code flow with S256 PKCE is required")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", parameters.get("code_challenge", "")):
        raise HTTPException(400, "Invalid S256 challenge")
    if parameters.get("resource") != resource_uri():
        raise HTTPException(400, "Exact MCP resource parameter is required")
    scopes = set(parameters.get("scope", "serverhub:read").split())
    if not scopes or not scopes <= SCOPES or len(parameters.get("state", "")) > 2048:
        raise HTTPException(400, "Invalid scopes or state")
    return client, sorted(scopes)


@router.get("/oauth/authorize", response_class=HTMLResponse)
def authorize_page(request: Request, db=Depends(get_db)):
    parameters = dict(request.query_params)
    client, scopes = _validate_authorization(parameters, db)
    try:
        actor = current_principal(request, db)
    except HTTPException:
        return HTMLResponse(
            '<!doctype html><html><title>Sign in to ServerHub</title><body><h1>Sign in to ServerHub</h1><p>Open the dashboard in this browser, sign in, then return here and reload to approve this connection.</p><a href="/" target="_blank" rel="noopener">Open dashboard</a></body></html>',
            status_code=401,
        )
    nonce = secrets.token_urlsafe(48)
    db.add(
        OAuthPending(
            digest=hash_secret(nonce),
            user_id=actor.id,
            parameters=parameters,
            expires_at=utcnow() + timedelta(minutes=5),
        )
    )
    db.commit()
    text = f'''<!doctype html><html lang="en"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ServerHub connection</title>
<body style="font:16px system-ui;background:#0c1421;color:#e7eefc;max-width:600px;margin:10vh auto;padding:24px">
<h1>Connect {html.escape(client.name)}</h1><p>Signed in as {html.escape(actor.username)}.</p>
<p>Requested access: {html.escape(", ".join(scopes))}. Existing host permissions and expiring operation policies still apply.</p>
<form method="post" action="/oauth/authorize"><input type="hidden" name="consent_nonce" value="{nonce}">
<button name="decision" value="approve">Approve connection</button> <button name="decision" value="deny">Deny</button></form></body></html>'''
    response = HTMLResponse(text)
    response.set_cookie(
        "serverhub_oauth_consent",
        nonce,
        max_age=300,
        httponly=True,
        secure=not get_settings().dev_mode,
        samesite="strict",
        path="/oauth/authorize",
    )
    return response


async def _form(request):
    if not request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
        raise HTTPException(415, "URL-encoded form required")
    raw = await request.body()
    if len(raw) > 16384:
        raise HTTPException(413, "OAuth form too large")
    try:
        values = parse_qs(raw.decode("utf-8"), strict_parsing=True, max_num_fields=20)
    except (ValueError, UnicodeError):
        raise HTTPException(400, "Invalid OAuth form") from None
    if any(len(value) != 1 for value in values.values()):
        raise HTTPException(400, "Duplicate OAuth parameters")
    return {key: value[0] for key, value in values.items()}


@router.post("/oauth/authorize")
async def consent(request: Request, actor: Principal = Depends(current_principal), db=Depends(get_db)):
    form = await _form(request)
    nonce = form.get("consent_nonce", "")
    if not nonce or not secrets.compare_digest(nonce, request.cookies.get("serverhub_oauth_consent", "")):
        raise HTTPException(403, "Consent CSRF check failed")
    pending = db.scalar(
        select(OAuthPending).where(OAuthPending.digest == hash_secret(nonce)).with_for_update()
    )
    if not pending or pending.user_id != actor.id or pending.expires_at <= utcnow():
        raise HTTPException(400, "Consent request expired or already consumed")
    p = pending.parameters
    client, scopes = _validate_authorization(p, db)
    db.delete(pending)
    values = {"state": p.get("state", "")}
    if form.get("decision") == "approve":
        code = secrets.token_urlsafe(48)
        db.add(
            OAuthCode(
                digest=hash_secret(code),
                user_id=actor.id,
                client_id=client.id,
                redirect_uri=p["redirect_uri"],
                challenge=p["code_challenge"],
                resource=resource_uri(),
                scopes=scopes,
                expires_at=utcnow() + timedelta(minutes=5),
            )
        )
        values["code"] = code
        append_audit(db, actor.id, "oauth.consent.approved", client.id, {"scopes": scopes})
    else:
        values["error"] = "access_denied"
    db.commit()
    response = RedirectResponse(
        p["redirect_uri"] + ("&" if "?" in p["redirect_uri"] else "?") + urlencode(values), status_code=303
    )
    response.delete_cookie("serverhub_oauth_consent", path="/oauth/authorize")
    return response


def _client_auth(form, db):
    client = db.get(OAuthClient, form.get("client_id"))
    if not client or not client.enabled:
        raise HTTPException(400, "invalid_client")
    if client.secret_hash and not verify_secret(form.get("client_secret", ""), client.secret_hash):
        raise HTTPException(401, "invalid_client")
    if form.get("resource") != resource_uri():
        raise HTTPException(400, "invalid_target")
    return client


@router.post("/oauth/token")
async def token(request: Request, db=Depends(get_db)):
    form = await _form(request)
    client = _client_auth(form, db)
    if form.get("grant_type") == "authorization_code":
        record = db.scalar(
            select(OAuthCode).where(OAuthCode.digest == hash_secret(form.get("code", ""))).with_for_update()
        )
        verifier = form.get("code_verifier", "")
        if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
            raise HTTPException(400, "invalid_grant")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        if (
            not record
            or record.consumed
            or record.expires_at <= utcnow()
            or record.client_id != client.id
            or record.redirect_uri != form.get("redirect_uri")
            or record.resource != form["resource"]
            or not secrets.compare_digest(record.challenge, challenge)
        ):
            raise HTTPException(400, "invalid_grant")
        record.consumed = True
        family = secrets.token_hex(24)
    elif form.get("grant_type") == "refresh_token":
        record = db.scalar(
            select(OAuthRefresh)
            .where(OAuthRefresh.digest == hash_secret(form.get("refresh_token", "")))
            .with_for_update()
        )
        if not record or record.client_id != client.id or record.resource != form["resource"]:
            raise HTTPException(400, "invalid_grant")
        if record.revoked:
            db.execute(update(OAuthRefresh).where(OAuthRefresh.family == record.family).values(revoked=True))
            db.execute(
                update(SessionToken)
                .where(SessionToken.user_id == record.user_id, SessionToken.label == "oauth:" + client.id)
                .values(revoked=True)
            )
            db.commit()
            raise HTTPException(400, "Refresh replay detected; grant family revoked")
        if record.expires_at <= utcnow():
            raise HTTPException(400, "invalid_grant")
        record.revoked = True
        family = record.family
    else:
        raise HTTPException(400, "unsupported_grant_type")
    user = db.get(User, record.user_id)
    if not user or not user.enabled:
        raise HTTPException(400, "invalid_grant")
    access = create_session(
        db, user, hours=1, label="oauth:" + client.id, audience="mcp", scopes=record.scopes
    )
    refresh = secrets.token_urlsafe(48)
    db.add(
        OAuthRefresh(
            digest=hash_secret(refresh),
            family=family,
            user_id=user.id,
            client_id=client.id,
            scopes=record.scopes,
            resource=resource_uri(),
            expires_at=utcnow() + timedelta(days=30),
        )
    )
    append_audit(db, user.id, "oauth.token.issued", client.id, {"scopes": record.scopes})
    db.commit()
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh,
        "scope": " ".join(record.scopes),
    }


@router.post("/oauth/revoke")
async def revoke_token(request: Request, db=Depends(get_db)):
    form = await _form(request)
    client = _client_auth(form, db)
    digest = hash_secret(form.get("token", ""))
    db.execute(
        update(OAuthRefresh)
        .where(OAuthRefresh.digest == digest, OAuthRefresh.client_id == client.id)
        .values(revoked=True)
    )
    db.execute(
        update(SessionToken)
        .where(SessionToken.digest == digest, SessionToken.label == "oauth:" + client.id)
        .values(revoked=True)
    )
    db.commit()
    return Response(status_code=200)


def _object(properties=None, required=None):
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


def policy_templates():
    from .ai.providers import read_operator_yaml

    content = read_operator_yaml("/etc/serverhub/mcp-policies.yaml").get("templates", {})
    if not isinstance(content, dict):
        raise ValueError("Policy templates must be an operator-owned mapping")
    return content


def activate_policy(arguments, actor, db):
    require_owner(actor)
    template = policy_templates().get(arguments["template_id"])
    if not isinstance(template, dict) or arguments["host_id"] not in template.get("allowed_hosts", []):
        raise PermissionDenied("Policy template is not enabled for this host")
    duration = arguments["duration_seconds"]
    maximum = template.get("maximum_seconds", 3600)
    if not isinstance(maximum, int) or not 60 <= duration <= min(maximum, 86400):
        raise ValueError("Approval duration exceeds its predefined maximum")
    grant = {
        "name": str(template.get("name", arguments["template_id"])),
        "host_id": arguments["host_id"],
        "project": template.get("project"),
        "operations": template.get("operations", []),
        "constraints": template.get("constraints", {}),
        "expires_at": utcnow() + timedelta(seconds=duration),
        "production": False,
    }
    if template.get("role"):
        grant["role"] = template["role"]
    else:
        grant["subject_id"] = actor.id
    return api.add_policy(api.NewPolicy.model_validate(grant), actor, db)


HOST = {"type": "string", "minLength": 1, "maxLength": 36}
TOOLS = [
    (
        "list_policy_templates",
        "Owner-only list of predefined host-scoped approval templates",
        _object(),
        "serverhub:policies",
    ),
    (
        "activate_policy",
        "Owner-only activate a predefined nonproduction policy for an explicitly allowlisted host and bounded duration",
        _object(
            {
                "template_id": {"type": "string", "maxLength": 100},
                "host_id": HOST,
                "duration_seconds": {"type": "integer", "minimum": 60, "maximum": 86400},
            },
            ["template_id", "host_id", "duration_seconds"],
        ),
        "serverhub:policies",
    ),
    ("docker_backup", "Queue a scoped encrypted backup, verification or isolated restore through the privileged broker",
     _object({"host_id": HOST, "target": {"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$"},
              "action":{"type":"string","enum":["create","list","verify","restore_plan","restore_apply"]},
              "backup_id":{"type":"string","pattern":"^[a-f0-9]{32}$"}}, ["host_id","target","action"]), "serverhub:jobs"),
    ("host_maintenance", "Queue an enrolled package, configuration or Compose transaction; no command execution",
     _object({"host_id": HOST, "target":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$"},
              "operation":{"type":"string","enum":["package.plan","package.apply","configuration.plan","configuration.apply","docker.compose.update"]}},
             ["host_id","target","operation"]), "serverhub:jobs"),
    ("audit_host", "Queue a persistent read-only host audit; returns job ID, no repairs or fake synchronous completion",
     _object({"host_id": HOST}, ["host_id"]), "serverhub:jobs"),
    ("list_hosts", "List authorized managed hosts", _object(), "serverhub:read"),
    (
        "read_inventory",
        "Read the last authenticated agent inventory for an authorized host",
        _object({"host_id": HOST}, ["host_id"]),
        "serverhub:read",
    ),
    (
        "security_findings",
        "Read evidence-based security findings on authorized hosts",
        _object(),
        "serverhub:read",
    ),
    ("list_incidents", "Read incidents on authorized hosts", _object(), "serverhub:read"),
    ("backup_status", "Read recorded backup status; no archive access", _object(), "serverhub:read"),
    (
        "job_progress",
        "Read own job state and execution events",
        _object({"job_id": HOST}, ["job_id"]),
        "serverhub:read",
    ),
    (
        "job_result",
        "Read own job result and remaining limitations",
        _object({"job_id": HOST}, ["job_id"]),
        "serverhub:read",
    ),
    (
        "submit_job",
        "Submit a persistent job; each tool is separately policy authorized",
        _object(
            {
                "kind": {
                    "type": "string",
                    "enum": ["inventory", "operation", "workflow", "autonomous", "monitoring", "development", "development_autonomous"],
                },
                "host_id": HOST,
                "project": {"type": "string", "maxLength": 200},
                "spec": {"type": "object"},
                "idempotency_key": {"type": "string", "maxLength": 200},
            },
            ["kind", "spec"],
        ),
        "serverhub:jobs",
    ),
    (
        "request_remediation",
        "Request a diagnostic or policy-authorized repair job on a selected host",
        _object(
            {"host_id": HOST, "prompt": {"type": "string", "minLength": 1, "maxLength": 16000}},
            ["host_id", "prompt"],
        ),
        "serverhub:jobs",
    ),
    (
        "list_policies",
        "Owner-only list of active and expired approval policies",
        _object(),
        "serverhub:policies",
    ),
]

# Dedicated development tools expose only registered project identities and job
# controls. They reuse REST authentication/authorization; no command/path input.
TOOLS += [
    ("update_job_budget", "Change limits on an owned paused/queued job; preserves accounted usage",
     _object({"job_id":HOST, "token_budget":{"type":"integer","minimum":0,"maximum":2000000},
              "cost_budget":{"type":"number","minimum":0,"maximum":1000}}, ["job_id","token_budget","cost_budget"]), "serverhub:jobs"),
    ("list_projects", "List registered development projects visible to this identity", _object(), "serverhub:read"),
    ("create_development_job", "Queue a durable registered-project workflow; omit prompt for no-patch validation",
     _object({"project": {"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"},
              "prompt":{"type":"string","minLength":1,"maxLength":16000}, "stage":{"type":"boolean"},
              "host_id":HOST, "idempotency_key":{"type":"string","minLength":1,"maxLength":200},
              "token_budget":{"type":"integer","minimum":0,"maximum":2000000},
              "cost_budget":{"type":"number","minimum":0,"maximum":1000}}, ["project"]), "serverhub:jobs"),
    ("job_logs", "Read bounded own-job events after a cursor", _object({"job_id":HOST,
        "after":{"type":"integer","minimum":0}}, ["job_id"]), "serverhub:read"),
    ("publish_development_result", "Publish a verified bounded candidate as a draft PR to its root-registered repository; separate policy required", _object({"job_id":HOST}, ["job_id"]), "serverhub:jobs"),
    ("development_artifacts", "Read the authorized job's candidate manifest and bounded source patch, never arbitrary files",
        _object({"job_id":HOST},["job_id"]), "serverhub:read"),
    ("resume_job", "Resume own paused/approval-blocked job only after its initiating identity has the missing permission",
        _object({"job_id":HOST},["job_id"]), "serverhub:jobs"),
    ("cancel_job", "Cancel own persistent job and its dependent child work",
        _object({"job_id":HOST},["job_id"]), "serverhub:jobs"),
    ("grant_development_profile", "Owner-only explicit expiring project grant; staging and dependency networking are opt-in",
        _object({"project":{"type":"string","maxLength":64}, "subject_id":HOST, "host_id":HOST,
            "hours":{"type":"integer","minimum":1,"maximum":8784},
            "allow_publication":{"type":"boolean"},"allow_staging":{"type":"boolean"},"allow_dependency_network":{"type":"boolean"}},
            ["project","subject_id","hours"]), "serverhub:policies"),
    ("revoke_policy", "Owner-only revoke an exact policy ID; live tools recheck policy",
        _object({"policy_id":HOST},["policy_id"]), "serverhub:policies"),
]


def _call(name, arguments, actor, db):
    if name == "publish_development_result":
        from .extensions import publish_development
        return publish_development(arguments["job_id"], actor, db)
    if name == "list_projects":
        from .extensions import projects
        return projects(actor, db)
    if name == "grant_development_profile":
        from .setup import grant_profile, ProfileGrant
        return grant_profile(ProfileGrant(profile="development", **arguments), actor, db)
    if name == "revoke_policy":
        return api.update_policy(arguments["policy_id"], api.PolicyUpdate(enabled=False), actor, db)
    if name == "update_job_budget":
        return api.update_job_budget(arguments["job_id"], api.JobBudgetUpdate(
            token_budget=arguments["token_budget"], cost_budget=arguments["cost_budget"]), actor, db)
    if name == "create_development_job":
        spec = {"project": arguments["project"], "stage": arguments.get("stage", False)}
        if arguments.get("prompt"):
            spec["prompt"] = arguments["prompt"]
        return api.add_job(api.NewJob(kind="development_autonomous" if "prompt" in spec else "development",
            project=arguments["project"], host_id=arguments.get("host_id"), spec=spec,
            idempotency_key=arguments.get("idempotency_key"), token_budget=arguments.get("token_budget"), cost_budget=arguments.get("cost_budget")), actor, db)
    if name == "job_logs":
        return api.job_events(arguments["job_id"], actor, arguments.get("after",0), db)
    if name in {"resume_job", "cancel_job"}:
        return api.job_action(arguments["job_id"], "resume" if name == "resume_job" else "cancel", actor, db)
    if name == "development_artifacts":
        value = api.job(arguments["job_id"], actor, db)
        if value["kind"] not in {"development", "development_autonomous"}:
            raise HTTPException(422, "Select a development job")
        result = value.get("result") or {}
        candidate = result.get("candidate") or {}
        return {"job_id":value["id"], "state":value["state"], "verified":result.get("verified",False),
            "manifest":{key:candidate[key] for key in ("sha256","commit","files","bytes") if key in candidate},
            "source_patch":result.get("source_patch"), "patch_available":result.get("source_patch") is not None,
            "archive_delivery":"Candidate archive retained in protected worker storage; MCP exposes manifest and bounded patch only"}
    if name == "list_policy_templates":
        require_owner(actor)
        return policy_templates()
    if name == "activate_policy":
        return activate_policy(arguments, actor, db)
    if name in {"docker_backup", "host_maintenance"}:
        action = arguments.get("action")
        operation = arguments.get("operation") if name == "host_maintenance" else {
            "create":"docker.backup.create", "list":"docker.backup.list", "verify":"docker.backup.verify",
            "restore_plan":"docker.restore.plan", "restore_apply":"docker.restore.apply"}[action]
        payload = {"target": arguments["target"]}
        if arguments.get("backup_id"):
            payload["backup_id"] = arguments["backup_id"]
        return api.add_job(api.NewJob(kind="operation", host_id=arguments["host_id"],
            spec={"operation":operation,"arguments":payload}, time_limit=7200), actor, db)
    if name == "audit_host":
        return api.add_job(api.NewJob(kind="operation", host_id=arguments["host_id"],
                                     spec={"operation": "host.audit", "arguments": {}}, token_budget=0, cost_budget=0), actor, db)
    if name == "list_hosts":
        return api.hosts(actor, db)
    if name == "read_inventory":
        return api.host_inventory(arguments["host_id"], actor, db)
    if name == "security_findings":
        return api.findings(actor, db)
    if name == "list_incidents":
        return api.incidents(actor, db)
    if name == "backup_status":
        return api.backups(actor, db)
    if name == "job_progress":
        return {
            "job": api.job(arguments["job_id"], actor, db),
            "events": api.job_events(arguments["job_id"], actor, 0, db),
        }
    if name == "job_result":
        return api.job(arguments["job_id"], actor, db)
    if name == "list_policies":
        return api.policies(actor, db)
    if name == "request_remediation":
        arguments = {
            "kind": "autonomous",
            "host_id": arguments["host_id"],
            "spec": {"prompt": arguments["prompt"]},
        }
        name = "submit_job"
    if name == "submit_job":
        return api.add_job(api.NewJob.model_validate(arguments), actor, db)
    raise ValueError("Unknown tool")


@router.get("/mcp")
@router.delete("/mcp")
def no_stream(identity=Depends(mcp_actor)):
    # This transport returns a JSON response per request; optional SSE is absent.
    return Response(status_code=405, headers={"Allow": "POST"})


@router.post("/mcp")
async def rpc(request: Request, identity=Depends(mcp_actor), db=Depends(get_db)):
    actor, scopes = identity
    try:
        body = await request.json()
    except (ValueError, UnicodeError):
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status_code=400,
        )
    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or not isinstance(body.get("method"), str):
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}},
            status_code=400,
        )
    identifier = body.get("id")
    if identifier is not None and (isinstance(identifier, bool) or not isinstance(identifier, (str, int))):
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request id"}},
            status_code=400,
        )
    method = body["method"]
    params = body.get("params", {})
    if not isinstance(params, dict):
        return {"jsonrpc": "2.0", "id": identifier, "error": {"code": -32602, "message": "Invalid params"}}
    if "id" not in body:
        if method == "notifications/initialized" or method == "notifications/cancelled":
            return Response(status_code=202)
        return Response(status_code=400)
    if method != "initialize" and request.headers.get("mcp-protocol-version", "2025-03-26") not in VERSIONS:
        raise HTTPException(400, "Unsupported MCP protocol version")
    if method == "initialize":
        version = params.get("protocolVersion")
        result = {
            "protocolVersion": version if version in VERSIONS else "2025-11-25",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "ServerHub AI OS", "version": __version__},
            "instructions": "Jobs execute persistently. Host and operation permissions are enforced server-side; unsupported operations are rejected.",
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": name,
                    "description": description,
                    "inputSchema": schema,
                    "annotations": {
                        "readOnlyHint": scope == "serverhub:read",
                        "destructiveHint": scope != "serverhub:read",
                        "openWorldHint": False,
                    },
                }
                for name, description, schema, scope in TOOLS
                if scope in scopes
            ]
        }
    elif method == "tools/call":
        name, arguments = params.get("name"), params.get("arguments", {})
        tool = next((item for item in TOOLS if item[0] == name), None)
        if tool is None:
            return {"jsonrpc": "2.0", "id": identifier, "error": {"code": -32602, "message": "Unknown tool"}}
        if tool[3] not in scopes:
            raise HTTPException(403, "MCP token lacks required scope")
        try:
            # Full schema validation also rejects unexpected arguments and invalid lengths/types.
            from jsonschema import validate

            validate(arguments, tool[2])
            result_data = _call(name, arguments, actor, db)
            append_audit(db, actor.id, "mcp.tool", name)
            db.commit()
            result = {
                "content": [{"type": "text", "text": json.dumps(result_data, default=str)}],
                "isError": False,
            }
        except (PermissionDenied, HTTPException, ValueError, ValidationError) as exc:
            db.rollback()
            result = {
                "content": [{"type": "text", "text": json.dumps({"message": str(getattr(exc, "detail", exc)),
                        "denial": exc.details if isinstance(exc, PermissionDenied) else None}, default=str)}],
                "isError": True,
            }
        except Exception as exc:
            from jsonschema.exceptions import ValidationError as SchemaError

            db.rollback()
            if isinstance(exc, SchemaError):
                result = {
                    "content": [{"type": "text", "text": "Tool arguments do not match its input schema"}],
                    "isError": True,
                }
            else:
                raise
    else:
        return {"jsonrpc": "2.0", "id": identifier, "error": {"code": -32601, "message": "Method not found"}}
    return {"jsonrpc": "2.0", "id": identifier, "result": result}
