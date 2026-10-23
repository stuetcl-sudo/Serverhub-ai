"""Read-only, actionable self-diagnostics; no repair side effects."""

from html.parser import HTMLParser
from pathlib import Path
import os
import shutil
import stat

from sqlalchemy import select, text

from .database import utcnow
from .models import Host, Policy, WorkerHeartbeat
from .settings import get_settings


class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = []

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "script" and attrs.get("src"):
            self.assets.append(attrs["src"])
        if tag == "link" and attrs.get("rel") == "stylesheet" and attrs.get("href"):
            self.assets.append(attrs["href"])


def frontend_assets(html):
    parser = AssetParser()
    parser.feed(html)
    if not parser.assets:
        raise ValueError(
            "Frontend index has no built script/style assets; run npm ci && npm run build in frontend"
        )
    for asset in parser.assets:
        if not asset.startswith("/assets/") or ".." in Path(asset).parts or "?" in asset or "#" in asset:
            raise ValueError("Frontend contains an unexpected external or unsafe asset reference")
    return parser.assets


def verify_frontend_files(directory):
    directory = Path(directory)
    assets = frontend_assets((directory / "index.html").read_text())
    for asset in assets:
        target = directory / asset.lstrip("/")
        if not target.resolve().is_relative_to(directory.resolve()) or not target.is_file():
            raise ValueError("Frontend asset missing: " + asset)
        if target.stat().st_size == 0:
            raise ValueError("Frontend asset empty: " + asset)
    return assets


def verify_frontend_http(client):
    index = client.get("/")
    index.raise_for_status()
    if "text/html" not in index.headers.get("content-type", ""):
        raise ValueError("Frontend index is not HTML")
    for asset in frontend_assets(index.text):
        response = client.get(asset, headers={"Origin": str(client.base_url).rstrip("/")})
        response.raise_for_status()
        if "text/html" in response.headers.get("content-type", "") or not response.content:
            raise ValueError("Frontend asset was replaced by HTML or is empty: " + asset)


def collect_diagnostics(db):
    settings = get_settings()
    checks = []

    def add(name, status, message, remediation="", **evidence):
        checks.append(
            {
                "id": name,
                "status": status,
                "message": message,
                "remediation": remediation,
                "evidence": evidence,
            }
        )

    try:
        from alembic.script import ScriptDirectory
        from .cli import _alembic_config

        heads = set(ScriptDirectory.from_config(_alembic_config()).get_heads())
        actual = set(db.execute(text("SELECT version_num FROM alembic_version")).scalars())
        add(
            "database",
            "ok" if heads == actual else "error",
            "Connected; schema revisions compared",
            "Run the backed-up upgrade/repair workflow as root; never migrate with the worker identity",
            installed=sorted(actual),
            expected=sorted(heads),
        )
    except Exception:
        db.rollback()
        add(
            "database",
            "error",
            "Database connectivity or migration lookup failed",
            "Check API database credentials and run serverhub migrate from the installed release as serverhub-ai-migrate",
        )
    try:
        workers = db.scalars(
            select(WorkerHeartbeat).where(
                WorkerHeartbeat.seen_at > utcnow() - __import__("datetime").timedelta(seconds=60)
            )
        ).all()
        add(
            "worker",
            "ok" if workers else "error",
            f"{len(workers)} worker heartbeat(s) in the last 60 seconds",
            "Inspect journalctl -u serverhub-ai-worker; check sandbox paths, worker.env permissions and database grants",
            workers=[{"id": r.worker_id, "job_id": r.job_id} for r in workers],
        )
    except Exception:
        db.rollback()
        add(
            "worker",
            "error",
            "Worker heartbeat table unavailable",
            "Apply migration 0004_runtime and PostgreSQL grants",
        )
    database_routes = False
    try:
        from .ai.providers import load_routes
        from .models import ModelRoute

        routes = load_routes()
        saved_routes = db.scalars(select(ModelRoute)).all()
        database_routes = bool(saved_routes)
        readiness = {row.name: row.readiness for row in saved_routes}
        add(
            "models",
            "ok" if "default" in routes else "error",
            "Default model configured" if "default" in routes else "No default model configured",
            "Use Setup → AI provider to discover, test and save a tool-capable model",
            routes=list(routes),
            readiness=readiness,
            connectivity="Readiness is a timestamped setup test. Test again in AI providers for a live connection check.",
        )
    except Exception as exc:
        add(
            "models",
            "error",
            "Model settings cannot be loaded: " + str(exc)[:300],
            "Use owner Setup or inspect protected configuration permissions; do not chmod secrets world-readable",
        )
    for label, target in (("model_file", settings.model_config_path), ("frontend", settings.frontend_dir)):
        try:
            if label == "frontend":
                assets = verify_frontend_files(target)
                add(
                    label,
                    "ok",
                    f"{len(assets)} built assets present and readable by API",
                    "",
                    directory=str(target),
                )
            elif database_routes:
                add(label, "ok", "Database routes are authoritative; unused fallback remains private",
                    "Do not broaden permissions on a legacy file that may contain credentials",
                    active=False)
            elif target.exists():
                metadata = target.stat()
                readable = os.access(target, os.R_OK)
                add(
                    label,
                    "ok" if readable and not metadata.st_mode & 0o022 else "error",
                    "Operator model fallback permissions checked",
                    "Root-owned non-secret models.yaml should be 0644 with searchable root-owned ancestors. API-managed routes do not require editing this file.",
                    mode=oct(stat.S_IMODE(metadata.st_mode)),
                    readable_by_api=readable,
                    uid=metadata.st_uid,
                )
            else:
                add(
                    label,
                    "warning",
                    "Optional model fallback file absent",
                    "Configure a database route using Setup",
                )
        except (OSError, ValueError) as exc:
            add(
                label,
                "error",
                str(exc)[:300],
                "Check directory traversal and asset modes with namei -l; rebuild assets if missing",
            )
    for name in ("serverhub-ai-api.service", "serverhub-ai-worker.service"):
        target = Path("/etc/systemd/system") / name
        try:
            content = target.read_text()
            missing = []
            for line in content.splitlines():
                if line.startswith(("ReadWritePaths=", "InaccessiblePaths=")):
                    missing += [
                        p
                        for p in line.split("=", 1)[1].split()
                        if not p.startswith("-") and not Path(p).exists()
                    ]
            add(
                name,
                "error" if missing else "ok",
                "Unit sandbox path existence checked",
                "Run the native repair workflow to refresh units; systemctl daemon-reload afterwards",
                missing_paths=missing,
            )
        except OSError:
            add(
                name,
                "warning",
                "Native unit not visible in this environment",
                "Install native units or run root CLI diagnostics on the controller",
            )
    add(
        "tools",
        "ok",
        "Controller tool availability recorded; node tools are separate",
        "Install optional scanners on the managed node before enabling scanner policies",
        tools={
            name: bool(shutil.which(name))
            for name in ("systemctl", "pg_dump", "pg_restore", "git", "bwrap", "trivy", "lynis")
        },
    )
    active = db.scalars(select(Policy).where(Policy.enabled.is_(True), Policy.expires_at > utcnow())).all()
    add(
        "policies",
        "ok" if active else "warning",
        f"{len(active)} active explicit grant(s)",
        "Use Approval policies → autonomy profiles to delegate exact operations/targets with an expiry. Owner inventory reads remain built-in.",
    )
    hosts = db.scalars(select(Host).where(Host.revoked.is_(False))).all()
    evidence = [
        {
            "id": h.id,
            "name": h.name,
            "last_seen": str(h.last_seen),
            "online": bool(
                h.last_seen and (utcnow() - h.last_seen).total_seconds() < settings.offline_seconds
            ),
            "broker_observation_errors": [
                e for e in (h.inventory or {}).get("errors", []) if e.get("collector") == "broker"
            ],
        }
        for h in hosts
    ]
    add(
        "hosts",
        "ok" if any(h["online"] for h in evidence) else "warning",
        f"{len(hosts)} enrolled host(s)",
        "Create an enrollment token in Managed hosts, configure node identity and start its agent. Broker allowlists require a root administrator; never add worker to docker/sudo groups.",
        hosts=evidence,
        broker="Last reported observation only; an online heartbeat alone does not prove broker connectivity",
    )
    return {
        "generated_at": utcnow().isoformat() + "Z",
        "healthy": not any(c["status"] == "error" for c in checks),
        "checks": checks,
    }
