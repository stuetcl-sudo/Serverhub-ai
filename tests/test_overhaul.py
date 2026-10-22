"""Regressions from real installation and delegated autonomy failures."""

import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select, text

from test_core import (
    core_env as core_env,
    client as client,
    bearer,
    owner as owner,
)  # shared isolated fixtures
from serverhub.database import SessionLocal, get_engine, utcnow
from serverhub.models import Host, Job, ModelRoute, Policy, WorkerHeartbeat, InventorySample
from serverhub.policy import PermissionDenied, authorize
from serverhub.ai.providers import ProviderConfig
from serverhub.model_setup import discover_models, test_model as probe_model
from serverhub.jobs import HANDLERS, Worker, submit_job
from serverhub.verification import verify_inventory


@pytest.mark.parametrize(
    "url",
    [
        "http://8.8.8.8:11434",
        "http://169.254.169.254",
        "http://example.com",
        "http://0.0.0.0",
        "http://[::ffff:192.168.1.1]",
    ],
)
def test_http_exception_cannot_authorize_public_metadata_dns_or_wildcard_endpoints(url):
    with pytest.raises(ValueError, match="Private HTTP"):
        ProviderConfig(kind="ollama", model="model", base_url=url, allow_insecure_http=True)


def test_private_endpoint_requires_consent_and_model_probe_is_not_an_infrastructure_action():
    with pytest.raises(ValueError):
        ProviderConfig(kind="ollama", model="model", base_url="http://192.168.68.20:11434")
    cfg = ProviderConfig(
        kind="ollama", model="model", base_url="http://192.168.68.20:11434", allow_insecure_http=True
    )
    requests = []

    def handle(req):
        requests.append(req.url.path)
        body = json.loads(req.content or "{}")
        if req.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "model"}]})
        if req.url.path == "/api/show":
            return httpx.Response(200, json={"capabilities": ["completion", "tools"]})
        nonce = body["tools"][0]["function"]["parameters"]["properties"]["nonce"]["enum"][0]
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": "",
                    "tool_calls": [{"function": {"name": "serverhub_probe", "arguments": {"nonce": nonce}}}],
                },
                "prompt_eval_count": 10,
                "eval_count": 5,
            },
        )

    transport = httpx.MockTransport(handle)
    assert discover_models(cfg, transport=transport)[0]["name"] == "model"
    assert probe_model(cfg, transport=transport)["ready"]
    assert requests == ["/api/tags", "/api/show", "/api/chat"]


def test_non_tool_model_and_unreachable_model_have_actionable_errors():
    cfg = ProviderConfig(kind="ollama", base_url="http://127.0.0.1:11434", model="no-tools")
    result = probe_model(
        cfg,
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"capabilities": ["completion"]})),
    )
    assert result["ready"] is False and "tool" in result["message"]

    def timeout(req):
        raise httpx.ConnectTimeout("private details")

    from serverhub.ai.providers import ProviderError

    with pytest.raises(ProviderError, match="trusted network"):
        discover_models(cfg, transport=httpx.MockTransport(timeout))


def test_model_configuration_owner_only_validated_and_persisted(client, monkeypatch):
    with SessionLocal() as db:
        owner_headers, adult_headers = bearer(db), bearer(db, "adult")
    body = {"kind": "ollama", "base_url": "http://127.0.0.1:11434", "model": "tools"}
    assert client.put("/api/settings/models/default", json=body, headers=adult_headers).status_code == 403
    monkeypatch.setattr(
        "serverhub.setup.test_model",
        lambda config: {"ready": True, "tool_calling": True, "message": "verified harmless probe"},
    )
    assert client.put("/api/settings/models/default", json=body, headers=owner_headers).status_code == 200
    assert client.get("/api/settings/models", headers=owner_headers).json()["configured"]
    from serverhub.ai.providers import load_routes

    assert load_routes()["default"].model == "tools"
    with SessionLocal() as db:
        assert db.get(ModelRoute, "default").updated_by == "owner"
    assert client.get("/api/settings/models", headers=adult_headers).status_code == 403


def test_profile_scopes_expiry_argument_constraints_and_no_production_escalation(client):
    with SessionLocal() as db:
        headers = bearer(db)
    body = {
        "profile": "maintenance",
        "subject_id": "adult",
        "host_id": "node1",
        "hours": 1,
        "services": ["example.service"],
        "network_targets": ["internet"],
    }
    response = client.post("/api/policies/profiles", json=body, headers=headers)
    assert response.status_code == 201, response.text
    from serverhub.auth import Principal

    actor = Principal("adult", "adult", "adult")
    with SessionLocal() as db:
        authorize(db, actor, "diagnostics.network", "node1", arguments={"target": "internet"})
        authorize(db, actor, "systemd.restart", "node1", arguments={"service": "example.service"})
        for operation, host, args in [
            ("diagnostics.network", "node2", {"target": "internet"}),
            ("diagnostics.network", "node1", {"target": "unapproved"}),
            ("systemd.restart", "node1", {"service": "sshd.service"}),
            ("production.deploy", "node1", {}),
        ]:
            with pytest.raises(PermissionDenied) as denial:
                authorize(db, actor, operation, host, arguments=args)
            assert denial.value.details["operation"] == operation and denial.value.details["host_id"] == host
        for grant in db.scalars(select(Policy)):
            grant.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
        with pytest.raises(PermissionDenied):
            authorize(db, actor, "systemd.restart", "node1", arguments={"service": "example.service"})


def test_owner_read_only_network_diagnostics_are_not_misclassified_as_writes(core_env, owner):
    with SessionLocal() as db:
        authorize(db, owner, "diagnostics.network", "node1", arguments={"target": "internet"})
        authorize(db, owner, "inventory.refresh", "node1")
        with pytest.raises(PermissionDenied):
            authorize(db, owner, "systemd.restart", "node1", arguments={"service": "example.service"})


def test_partial_job_does_not_report_succeeded_and_cannot_unlock_dependencies(core_env, owner):
    HANDLERS["test_partial"] = lambda ctx, spec: {"completed": False, "verified": False}
    with SessionLocal() as db:
        job = submit_job(db, owner, "test_partial", {}, host_id="node1")
        db.commit()
        identity = job.id
    assert Worker(isolated=False).run_once()
    with SessionLocal() as db:
        assert db.get(Job, identity).state == "partial"
        assert db.scalars(select(WorkerHeartbeat)).first()


def test_policy_blocked_job_has_exact_denial_and_resumes_saved_progress(core_env, owner):
    from serverhub.auth import Principal

    actor = Principal("adult", "adult", "adult")
    calls = []

    def task(ctx, spec):
        if not ctx.job.checkpoint.get("first"):
            calls.append("first")
            ctx.save_checkpoint({"first": True})
        ctx.require("diagnostics.network", {"target": "internet"})
        return {"verified": True}

    HANDLERS["test_resume_policy"] = task
    with SessionLocal() as db:
        job = submit_job(db, actor, "test_resume_policy", {}, host_id="node1")
        db.commit()
        identity = job.id
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        job = db.get(Job, identity)
        assert job.state == "waiting_approval"
        assert job.result["denial"]["arguments"] == {"target": "internet"}
        assert job.result["denial"]["environment"] == "read"
        assert job.checkpoint["first"]
        db.add(
            Policy(
                name="exact read",
                subject_id="adult",
                host_id="node1",
                operations=["diagnostics.network"],
                constraints={"target": ["internet"]},
                environment="read",
                expires_at=utcnow() + timedelta(hours=1),
                created_by="owner",
            )
        )
        job.state = "queued"
        db.commit()
    Worker(isolated=False).run_once()
    with SessionLocal() as db:
        assert db.get(Job, identity).state == "succeeded"
    assert calls == ["first"]


def test_verification_rejects_stale_observations_and_unknown_checks(core_env):
    with SessionLocal() as db:
        db.add(InventorySample(host_id="node1", metrics={}))
        db.commit()
        assert verify_inventory(db, "node1", [{"kind": "inventory.fresh"}])["verified"]
        host = db.get(Host, "node1")
        host.last_seen = utcnow() - timedelta(minutes=10)
        db.commit()
        assert not verify_inventory(db, "node1", [{"kind": "inventory.fresh"}])["verified"]
        assert not verify_inventory(db, "node1", [{"kind": "whatever"}])["verified"]


def test_loopback_asset_origin_is_allowed_but_foreign_origin_is_rejected(core_env, monkeypatch):
    from serverhub.main import create_app
    from fastapi.testclient import TestClient
    from serverhub.settings import get_settings

    web = core_env / "web"
    (web / "assets").mkdir(parents=True)
    (web / "index.html").write_text('<html><script src="/assets/app.js"></script></html>')
    (web / "assets/app.js").write_text("window.ready=true;")
    monkeypatch.setenv("SERVERHUB_PUBLIC_URL", "https://serverhub.example")
    monkeypatch.setenv("SERVERHUB_ALLOWED_ORIGINS", '["https://serverhub.example"]')
    get_settings.cache_clear()
    with TestClient(create_app(), base_url="http://127.0.0.1:9080") as browser:
        assert browser.get("/assets/app.js", headers={"Origin": "http://127.0.0.1:9080"}).status_code == 200
        assert browser.get("/assets/app.js", headers={"Origin": "https://evil.example"}).status_code == 403
        assert (
            browser.post("/api/auth/login", headers={"Origin": "http://127.0.0.1:9999"}, json={}).status_code
            == 403
        )


def test_migration_config_never_requires_the_callers_working_directory(tmp_path, monkeypatch):
    from serverhub.cli import _alembic_config

    release = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("SERVERHUB_RELEASE_DIR", str(release))
    monkeypatch.setattr(
        Path, "cwd", classmethod(lambda cls: (_ for _ in ()).throw(PermissionError("inaccessible")))
    )
    cfg = _alembic_config()
    assert Path(cfg.get_main_option("script_location")).is_absolute()
    assert cfg.get_main_option("prepend_sys_path") == ""


def test_sandbox_masks_optional_paths_without_requiring_them():
    source = Path(__file__).resolve().parents[1]
    for filename in ("serverhub-api.service", "serverhub-worker.service", "serverhub-node.service"):
        content = (source / "packaging/systemd" / filename).read_text()
        paths = (
            next(line for line in content.splitlines() if line.startswith("InaccessiblePaths="))
            .split("=", 1)[1]
            .split()
        )
        assert all(path.startswith("-/") for path in paths)
        assert "ProtectSystem=strict" in content and "NoNewPrivileges=true" in content


def test_diagnostics_explains_missing_model_worker_and_assets(client):
    with SessionLocal() as db:
        headers = bearer(db)
    response = client.get("/api/diagnostics", headers=headers)
    assert response.status_code == 200, response.text
    checks = {item["id"]: item for item in response.json()["checks"]}
    assert checks["worker"]["status"] == "error"
    assert checks["models"]["status"] == "error"
    assert checks["frontend"]["remediation"]


def test_inventory_verification_requires_a_recent_report_not_only_a_heartbeat(core_env):
    with SessionLocal() as db:
        db.add(InventorySample(host_id="node1", metrics={}, created_at=utcnow() - timedelta(hours=2)))
        db.commit()
        assert verify_inventory(db, "node1", [{"kind": "host.online"}])["verified"]
        assert not verify_inventory(db, "node1", [{"kind": "inventory.fresh"}])["verified"]


def test_install_resume_retains_credentials_configuration_and_completed_phases(tmp_path, monkeypatch):
    import subprocess
    import serverhub.ops.installer as native
    import shutil

    original = Path(__file__).resolve().parents[1]
    source = tmp_path / "fixture-source"
    shutil.copytree(
        original,
        source,
        ignore=shutil.ignore_patterns(
            ".git", "node_modules", "dist", ".build-venv", "__pycache__", ".pytest_cache", ".ruff_cache"
        ),
    )
    (source / "dist").mkdir()
    (source / "dist/serverhub_ai_os-test.whl").write_text("fixture wheel; runner is mocked")
    (source / "frontend/dist/assets").mkdir(parents=True)
    (source / "frontend/dist/index.html").write_text('<html><script src="/assets/app.js"></script></html>')
    (source / "frontend/dist/assets/app.js").write_text("window.ready=true;")
    monkeypatch.setattr(
        native, "check_compatibility", lambda *args: {"compatible": True, "ready_for_apply": True}
    )
    monkeypatch.setattr(native.os, "chown", lambda *args: None)
    monkeypatch.setattr(native.os, "getgrouplist", lambda *args: [])
    monkeypatch.setattr(
        native.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(
            pw_shell="/usr/sbin/nologin", pw_dir=native.ACCOUNTS[name], pw_uid=999, pw_gid=999
        ),
    )
    monkeypatch.setattr(native.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=999))
    monkeypatch.setattr(native.Installer, "_activate", lambda *args: None)
    monkeypatch.setattr(native.Installer, "_healthchecks", lambda *args: None)
    calls = []
    failed = [False]

    def run(command, **kwargs):
        calls.append(command)
        if command[-1] == "migrate" and not failed[0]:
            failed[0] = True
            raise subprocess.CalledProcessError(1, command, stderr="controlled interrupted migration")
        assert kwargs["cwd"] == "/" or str(tmp_path) in kwargs["cwd"]
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    installer = native.Installer(source, root=tmp_path, runner=run)
    with pytest.raises(native.InstallError, match="rerun"):
        installer._apply_locked(False, "owner", None, False)
    journal = tmp_path / "var/lib/serverhub-install/state.json"
    before = json.loads(journal.read_text())
    configuration = (tmp_path / "etc/serverhub/api.env").read_bytes()
    assert journal.stat().st_mode & 0o777 == 0o600
    assert before["phase"] == "migrations" and before["state"] == "interrupted"
    assert installer._apply_locked(False, "owner", None, False)["state"] == "installed"
    after = json.loads(journal.read_text())
    assert after["credentials"] == before["credentials"]
    assert (tmp_path / "etc/serverhub/api.env").read_bytes() == configuration
    assert len([c for c in calls if c[0] == "createdb"]) == 0  # createdb is invoked through runuser
    assert len([c for c in calls if "createdb" in c]) == 1
    ownerfile = tmp_path / "etc/serverhub/bootstrap-owner.txt"
    ownerfile.unlink()
    assert installer._apply_locked(False, "owner", None, False)["state"] == "installed"
    assert not ownerfile.exists()  # no password reset/republication on repeat install


def test_optional_real_ollama_probe():
    import os

    endpoint = os.environ.get("SERVERHUB_TEST_OLLAMA_URL")
    model = os.environ.get("SERVERHUB_TEST_OLLAMA_MODEL")
    if not endpoint or not model:
        pytest.skip("Optional real Ollama provider is not configured")
    config = ProviderConfig(
        kind="ollama",
        base_url=endpoint,
        model=model,
        allow_insecure_http=os.environ.get("SERVERHUB_TEST_OLLAMA_PRIVATE_HTTP") == "true",
    )
    assert probe_model(config)["ready"]


def test_upgrade_of_existing_0003_schema_adds_runtime_without_erasing_grants(tmp_path, monkeypatch):
    from serverhub.settings import get_settings
    from serverhub.models import Base
    from serverhub.cli import _alembic_config
    from alembic import command

    monkeypatch.setenv("SERVERHUB_DEV_MODE", "true")
    monkeypatch.setenv("SERVERHUB_DATABASE_URL", f"sqlite:///{tmp_path / 'legacy.sqlite'}")
    get_settings.cache_clear()
    Base.metadata.create_all(get_engine())
    with get_engine().begin() as connection:
        connection.execute(text("DROP TABLE model_routes"))
        connection.execute(text("DROP TABLE worker_heartbeats"))
        connection.execute(text("ALTER TABLE policies DROP COLUMN environment"))
    command.stamp(_alembic_config(), "0003_schedules")
    command.upgrade(_alembic_config(), "head")
    command.upgrade(_alembic_config(), "head")
    with get_engine().connect() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0004_runtime"
        connection.execute(text("SELECT environment FROM policies"))
        connection.execute(text("SELECT name FROM model_routes"))
    get_engine().dispose()
    get_settings.cache_clear()


def test_redaction_preserves_policy_scope_but_masks_log_credentials():
    from serverhub.audit import redact

    assert redact({"environment": "staging"})["environment"] == "staging"
    assert redact({"environment": {"SECRET": "value"}})["environment"] == "[REDACTED]"
    value = redact(
        'password=hunter2 api_key="example-secret" postgresql://owner:db-secret@localhost/test Bearer abcdef'
    )
    assert all(secret not in value for secret in ("hunter2", "example-secret", "db-secret", "abcdef"))


def test_invalid_legacy_model_settings_never_echo_credentials_into_job_errors(tmp_path, monkeypatch):
    from serverhub.ai.providers import load_routes

    monkeypatch.setenv("SERVERHUB_DEV_MODE", "true")
    config = tmp_path / "models.yaml"
    config.write_text(
        "routes:\n  default:\n    kind: ollama\n    base_url: http://127.0.0.1\n    model: test\n    api_key: private-secret-should-not-escape\n"
    )
    config.chmod(0o600)
    with pytest.raises(ValueError) as failure:
        load_routes(config)
    assert "private-secret-should-not-escape" not in str(failure.value)
    config.write_text('routes: [broken, "private-secret-should-not-escape]')
    with pytest.raises(ValueError) as failure:
        load_routes(config)
    assert "private-secret-should-not-escape" not in str(failure.value)
