"""Disposable 0006 backup -> restore -> 0007 migration and compatible recovery drill.

Synthetic data only. Never connects to the production database. A real
production-backup restore remains a separate, owner-authorized release gate.
"""
import os
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import psycopg
from psycopg import sql
import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session


def test_0006_backup_restore_migrate_and_compatible_recovery(monkeypatch, tmp_path):
    raw = os.environ.get("SERVERHUB_TEST_POSTGRES_URL")
    if not raw:
        pytest.skip("Isolated PostgreSQL instance not configured")
    base = make_url(raw)
    if (
        os.environ.get("SERVERHUB_TEST_DATABASE_CONFIRM") != "isolated"
        or "test" not in (base.database or "").lower()
        or base.host not in {"127.0.0.1", "localhost", "::1"}
    ):
        pytest.fail("Restore drill requires an explicitly confirmed local test database")
    if not all(shutil.which(tool) for tool in ("pg_dump", "pg_restore", "psql")):
        pytest.skip("Native PostgreSQL client tools unavailable")

    from alembic import command
    from serverhub.audit import append_audit
    from serverhub.cli import _alembic_config
    from serverhub.database import get_engine
    from serverhub.models import Job, User
    from serverhub.oauth_models import OAuthClient
    from serverhub.ops.backup import BackupManager
    from serverhub.settings import get_settings

    names = ["sh_drill_" + uuid4().hex[:16] for _ in range(3)]
    source_name, migrated_name, recovered_name = names
    role_names = {kind: "sh_drill_" + uuid4().hex[:16] for kind in ("api", "worker", "migrate")}
    passwords = {kind: secrets.token_hex(24) for kind in role_names}
    admin_dsn = base.set(drivername="postgresql").render_as_string(hide_password=False)
    created = []
    roles_created = []

    def url(name):
        return base.set(database=name).render_as_string(hide_password=False)

    def pg_url(name):
        return base.set(database=name, drivername="postgresql").render_as_string(hide_password=False)

    def upgrade(name, revision):
        get_engine().dispose()
        get_settings.cache_clear()
        monkeypatch.setenv("SERVERHUB_DATABASE_URL", url(name))
        monkeypatch.setenv("SERVERHUB_DEV_MODE", "true")
        command.upgrade(_alembic_config(), revision)
        get_engine().dispose()
        get_settings.cache_clear()

    def snapshot(name):
        with psycopg.connect(pg_url(name)) as connection:
            return {
                "revision": connection.execute("SELECT version_num FROM alembic_version").fetchone()[0],
                "user": connection.execute("SELECT username FROM users WHERE id='drill-owner'").fetchone()[0],
                "job": connection.execute(
                    "SELECT state, checkpoint, paused_seconds FROM jobs WHERE id='drill-job'"
                ).fetchone(),
                "oauth": connection.execute(
                    "SELECT name FROM oauth_clients WHERE id='drill-oauth'"
                ).fetchone()[0],
                "audit": connection.execute(
                    "SELECT action, hash FROM audit WHERE actor='drill-owner' ORDER BY id"
                ).fetchall(),
            }

    try:
        with psycopg.connect(admin_dsn, autocommit=True) as admin:
            for role in role_names.values():
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(passwords[next(k for k, v in role_names.items() if v == role)])
                ))
                roles_created.append(role)
            for name in names:
                admin.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(name)))
                created.append(name)

        upgrade(source_name, "0006_pause_clock")
        engine = create_engine(url(source_name))
        try:
            with Session(engine) as db:
                db.add(User(id="drill-owner", username="synthetic-restore-owner",
                            password_hash="not-a-real-password-hash", role="owner"))
                db.flush()
                db.add(Job(id="drill-job", owner_id="drill-owner", kind="development",
                           spec={"synthetic": True}, state="paused",
                           checkpoint={"before_restore": "retained"},
                           paused_at=datetime.now(timezone.utc).replace(tzinfo=None),
                           paused_seconds=12.5))
                db.add(OAuthClient(id="drill-oauth", name="synthetic-oauth-client",
                                   redirect_uris=["https://example.invalid/callback"],
                                   created_by="drill-owner"))
                append_audit(db, "drill-owner", "synthetic.restore.drill")
                db.commit()
        finally:
            engine.dispose()

        before = snapshot(source_name)
        assert before["revision"] == "0006_pause_clock"
        assert before["audit"]

        manager = BackupManager(tmp_path / "isolated-backups", require_root=False)
        manifest = manager.create(url(source_name))
        assert manager.verify(manifest["id"])["files"]["postgres.dump"]["size"] > 0

        manager.restore(manifest["id"], url(migrated_name), confirm_database=migrated_name)
        assert snapshot(migrated_name) == before
        upgrade(migrated_name, "0007_job_controls")

        with psycopg.connect(pg_url(migrated_name)) as connection:
            assert connection.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0007_job_controls"
            assert connection.execute(
                "SELECT to_regclass('public.job_control_state')"
            ).fetchone()[0] == "job_control_state"

        # Apply production-equivalent grants using distinct disposable roles.
        grants = Path("packaging/postgresql-grants.sql").read_text()
        grants = grants.replace("DATABASE serverhub ", "DATABASE " + migrated_name + " ")
        for kind, role in role_names.items():
            grants = grants.replace("serverhub_" + kind, role)
        with psycopg.connect(pg_url(migrated_name), autocommit=True) as admin:
            admin.execute(grants)

        worker_url = base.set(database=migrated_name, username=role_names["worker"],
                              password=passwords["worker"], drivername="postgresql").render_as_string(hide_password=False)
        with psycopg.connect(worker_url, autocommit=True) as worker:
            worker.execute(
                "INSERT INTO job_control_state (key,value,updated_at) "
                "VALUES ('synthetic-quota','{}',CURRENT_TIMESTAMP)"
            )
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute("UPDATE system_state SET value='{}'")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute("SELECT * FROM oauth_clients")

        migrated = snapshot(migrated_name)
        assert {key: value for key, value in migrated.items() if key != "revision"} == {
            key: value for key, value in before.items() if key != "revision"
        }

        # Simulate a failed post-migration activation: restore the untouched
        # 0006 archive into a *different empty database*, never downgrade live data.
        manager.restore(manifest["id"], url(recovered_name), confirm_database=recovered_name)
        assert snapshot(recovered_name) == before
    finally:
        get_engine().dispose()
        get_settings.cache_clear()
        with psycopg.connect(admin_dsn, autocommit=True) as admin:
            for name in reversed(created):
                admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
            for role in reversed(roles_created):
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
