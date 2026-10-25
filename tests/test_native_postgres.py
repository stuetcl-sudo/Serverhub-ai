"""Real PostgreSQL grants and real pg_dump/pg_restore, only on confirmed test DBs."""

import os
import secrets
import shutil
from uuid import uuid4

import psycopg
from psycopg import sql
import pytest
from sqlalchemy.engine import make_url

from serverhub.database import get_engine
from serverhub.settings import get_settings


@pytest.fixture
def native_pg(monkeypatch):
    raw = os.environ.get("SERVERHUB_TEST_POSTGRES_URL")
    if not raw:
        pytest.skip("Disposable PostgreSQL URL not configured")
    source = make_url(raw)
    if (
        "test" not in (source.database or "").lower()
        or os.environ.get("SERVERHUB_TEST_DATABASE_CONFIRM") != "isolated"
    ):
        pytest.fail("Native PostgreSQL tests require a confirmed isolated test instance")
    database = "native_test_" + uuid4().hex[:12]
    roles = {name: "sh_" + name + "_" + uuid4().hex[:10] for name in ("api", "worker", "migrate")}
    passwords = {name: secrets.token_hex(24) for name in roles}
    admin_dsn = source.set(drivername="postgresql").render_as_string(hide_password=False)
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        for name, role in roles.items():
            admin.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(passwords[name])
                )
            )
        admin.execute(
            sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0 ENCODING 'UTF8'").format(
                sql.Identifier(database), sql.Identifier(roles["migrate"])
            )
        )
    urls = {
        name: source.set(database=database, username=role, password=passwords[name])
        for name, role in roles.items()
    }
    db_admin = source.set(database=database, drivername="postgresql").render_as_string(hide_password=False)
    try:
        monkeypatch.setenv("SERVERHUB_DATABASE_URL", urls["migrate"].render_as_string(hide_password=False))
        monkeypatch.setenv("SERVERHUB_DEV_MODE", "true")
        get_settings.cache_clear()
        from serverhub.cli import _alembic_config
        from alembic import command

        command.upgrade(_alembic_config(), "head")
        from pathlib import Path

        grants = (
            Path("packaging/postgresql-grants.sql")
            .read_text()
            .replace("DATABASE serverhub ", "DATABASE " + database + " ")
        )
        for name, role in roles.items():
            grants = grants.replace("serverhub_" + name, role)
        with psycopg.connect(db_admin, autocommit=True) as connection:
            connection.execute(grants)
        yield {"urls": urls, "admin": admin_dsn, "db_admin": db_admin}
    finally:
        get_engine().dispose()
        get_settings.cache_clear()
        with psycopg.connect(admin_dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))
            for role in roles.values():
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_native_postgres_worker_cannot_modify_its_trust_boundaries(native_pg):
    url = native_pg["urls"]["worker"].set(drivername="postgresql").render_as_string(hide_password=False)
    with psycopg.connect(url, autocommit=True) as worker:
        worker.execute("SELECT id FROM policies LIMIT 1")
        worker.execute("UPDATE schedules SET next_run=now() WHERE false")
        for statement in (
            "UPDATE policies SET enabled=false",
            "DELETE FROM audit",
            "TRUNCATE audit",
            "UPDATE system_state SET value='{}'",
            "DELETE FROM backups",
            "SELECT * FROM session_tokens",
            "SELECT * FROM oauth_codes",
            "SELECT * FROM oauth_refresh",
            "SELECT * FROM enrollments",
            "UPDATE schedules SET spec='{}'",
            "UPDATE schedules SET enabled=false",
            "ALTER TABLE audit DISABLE TRIGGER ALL",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute(statement)


def test_native_real_postgres_backup_checksum_and_restore_drill(native_pg, tmp_path):
    if not all(shutil.which(name) for name in ("pg_dump", "pg_restore", "createdb", "dropdb", "psql")):
        pytest.skip("PostgreSQL native client tools unavailable")
    from serverhub.ops.backup import BackupManager

    manager = BackupManager(tmp_path / "protected-backups", require_root=False)
    configuration = tmp_path / "operator-config.yaml"
    configuration.write_text("test_configuration: isolated\n")
    manifest = manager.create(native_pg["db_admin"], [configuration])
    assert manager.verify(manifest["id"])["files"]["postgres.dump"]["size"] > 0
    result = manager.restore_drill(manifest["id"], native_pg["admin"])
    assert result["state"] == "verified"
    assert result["restored_tables"] >= 20


def test_worker_cannot_reconfigure_models_but_can_publish_liveness(native_pg):
    url = native_pg['urls']['worker'].set(drivername='postgresql').render_as_string(hide_password=False)
    with psycopg.connect(url, autocommit=True) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.execute("UPDATE model_routes SET enabled=false")
        worker.execute("INSERT INTO worker_heartbeats (worker_id,seen_at) VALUES ('isolated-worker',CURRENT_TIMESTAMP)")
        assert worker.execute("SELECT worker_id FROM worker_heartbeats").fetchone()[0]=='isolated-worker'


def test_worker_runtime_accounting_does_not_grant_system_state_writes(native_pg):
    url = native_pg['urls']['worker'].set(drivername='postgresql').render_as_string(hide_password=False)
    with psycopg.connect(url, autocommit=True) as worker:
        worker.execute("INSERT INTO job_control_state (key,value,updated_at) VALUES ('quota-test','{}',CURRENT_TIMESTAMP)")
        worker.execute("UPDATE job_control_state SET value='{\"tokens\":42}' WHERE key='quota-test'")
        assert worker.execute("SELECT value FROM job_control_state WHERE key='quota-test'").fetchone()[0]['tokens'] == 42
        for statement in ("DELETE FROM job_control_state", "TRUNCATE job_control_state",
                          "UPDATE system_state SET value='{}'", "UPDATE policies SET enabled=false"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute(statement)


def test_quota_admitted_by_api_can_be_charged_by_actual_worker(native_pg):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from serverhub.job_limits import admit_job, charge_daily
    from serverhub.models import JobControlState
    from serverhub.database import utcnow
    api_engine = create_engine(native_pg['urls']['api'])
    worker_engine = create_engine(native_pg['urls']['worker'])
    key = 'job-quota:' + utcnow().date().isoformat() + ':isolated-quota-user'
    try:
        with Session(api_engine) as db:
            admit_job(db, 'isolated-quota-user', 60)
            db.commit()
        with Session(worker_engine) as db:
            charge_daily(db, 'isolated-quota-user', 4200, 0)
            db.commit()
            assert db.get(JobControlState, key).value == {'tokens': 4200, 'cost': 0, 'runtime': 60, 'jobs': 1}
            charge_daily(db, 'isolated-quota-user', 100, .01)
            db.commit()
            assert db.get(JobControlState, key).value['tokens'] == 4300
    finally:
        api_engine.dispose()
        worker_engine.dispose()
