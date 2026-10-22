"""PostgreSQL integration tests; only an explicitly confirmed disposable DB is used.

Set SERVERHUB_TEST_POSTGRES_URL to a database whose name contains 'test' and
SERVERHUB_TEST_DATABASE_CONFIRM=isolated. Every test owns a random schema; existing
schemas and production data are never modified.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import os
import time
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from serverhub.audit import append_audit, verify_chain
from serverhub.auth import Principal, hash_password
from serverhub.database import SessionLocal, get_engine, utcnow
from serverhub.jobs import HANDLERS, Worker, submit_job
from serverhub.models import Host, Job, User
from serverhub.settings import get_settings


@pytest.fixture
def pg_env(monkeypatch):
    source = os.environ.get("SERVERHUB_TEST_POSTGRES_URL")
    if not source:
        pytest.skip("Disposable PostgreSQL URL not configured")
    url = make_url(source)
    if "test" not in (url.database or "").lower() or os.environ.get("SERVERHUB_TEST_DATABASE_CONFIRM") != "isolated":
        pytest.fail("PostgreSQL tests require an explicitly confirmed isolated test database")
    schema = "core_test_" + uuid4().hex
    admin = create_engine(source)
    with admin.begin() as connection:
        connection.execute(text('CREATE SCHEMA "' + schema + '"'))
    isolated = url.update_query_dict({"options": "-csearch_path=" + schema})
    monkeypatch.setenv("SERVERHUB_DATABASE_URL", isolated.render_as_string(hide_password=False))
    monkeypatch.setenv("SERVERHUB_DEV_MODE", "true")
    get_settings.cache_clear()
    from serverhub.cli import _alembic_config
    from alembic import command
    command.upgrade(_alembic_config(), "head")
    with SessionLocal() as db:
        db.add(User(id="pgowner", username="pgowner", password_hash=hash_password("isolated-postgres-password"), role="owner"))
        db.add(Host(id="pghost", name="disposable"))
        db.commit()
    yield Principal("pgowner", "owner", "pgowner")
    get_engine().dispose()
    get_settings.cache_clear()
    with admin.begin() as connection:
        connection.execute(text('DROP SCHEMA "' + schema + '" CASCADE'))
    admin.dispose()


def test_postgres_migration_and_database_audit_protection(pg_env):
    with SessionLocal() as db:
        append_audit(db, pg_env.id, "verified.postgresql")
        db.commit()
        assert verify_chain(db)["valid"]
        with pytest.raises(DBAPIError, match="append-only"):
            db.execute(text("UPDATE audit SET action='tampered'"))
        db.rollback()
        with pytest.raises(DBAPIError, match="append-only"):
            db.execute(text("DELETE FROM audit"))
        db.rollback()
        assert verify_chain(db)["valid"]


def test_postgres_worker_separate_process_lifecycle(pg_env, monkeypatch):
    def work(ctx, spec):
        ctx.save_checkpoint({"verified": True})
        return {"executed_in_process": os.getpid()}
    monkeypatch.setitem(HANDLERS, "pg_process", work)
    with SessionLocal() as db:
        job = submit_job(db, pg_env, "pg_process", {})
        job_id = job.id
        db.commit()
    assert Worker(isolated=True).run_once()
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.state == "succeeded", job.error
        assert job.checkpoint["verified"] is True
        assert job.result["executed_in_process"] != os.getpid()
        assert job.worker_id is None


def test_postgres_concurrent_claim_obeys_per_host_limit(pg_env, monkeypatch):
    monkeypatch.setitem(HANDLERS, "pg_claim", lambda ctx, spec: {})
    with SessionLocal() as db:
        for index in range(4):
            submit_job(db, pg_env, "pg_claim", {"i": index}, host_id="pghost")
        db.commit()
    with ThreadPoolExecutor(max_workers=4) as executor:
        claimed = list(executor.map(lambda _: Worker()._claim(), range(4)))
    assert sum(item is not None for item in claimed) == 1
    with SessionLocal() as db:
        assert len(db.scalars(select(Job).where(Job.state == "running")).all()) == 1


def test_postgres_restart_recovery_preserves_checkpoint(pg_env, monkeypatch):
    monkeypatch.setitem(HANDLERS, "pg_recovery", lambda ctx, spec: {"previous": ctx.job.checkpoint["step"]})
    with SessionLocal() as db:
        job = submit_job(db, pg_env, "pg_recovery", {})
        job.state, job.worker_id = "running", "terminated-worker"
        job.lease_until = utcnow() - timedelta(seconds=1)
        job.attempts, job.checkpoint = 1, {"step": "committed-before-restart"}
        job_id = job.id
        db.commit()
    assert Worker(isolated=True).run_once()
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.state == "succeeded", job.error
        assert job.attempts == 2
        assert job.result["previous"] == "committed-before-restart"


def test_postgres_supervisor_enforces_deadline_without_handler_cooperation(pg_env, monkeypatch):
    def blocked(ctx, spec):
        time.sleep(10)
        return {"unexpected": "deadline ignored"}
    monkeypatch.setitem(HANDLERS, "pg_deadline", blocked)
    with SessionLocal() as db:
        job = submit_job(db, pg_env, "pg_deadline", {}, time_limit=1)
        job_id = job.id
        db.commit()
    began = time.monotonic()
    assert Worker(isolated=True).run_once()
    assert time.monotonic() - began < 6
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.state == "failed"
        assert job.failure_class == "timeout"
        assert not job.result
