"""Concurrent quotas on real PostgreSQL, using a disposable per-test schema."""
from concurrent.futures import ThreadPoolExecutor

from test_core_postgres import pg_env as pg_env
from serverhub.database import SessionLocal
from serverhub.jobs import HANDLERS, Worker, submit_job
from serverhub.job_limits import charge_daily
from serverhub.settings import get_settings
from serverhub.jobs import BudgetExceeded


def test_concurrent_daily_reservations_cannot_oversubscribe(pg_env):
    get_settings().user_daily_tokens = 100
    def reserve(_):
        with SessionLocal() as db:
            try:
                charge_daily(db, pg_env.id, 40, 0)
                db.commit()
                return True
            except BudgetExceeded:
                db.rollback()
                return False
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(reserve, range(4))) == 2


def test_concurrent_submission_idempotence_and_per_user_claim(pg_env, monkeypatch):
    monkeypatch.setitem(HANDLERS, 'pg_quota', lambda *_: {})
    get_settings().max_user_jobs = 1
    def submit(_):
        with SessionLocal() as db:
            job = submit_job(db, pg_env, 'pg_quota', {}, idempotency_key='same-request')
            db.commit()
            return job.id
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert len(set(pool.map(submit, range(4)))) == 1
    with SessionLocal() as db:
        submit_job(db, pg_env, 'pg_quota', {})
        db.commit()
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(value is not None for value in pool.map(lambda _: Worker()._claim(), range(4))) == 1
