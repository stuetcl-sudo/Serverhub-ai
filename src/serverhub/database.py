from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from .settings import get_settings


def utcnow() -> datetime:
    """All DB timestamps use UTC-naive consistently across PostgreSQL and SQLite."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@lru_cache(maxsize=8)
def engine_for(url: str):
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def sqlite_pragmas(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
    return engine


def get_engine():
    return engine_for(get_settings().database_url)


def SessionLocal():
    return sessionmaker(bind=get_engine(), expire_on_commit=False)()


def get_db():
    with SessionLocal() as db:
        yield db


@contextmanager
def transaction():
    with SessionLocal() as db:
        with db.begin():
            yield db
