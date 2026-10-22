from datetime import datetime
from uuid import uuid4
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .database import utcnow


def new_id():
    return str(uuid4())


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(32), default="readonly")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SessionToken(Base):
    __tablename__ = "session_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    label: Mapped[str] = mapped_column(String(120), default="session")
    audience: Mapped[str | None] = mapped_column(String(500), nullable=True)
    scopes: Mapped[list] = mapped_column(JSON, default=list)


class Host(Base):
    __tablename__ = "hosts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    group_name: Mapped[str] = mapped_column(String(100), default="default")
    identity: Mapped[str] = mapped_column(String(200), default="")
    agent_secret_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    inventory: Mapped[dict] = mapped_column(JSON, default=dict)
    agent_version: Mapped[str] = mapped_column(String(50), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Enrollment(Base):
    __tablename__ = "enrollments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    group_name: Mapped[str] = mapped_column(String(100), default="default")
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    subject_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("hosts.id"), nullable=True)
    project: Mapped[str | None] = mapped_column(String(200), nullable=True)
    operations: Mapped[list] = mapped_column(JSON, default=list)
    constraints: Mapped[dict] = mapped_column(JSON, default=dict)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    production: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (UniqueConstraint("owner_id", "idempotency_key", name="uq_job_owner_idempotency"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("hosts.id"), nullable=True, index=True)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("jobs.id"), nullable=True)
    project: Mapped[str | None] = mapped_column(String(200), nullable=True)
    kind: Mapped[str] = mapped_column(String(60))
    spec: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    checkpoint: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_class: Mapped[str | None] = mapped_column(String(60), nullable=True)
    depends_on: Mapped[list] = mapped_column(JSON, default=list)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    time_limit: Mapped[int] = mapped_column(Integer, default=3600)
    token_budget: Mapped[int] = mapped_column(Integer, default=20000)
    cost_budget: Mapped[float] = mapped_column(Float, default=1.0)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    cost_used: Mapped[float] = mapped_column(Float, default=0.0)
    run_after: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    worker_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class JobEvent(Base):
    __tablename__ = "job_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    level: Mapped[str] = mapped_column(String(20), default="info")
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(150))
    target: Mapped[str] = mapped_column(String(200), default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("host_id", "key", name="uq_finding_host_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    key: Mapped[str] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    service: Mapped[str] = mapped_column(String(200), default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(30), default="open")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("hosts.id"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(20), default="warning")
    state: Mapped[str] = mapped_column(String(30), default="open")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    root_cause: Mapped[str] = mapped_column(Text, default="")
    resolution: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Memory(Base):
    __tablename__ = "memories"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("hosts.id"), nullable=True, index=True)
    project: Mapped[str | None] = mapped_column(String(200), nullable=True)
    kind: Mapped[str] = mapped_column(String(60), default="observation")
    content: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Backup(Base):
    __tablename__ = "backups"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("hosts.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(60), default="database")
    state: Mapped[str] = mapped_column(String(30), default="pending")
    path: Mapped[str] = mapped_column(Text, default="")
    checksum: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AgentCommand(Base):
    __tablename__ = "agent_commands"
    __table_args__ = (UniqueConstraint("host_id", "idempotency_key", name="uq_command_host_idempotency"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    job_id: Mapped[str | None] = mapped_column(ForeignKey("jobs.id"), nullable=True)
    operation: Mapped[str] = mapped_column(String(150))
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(200))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SystemState(Base):
    __tablename__ = "system_state"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class InventorySample(Base):
    __tablename__ = "inventory_samples"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class GraphEdge(Base):
    __tablename__ = "graph_edges"
    __table_args__ = (UniqueConstraint("host_id", "source", "target", "relation", name="uq_graph_edge"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    source: Mapped[str] = mapped_column(String(300))
    target: Mapped[str] = mapped_column(String(300))
    relation: Mapped[str] = mapped_column(String(100))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


Index("ix_job_claim", Job.state, Job.run_after, Job.lease_until)


def to_dict(model: Any, exclude: set[str] | None = None) -> dict:
    result = {}
    for column in model.__table__.columns:
        if column.name in (exclude or set()):
            continue
        value = getattr(model, column.name)
        result[column.name] = value.isoformat() + "Z" if isinstance(value, datetime) else value
    return result
