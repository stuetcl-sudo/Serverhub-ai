"""Append-only, hash-linked audit trail. PostgreSQL grants prevent worker updates/deletes.

A chain detects accidental/tampered rows; an external append-only sink remains necessary
against a compromised database administrator. Never call this cryptographic non-repudiation.
"""
import hashlib
import json
import re
import threading
from datetime import datetime

from sqlalchemy import select, text

from .database import utcnow
from .models import Audit

_LOCK = threading.RLock()
_SECRET_KEYS = re.compile(r"password|secret|token|credential|authorization|cookie|private.key|api.key|environment", re.I)
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9+/_=:.~-]+")


def redact(value, key: str = ""):
    if _SECRET_KEYS.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value[:1000]]
    if isinstance(value, str):
        return _BEARER.sub("[REDACTED AUTH]", value)[:16000]
    if isinstance(value, datetime):
        return value.isoformat() + "Z"
    return value


def audit_hash(actor, action, target, data, created_at, prev_hash):
    body = {"actor": actor, "action": action, "target": target, "data": data,
            "created_at": created_at.isoformat(), "prev_hash": prev_hash}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def append_audit(db, actor: str, action: str, target: str = "", data: dict | None = None) -> Audit:
    with _LOCK:
        # Serialize concurrent appenders across API/worker processes until their transaction commits.
        if db.bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(734882101)"))
        previous = db.scalar(select(Audit).order_by(Audit.id.desc()).limit(1))
        prev_hash = previous.hash if previous else "0" * 64
        at = utcnow()
        cleaned = redact(data or {})
        record = Audit(actor=actor, action=action, target=target, data=cleaned,
                       created_at=at, prev_hash=prev_hash,
                       hash=audit_hash(actor, action, target, cleaned, at, prev_hash))
        db.add(record)
        db.flush()
        return record


def verify_chain(db) -> dict:
    previous = "0" * 64
    count = 0
    for row in db.scalars(select(Audit).order_by(Audit.id)):
        expected = audit_hash(row.actor, row.action, row.target, row.data, row.created_at, previous)
        if row.prev_hash != previous or row.hash != expected:
            return {"valid": False, "checked": count, "broken_at": row.id}
        previous = row.hash
        count += 1
    return {"valid": True, "checked": count, "head": previous}
