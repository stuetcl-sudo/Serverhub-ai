import hashlib
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select

from .database import get_db, utcnow
from .models import SessionToken, User
from .settings import get_settings

PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
# A fixed Argon hash provides comparable password verification work for absent accounts.
_DUMMY_HASH = PASSWORDS.hash("serverhub-placeholder-never-a-password")
ROLES = {"owner", "administrator", "adult", "user", "readonly"}


@dataclass(frozen=True)
class Principal:
    id: str
    role: str
    username: str


def hash_secret(value: str) -> str:
    """Fast keyed-token fingerprint; passwords use separate Argon2 hashing."""
    return hashlib.sha256(value.encode()).hexdigest()


def verify_secret(value: str, digest: str) -> bool:
    return secrets.compare_digest(hash_secret(value), digest)


def hash_password(value: str) -> str:
    if len(value) < 14 or len(value) > 1024:
        raise ValueError("password must contain 14–1024 characters")
    return PASSWORDS.hash(value)


def verify_password(value: str, encoded: str) -> bool:
    try:
        return PASSWORDS.verify(encoded, value)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def principal_for_user(user: User) -> Principal:
    if not user.enabled or user.role not in ROLES:
        raise HTTPException(401, "Account disabled")
    return Principal(user.id, user.role, user.username)


def create_session(db, user: User, *, hours: float | None = None, label: str = "session",
                   audience: str | None = None, scopes: list | None = None) -> str:
    token = secrets.token_urlsafe(48)
    db.add(SessionToken(user_id=user.id, digest=hash_secret(token), audience=audience,
                        scopes=scopes or [], label=label,
                        expires_at=utcnow() + timedelta(hours=hours if hours is not None else get_settings().session_hours)))
    db.flush()
    return token


def token_principal(db, token: str, *, audience: str | None = None) -> Principal:
    session = db.scalar(select(SessionToken).where(SessionToken.digest == hash_secret(token))
                        .execution_options(populate_existing=True))
    if not session or session.revoked or session.expires_at <= utcnow():
        raise HTTPException(401, "Invalid or expired session", headers={"WWW-Authenticate": "Bearer"})
    if session.audience != audience:
        raise HTTPException(401, "Token audience mismatch")
    user = db.get(User, session.user_id)
    if not user:
        raise HTTPException(401, "Unknown account")
    db.refresh(user)
    return principal_for_user(user)


def request_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization:
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "Bearer token required")
        return authorization[7:]
    return request.cookies.get("serverhub_session", "")


def current_principal(request: Request, db=Depends(get_db)) -> Principal:
    token = request_token(request)
    if not token:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    return token_principal(db, token)


Authenticated = Annotated[Principal, Depends(current_principal)]


def require_owner(principal: Principal):
    if principal.role != "owner":
        raise HTTPException(403, "Owner role required")
