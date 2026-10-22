"""OAuth control-plane records; the worker has no grants on these tables."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .database import utcnow
from .models import Base, new_id


class OAuthClient(Base):
    __tablename__ = "oauth_clients"
    id: Mapped[str] = mapped_column(String(100), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(150))
    redirect_uris: Mapped[list] = mapped_column(JSON)
    secret_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class OAuthPending(Base):
    __tablename__ = "oauth_pending"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    parameters: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class OAuthCode(Base):
    __tablename__ = "oauth_codes"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    client_id: Mapped[str] = mapped_column(ForeignKey("oauth_clients.id"))
    redirect_uri: Mapped[str] = mapped_column(String(2048))
    challenge: Mapped[str] = mapped_column(String(128))
    resource: Mapped[str] = mapped_column(String(2048))
    scopes: Mapped[list] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)


class OAuthRefresh(Base):
    __tablename__ = "oauth_refresh"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    family: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    client_id: Mapped[str] = mapped_column(ForeignKey("oauth_clients.id"))
    resource: Mapped[str] = mapped_column(String(2048))
    scopes: Mapped[list] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
