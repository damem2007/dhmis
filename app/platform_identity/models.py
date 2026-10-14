from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


# Defines the platform user model, contract, or value object.
class PlatformUser(Record, Base):
    __tablename__ = "platform_users"
    __table_args__ = {"schema": "dhmis_control"}
    email: Mapped[str] = mapped_column(String(254), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    role: Mapped[str] = mapped_column(String(30), default="platform_admin")
    password_hash: Mapped[str] = mapped_column(String(300))
    mfa_secret: Mapped[str] = mapped_column(String(1000), default="")
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_counter: Mapped[int] = mapped_column(BigInteger, default=-1)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    token_version: Mapped[int] = mapped_column(Integer, default=1)


# Defines the platform challenge model, contract, or value object.
class PlatformChallenge(Record, Base):
    __tablename__ = "platform_challenges"
    __table_args__ = {"schema": "dhmis_control"}
    user_id: Mapped[str] = mapped_column(String(36))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires: Mapped[int] = mapped_column(BigInteger)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


# Defines the platform session model, contract, or value object.
class PlatformSession(Record, Base):
    __tablename__ = "platform_sessions"
    __table_args__ = {"schema": "dhmis_control"}
    user_id: Mapped[str] = mapped_column(String(36))
    expires: Mapped[int] = mapped_column(BigInteger)
    last_active: Mapped[int] = mapped_column(BigInteger)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


# Defines the platform audit event model, contract, or value object.
class PlatformAuditEvent(Record, Base):
    __tablename__ = "platform_audit_events"
    __table_args__ = {"schema": "dhmis_control"}
    actor_id: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reason: Mapped[str] = mapped_column(String(1000), default="")
    details: Mapped[dict] = mapped_column(JSONB, default=dict)


class PlatformSupportTicket(Record, Base):
    """Support-owned ticket record shared by platform modules.

    Billing may create and reference tickets, but ticket lifecycle remains in
    this Support-owned table rather than in billing tables.
    """

    __tablename__ = "platform_support_tickets"
    __table_args__ = {"schema": "dhmis_control"}
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    source: Mapped[str] = mapped_column(String(40), default="support")
    subscription_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    category: Mapped[str] = mapped_column(String(80), default="General")
    priority: Mapped[str] = mapped_column(String(20), default="normal")
    subject: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(String(4000))
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    assignee_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    context: Mapped[dict] = mapped_column(JSONB, default=dict)


# Defines the platform invite model, contract, or value object.
class PlatformInvite(Record, Base):
    __tablename__ = "platform_invites"
    __table_args__ = {"schema": "dhmis_control"}
    name: Mapped[str] = mapped_column(String(160))
    email: Mapped[str] = mapped_column(String(254))
    role: Mapped[str] = mapped_column(String(160), default="platform_admin")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(30), default="pending")


class PlatformOutboxMessage(Record, Base):
    """Provider-agnostic control-plane delivery record."""

    __tablename__ = "platform_outbox_messages"
    __table_args__ = {"schema": "dhmis_control"}
    kind: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    idempotency_key: Mapped[str] = mapped_column(String(120), unique=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[dict] = mapped_column(JSON, default=dict)


# Defines the platform password reset challenge model, contract, or value object.
class PlatformPasswordResetChallenge(Record, Base):
    __tablename__ = "platform_password_reset_challenges"
    __table_args__ = {"schema": "dhmis_control"}
    user_id: Mapped[str] = mapped_column(String(36))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires: Mapped[int] = mapped_column(BigInteger)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    initiated_by: Mapped[str] = mapped_column(String(100))
    reason: Mapped[str] = mapped_column(String(1000))
