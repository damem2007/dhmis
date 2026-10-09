from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class StaffUser(Record, Base):
    __tablename__ = "staff_users"
    __table_args__ = {"schema": "tenant"}
    email: Mapped[str] = mapped_column(String(254), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    password_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(30), default="admin")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    token_version: Mapped[int] = mapped_column(Integer, default=1)

    mfa_secret: Mapped[str] = mapped_column(Text, default="")
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_counter: Mapped[int] = mapped_column(BigInteger, default=-1)
    location_ids: Mapped[list] = mapped_column(JSON, default=list)
    external_subject: Mapped[str | None] = mapped_column(String(250), nullable=True, unique=True)
    photo_url: Mapped[str] = mapped_column(String(500), default="")


class AuthChallenge(Record, Base):
    __tablename__ = "auth_challenges"
    __table_args__ = {"schema": "tenant"}
    user_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires: Mapped[int] = mapped_column(BigInteger)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class StaffSession(Record, Base):
    __tablename__ = "staff_sessions"
    __table_args__ = {"schema": "tenant"}
    user_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    expires: Mapped[int] = mapped_column(BigInteger)
    last_active: Mapped[int] = mapped_column(BigInteger)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class StaffInvite(Record, Base):
    __tablename__ = "staff_invites"
    __table_args__ = {"schema": "tenant"}
    email: Mapped[str] = mapped_column(String(254))
    name: Mapped[str] = mapped_column(String(160))
    role: Mapped[str] = mapped_column(String(30))
    location_ids: Mapped[list] = mapped_column(JSON, default=list)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires: Mapped[int] = mapped_column(BigInteger)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    resend_count: Mapped[int] = mapped_column(Integer, default=0)
    supersedes_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class StaffLocationAssignment(Record, Base):
    __tablename__ = "staff_location_assignments"
    __table_args__ = (
        CheckConstraint(
            "(scope = 'organization' AND location_id IS NULL) OR "
            "(scope = 'location' AND location_id IS NOT NULL)",
            name="ck_staff_assignment_scope",
        ),
        Index(
            "uq_staff_active_location_assignment",
            "user_id",
            "location_id",
            unique=True,
            postgresql_where=text("active AND scope = 'location'"),
        ),
        Index(
            "uq_staff_active_organization_assignment",
            "user_id",
            unique=True,
            postgresql_where=text("active AND scope = 'organization'"),
        ),
        {"schema": "tenant"},
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    location_id: Mapped[str | None] = mapped_column(
        ForeignKey("tenant.locations.id"), nullable=True
    )
    scope: Mapped[str] = mapped_column(String(20), default="location")
    role: Mapped[str] = mapped_column(String(30))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    replaced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class StaffInviteAssignment(Record, Base):
    __tablename__ = "staff_invite_assignments"
    __table_args__ = (
        CheckConstraint(
            "(scope = 'organization' AND location_id IS NULL) OR "
            "(scope = 'location' AND location_id IS NOT NULL)",
            name="ck_staff_invite_assignment_scope",
        ),
        Index(
            "uq_staff_invite_location_assignment",
            "invite_id",
            "location_id",
            unique=True,
            postgresql_where=text("scope = 'location'"),
        ),
        Index(
            "uq_staff_invite_organization_assignment",
            "invite_id",
            unique=True,
            postgresql_where=text("scope = 'organization'"),
        ),
        {"schema": "tenant"},
    )
    invite_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_invites.id"))
    email: Mapped[str] = mapped_column(String(254))
    location_id: Mapped[str | None] = mapped_column(
        ForeignKey("tenant.locations.id"), nullable=True
    )
    scope: Mapped[str] = mapped_column(String(20), default="location")
    role: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30), default="pending")


class PasswordResetChallenge(Record, Base):
    __tablename__ = "password_reset_challenges"
    __table_args__ = {"schema": "tenant"}
    user_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires: Mapped[int] = mapped_column(BigInteger)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    initiated_by: Mapped[str] = mapped_column(String(100))
    reason: Mapped[str] = mapped_column(String(1000), default="")


class AuthRateLimit(Base):
    __tablename__ = "auth_rate_limits"
    __table_args__ = {"schema": "dhmis_control"}
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    until: Mapped[int] = mapped_column(BigInteger)
