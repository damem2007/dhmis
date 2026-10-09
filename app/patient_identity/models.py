from sqlalchemy import BigInteger, Boolean, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class PatientUser(Record, Base):
    __tablename__ = "patient_users"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"), unique=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(String(300))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    token_version: Mapped[int] = mapped_column(Integer, default=1)


class PatientSession(Record, Base):
    __tablename__ = "patient_sessions"
    __table_args__ = {"schema": "tenant"}
    user_id: Mapped[str] = mapped_column(ForeignKey("tenant.patient_users.id"))
    expires: Mapped[int] = mapped_column(BigInteger)
    last_active: Mapped[int] = mapped_column(BigInteger)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class PatientInvite(Record, Base):
    __tablename__ = "patient_invites"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    email: Mapped[str] = mapped_column(String(254))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires: Mapped[int] = mapped_column(BigInteger)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class PatientVerificationChallenge(Record, Base):
    __tablename__ = "patient_verification_challenges"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    appointment_id: Mapped[str | None] = mapped_column(
        ForeignKey("tenant.appointments.id"), nullable=True
    )
    email: Mapped[str] = mapped_column(String(254))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    expires: Mapped[int] = mapped_column(BigInteger)
    resend_after: Mapped[int] = mapped_column(BigInteger)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
