from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class LabCase(Record, Base):
    __tablename__ = "lab_cases"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    provider_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    case_type: Mapped[str] = mapped_column(String(120))
    laboratory: Mapped[str] = mapped_column(String(180))
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(30), default="created")
    notes: Mapped[str] = mapped_column(String(2000), default="")
    status_history: Mapped[list] = mapped_column(JSON, default=list)


class Referral(Record, Base):
    __tablename__ = "referrals"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    provider_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    direction: Mapped[str] = mapped_column(String(20))
    specialty: Mapped[str] = mapped_column(String(120))
    organization_name: Mapped[str] = mapped_column(String(180))
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(30), default="created")
    reason: Mapped[str] = mapped_column(String(2000))
    status_history: Mapped[list] = mapped_column(JSON, default=list)

