from datetime import date, datetime

from sqlalchemy import JSON, Date, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class Patient(Record, Base):
    __tablename__ = "patients"
    __table_args__ = {"schema": "tenant"}
    first_name: Mapped[str] = mapped_column(String(80))
    last_name: Mapped[str] = mapped_column(String(80))
    birth_date: Mapped[date] = mapped_column(Date)
    email: Mapped[str] = mapped_column(String(254), default="")
    phone: Mapped[str] = mapped_column(String(40), default="")
    allergies: Mapped[list] = mapped_column(JSON, default=list)
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))

    medical_history: Mapped[str] = mapped_column(String(8000), default="")
    dental_history: Mapped[str] = mapped_column(String(8000), default="")
    alerts: Mapped[list] = mapped_column(JSON, default=list)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    archive_reason: Mapped[str] = mapped_column(String(1000), default="")


class GuardianLink(Record, Base):
    __tablename__ = "guardian_links"
    __table_args__ = {"schema": "tenant"}
    guardian_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    dependent_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    relationship: Mapped[str] = mapped_column(String(60))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
