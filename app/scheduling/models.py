from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class Appointment(Record, Base):
    __tablename__ = "appointments"
    __table_args__ = (
        CheckConstraint("ends_at > starts_at", name="appointment_positive_duration"),
        {"schema": "tenant"},
    )
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    provider_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    chair: Mapped[str] = mapped_column(String(40))
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    procedure: Mapped[str] = mapped_column(String(180))
    status: Mapped[str] = mapped_column(String(25), default="confirmed")
    cancellation_reason: Mapped[str] = mapped_column(String(500), default="")
