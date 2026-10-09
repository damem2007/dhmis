from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class MedicationSafetyRule(Record, Base):
    __tablename__ = "medication_safety_rules"
    __table_args__ = {"schema": "tenant"}
    medication: Mapped[str] = mapped_column(String(160))
    conflicts: Mapped[list] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(20), default="warning")
    message: Mapped[str] = mapped_column(String(500))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Prescription(Record, Base):
    __tablename__ = "prescriptions"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    prescriber_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    medication: Mapped[str] = mapped_column(String(160))
    dosage: Mapped[str] = mapped_column(String(120))
    route: Mapped[str] = mapped_column(String(60), default="oral")
    frequency: Mapped[str] = mapped_column(String(120))
    duration_days: Mapped[int] = mapped_column(Integer)
    instructions: Mapped[str] = mapped_column(String(1000), default="")
    controlled_substance: Mapped[bool] = mapped_column(Boolean, default=False)
    safety_flags: Mapped[list] = mapped_column(JSON, default=list)
    override_reason: Mapped[str] = mapped_column(String(1000), default="")
    status: Mapped[str] = mapped_column(String(30), default="issued")
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

