from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class DaySurgeryAdmission(Record, Base):
    __tablename__ = "day_surgery_admissions"
    __table_args__ = {"schema": "tenant"}
    encounter_id: Mapped[str] = mapped_column(ForeignKey("tenant.encounters.id"), unique=True)
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    provider_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    procedure_name: Mapped[str] = mapped_column(String(180))
    status: Mapped[str] = mapped_column(String(30), default="admitted")
    preop_checklist: Mapped[dict] = mapped_column(JSON, default=dict)
    anesthesia_records: Mapped[list] = mapped_column(JSON, default=list)
    recovery_notes: Mapped[str] = mapped_column(String(8000), default="")
    discharge_summary: Mapped[str] = mapped_column(String(8000), default="")

