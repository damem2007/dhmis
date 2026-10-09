from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class ChartEntry(Record, Base):
    __tablename__ = "chart_entries"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    tooth: Mapped[str] = mapped_column(String(3))
    encounter_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.encounters.id"), nullable=True)
    surface: Mapped[str] = mapped_column(String(20))
    condition: Mapped[str] = mapped_column(String(100))
    notes: Mapped[str] = mapped_column(String(4000), default="")


class PerioExam(Record, Base):
    __tablename__ = "perio_exams"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    measurements: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="draft")
    dentition: Mapped[list] = mapped_column(JSON, default=list)
    encounter_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.encounters.id"), nullable=True)


class Encounter(Record, Base):
    __tablename__ = "encounters"
    __table_args__ = {"schema": "tenant"}
    appointment_id: Mapped[str] = mapped_column(ForeignKey("tenant.appointments.id"), unique=True)
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    provider_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    status: Mapped[str] = mapped_column(String(20), default="open")
    soap: Mapped[dict] = mapped_column(JSON, default=dict)
    procedures: Mapped[list] = mapped_column(JSON, default=list)
    invoice_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.invoices.id"), nullable=True)
    care_setting: Mapped[str] = mapped_column(String(30), default="outpatient")


class TreatmentPlan(Record, Base):
    __tablename__ = "treatment_plans"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    title: Mapped[str] = mapped_column(String(200))
    options: Mapped[list] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(30), default="proposed")
    accepted_option: Mapped[int | None] = mapped_column(Integer, nullable=True)
    consent_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.consents.id"), nullable=True)


class RecordAddendum(Record, Base):
    """Append-only correction linked to a finalized clinical/report record."""

    __tablename__ = "record_addenda"
    __table_args__ = {"schema": "tenant"}
    record_type: Mapped[str] = mapped_column(String(80))
    record_id: Mapped[str] = mapped_column(String(36), index=True)
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"), index=True)
    parent_id: Mapped[str | None] = mapped_column(
        ForeignKey("tenant.record_addenda.id"), nullable=True
    )
    reason: Mapped[str] = mapped_column(String(1000))
    content: Mapped[dict] = mapped_column(JSON)
    source_snapshot: Mapped[dict] = mapped_column(JSON)
    source_hash: Mapped[str] = mapped_column(String(64))
    finalized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finalized_by: Mapped[str] = mapped_column(String(100))
