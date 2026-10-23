from datetime import date, datetime

from sqlalchemy import DateTime, ForeignKey, String, event
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record
from app.core.secure_fields import EncryptedDate, EncryptedJSON, EncryptedText, email_lookup


# Defines the patient model, contract, or value object.
class Patient(Record, Base):
    __tablename__ = "patients"
    __table_args__ = {"schema": "tenant"}
    first_name: Mapped[str] = mapped_column(EncryptedText())
    last_name: Mapped[str] = mapped_column(EncryptedText())
    birth_date: Mapped[date] = mapped_column(EncryptedDate())
    email: Mapped[str] = mapped_column(EncryptedText(), default="")
    email_lookup: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    phone: Mapped[str] = mapped_column(EncryptedText(), default="")
    allergies: Mapped[list] = mapped_column(EncryptedJSON(), default=list)
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))

    medical_history: Mapped[str] = mapped_column(EncryptedText(), default="")
    dental_history: Mapped[str] = mapped_column(EncryptedText(), default="")
    alerts: Mapped[list] = mapped_column(EncryptedJSON(), default=list)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    archive_reason: Mapped[str] = mapped_column(EncryptedText(), default="")


# Defines the guardian link model, contract, or value object.
class GuardianLink(Record, Base):
    __tablename__ = "guardian_links"
    __table_args__ = {"schema": "tenant"}
    guardian_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    dependent_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    relationship: Mapped[str] = mapped_column(EncryptedText())
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))


# Keep the exact-match token synchronized for every ORM write path, including
# development scripts and integrations that create patients directly.
@event.listens_for(Patient, "before_insert")
@event.listens_for(Patient, "before_update")
def _sync_patient_email_lookup(mapper, connection, target):
    """Derive the keyed email lookup whenever a patient row is persisted."""

    target.email_lookup = email_lookup(target.email)
