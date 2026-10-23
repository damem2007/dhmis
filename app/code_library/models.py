"""Persistent models for tenant-owned licensed procedure-code libraries."""

from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Index, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class CodeLibraryActivation(Record, Base):
    """Record a tenant's licence attestation and current activation state."""

    __tablename__ = "code_library_activations"
    __table_args__ = (UniqueConstraint("code_set_type", name="uq_code_library_activation_type"), {"schema": "tenant"})
    code_set_type: Mapped[str] = mapped_column(String(20))
    licence_holder: Mapped[str] = mapped_column(String(180))
    licence_reference: Mapped[str] = mapped_column(String(180))
    valid_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    source_file_name: Mapped[str] = mapped_column(String(255), default="")
    source_file_size: Mapped[int] = mapped_column(default=0)
    source_mime_type: Mapped[str] = mapped_column(String(120), default="")
    source_content: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    attested: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="active")
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_by: Mapped[str] = mapped_column(String(100), default="")


class CodeLibraryVersion(Record, Base):
    """Immutable imported version metadata for a tenant code library."""

    __tablename__ = "code_library_versions"
    __table_args__ = (
        UniqueConstraint("activation_id", "version", name="uq_code_library_version"),
        Index("ix_code_library_versions_activation", "activation_id", "imported_at"),
        {"schema": "tenant"},
    )
    activation_id: Mapped[str] = mapped_column(ForeignKey("tenant.code_library_activations.id"))
    version: Mapped[str] = mapped_column(String(80))
    checksum: Mapped[str] = mapped_column(String(128))
    source_file_name: Mapped[str] = mapped_column(String(255), default="")
    source_file_size: Mapped[int] = mapped_column(default=0)
    source_mime_type: Mapped[str] = mapped_column(String(120), default="")
    source_content: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    imported_by: Mapped[str] = mapped_column(String(100))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class ProcedureCode(Record, Base):
    """A normalized code row owned by a tenant library version."""

    __tablename__ = "procedure_codes"
    __table_args__ = (
        UniqueConstraint("version_id", "code", name="uq_procedure_code_version_code"),
        Index("ix_procedure_codes_lookup", "code", "status"),
        {"schema": "tenant"},
    )
    version_id: Mapped[str] = mapped_column(ForeignKey("tenant.code_library_versions.id"))
    code: Mapped[str] = mapped_column(String(80))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(20), default="active")
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TreatmentCodeMapping(Record, Base):
    """Link a tenant service catalogue item to a tenant-owned procedure code."""

    __tablename__ = "treatment_code_mappings"
    __table_args__ = (UniqueConstraint("service_id", "procedure_code_id", name="uq_treatment_code_mapping"), {"schema": "tenant"})
    service_id: Mapped[str] = mapped_column(ForeignKey("tenant.services.id"))
    procedure_code_id: Mapped[str] = mapped_column(ForeignKey("tenant.procedure_codes.id"))
    status: Mapped[str] = mapped_column(String(20), default="active")
