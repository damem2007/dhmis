from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


# Defines the chart entry model, contract, or value object.
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
    # Chart entries are append-only clinical history. A missing-tooth return
    # changes the entry's status; it never deletes the original declaration.
    status: Mapped[str] = mapped_column(String(20), default="active", server_default="active")
    status_reason: Mapped[str] = mapped_column(String(1000), default="", server_default="")
    status_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status_changed_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rendering_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)


# Defines the perio exam model, contract, or value object.
class PerioExam(Record, Base):
    __tablename__ = "perio_exams"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    measurements: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="draft")
    dentition: Mapped[list] = mapped_column(JSON, default=list)
    encounter_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.encounters.id"), nullable=True)


# Defines the encounter model, contract, or value object.
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


# Defines the treatment plan model, contract, or value object.
class TreatmentPlan(Record, Base):
    __tablename__ = "treatment_plans"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    provider_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.staff_users.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(200))
    options: Mapped[list] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(30), default="proposed")
    accepted_option: Mapped[int | None] = mapped_column(Integer, nullable=True)
    consent_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.consents.id"), nullable=True)


class TreatmentCatalogueItem(Record, Base):
    """Tenant-owned clinical catalogue entry linked to existing billing services."""

    __tablename__ = "treatment_catalogue_items"
    __table_args__ = (
        UniqueConstraint("item_type", "code", name="uq_treatment_catalogue_item_code"),
        {"schema": "tenant"},
    )
    item_type: Mapped[str] = mapped_column(String(30))
    code: Mapped[str] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(String(1000), default="")
    category: Mapped[str] = mapped_column(String(80), default="")
    service_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.services.id"), nullable=True)
    # Procedure surcharge in cents. Conditions and tooth statuses keep this
    # field at zero; procedures may be billed without a Services & fees link.
    fee_cents: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    procedure_code_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    fee_source: Mapped[str] = mapped_column(String(40), default="services")
    quick_chart: Mapped[bool] = mapped_column(Boolean, default=False)
    appearance_key: Mapped[str] = mapped_column(String(60), default="healthy")
    draw_on: Mapped[str] = mapped_column(String(40), default="")
    # Legacy display value retained for migration/audit compatibility. New
    # resolution mappings are stored in ConditionTreatmentLink rows.
    resolved_by: Mapped[str] = mapped_column(String(40), default="")
    tooth_status_effect: Mapped[str] = mapped_column(String(40), default="")
    applies_to: Mapped[str] = mapped_column(String(30), default="whole_mouth")
    allowed_surfaces: Mapped[list] = mapped_column(JSON, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class ConditionTreatmentLink(Record, Base):
    """Tenant-owned potential resolution mapping configured from Condition setup."""

    __tablename__ = "condition_treatment_links"
    __table_args__ = (
        UniqueConstraint("condition_id", "treatment_id", "relationship_type", name="uq_condition_treatment_link"),
        {"schema": "tenant"},
    )
    condition_id: Mapped[str] = mapped_column(ForeignKey("tenant.treatment_catalogue_items.id"))
    treatment_id: Mapped[str] = mapped_column(ForeignKey("tenant.treatment_catalogue_items.id"))
    relationship_type: Mapped[str] = mapped_column(String(30), default="may_resolve", server_default="may_resolve")


class TreatmentCatalogueOption(Record, Base):
    """Tenant-owned type/category option used by catalogue setup dropdowns."""

    __tablename__ = "treatment_catalogue_options"
    __table_args__ = (
        UniqueConstraint("option_type", "item_type", "value", name="uq_treatment_catalogue_option_value"),
        {"schema": "tenant"},
    )
    option_type: Mapped[str] = mapped_column(String(20))
    item_type: Mapped[str] = mapped_column(String(30))
    value: Mapped[str] = mapped_column(String(80))
    label: Mapped[str] = mapped_column(String(120))
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class QuickChartSet(Record, Base):
    """Ordered, tenant-wide Quick chart shortcuts governed by feature permissions."""

    __tablename__ = "quick_chart_sets"
    __table_args__ = ({"schema": "tenant"},)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    description: Mapped[str] = mapped_column(String(1000), default="")
    items: Mapped[list] = mapped_column(JSON, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Quote(Record, Base):
    """Immutable fee snapshot for one treatment-plan option and revision."""

    __tablename__ = "quotes"
    __table_args__ = (
        UniqueConstraint("treatment_plan_id", "option_index", "version", name="uq_quote_revision"),
        {"schema": "tenant"},
    )
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    treatment_plan_id: Mapped[str] = mapped_column(ForeignKey("tenant.treatment_plans.id"))
    option_index: Mapped[int] = mapped_column(Integer)
    version: Mapped[int] = mapped_column(Integer)
    snapshot: Mapped[dict] = mapped_column(JSON)
    total_cents: Mapped[int] = mapped_column(Integer)
    estimated_insurance_cents: Mapped[int] = mapped_column(Integer)
    estimated_patient_cents: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default="draft")


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
