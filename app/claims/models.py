from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class Claim(Record, Base):
    __tablename__ = "claims"
    __table_args__ = {"schema": "tenant"}
    invoice_id: Mapped[str] = mapped_column(ForeignKey("tenant.invoices.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    network: Mapped[str] = mapped_column(String(30), default="Sandbox1_CDAnet")
    status: Mapped[str] = mapped_column(String(30), default="submitted")
    reference: Mapped[str] = mapped_column(String(120))
    covered_cents: Mapped[int] = mapped_column(Integer, default=0)

    plan_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.insurance_plans.id"), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(100), unique=True, nullable=True)
    submitted_cents: Mapped[int] = mapped_column(Integer, default=0)
    payer_order: Mapped[int] = mapped_column(Integer, default=1)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    remittance: Mapped[dict] = mapped_column(JSON, default=dict)
    discrepancy: Mapped[str] = mapped_column(String(500), default="")


class InsurancePlan(Record, Base):
    __tablename__ = "insurance_plans"
    __table_args__ = (CheckConstraint("coverage_pct >= 0 AND coverage_pct <= 100"), {"schema": "tenant"})
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    payer_name: Mapped[str] = mapped_column(String(160))
    member_id: Mapped[str] = mapped_column(String(100))
    priority: Mapped[int] = mapped_column(Integer)
    coverage_pct: Mapped[int] = mapped_column(Integer, default=80)
    maximum_cents: Mapped[int] = mapped_column(Integer, default=200000)
    used_cents: Mapped[int] = mapped_column(Integer, default=0)
    waiting_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
