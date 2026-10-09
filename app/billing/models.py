from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class Service(Record, Base):
    __tablename__ = "services"
    __table_args__ = (CheckConstraint("fee_cents >= 0"), {"schema": "tenant"})
    code: Mapped[str] = mapped_column(String(30), unique=True)
    name: Mapped[str] = mapped_column(String(180))
    fee_cents: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(String(1000), default="")


class Invoice(Record, Base):
    __tablename__ = "invoices"
    __table_args__ = (
        CheckConstraint("total_cents >= 0 AND paid_cents >= 0 AND paid_cents <= total_cents"),
        {"schema": "tenant"},
    )
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    provider_id: Mapped[str | None] = mapped_column(
        ForeignKey("tenant.staff_users.id"), nullable=True
    )
    lines: Mapped[list] = mapped_column(JSON)
    total_cents: Mapped[int] = mapped_column(Integer)
    paid_cents: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="open")
    adjustment_cents: Mapped[int] = mapped_column(Integer, default=0)


class LedgerEntry(Record, Base):
    __tablename__ = "ledger_entries"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    invoice_id: Mapped[str] = mapped_column(ForeignKey("tenant.invoices.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    kind: Mapped[str] = mapped_column(String(30))
    amount_cents: Mapped[int] = mapped_column(Integer)
    idempotency_key: Mapped[str] = mapped_column(String(100), unique=True)
    reference: Mapped[str] = mapped_column(String(120), default="")


class FeeVersion(Record, Base):
    __tablename__ = "fee_versions"
    __table_args__ = (CheckConstraint("fee_cents >= 0"), {"schema": "tenant"})
    service_id: Mapped[str] = mapped_column(ForeignKey("tenant.services.id"))
    location_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.locations.id"), nullable=True)
    provider_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.staff_users.id"), nullable=True)
    fee_cents: Mapped[int] = mapped_column(Integer)
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PaymentPlan(Record, Base):
    __tablename__ = "payment_plans"
    __table_args__ = {"schema": "tenant"}
    invoice_id: Mapped[str] = mapped_column(ForeignKey("tenant.invoices.id"), unique=True)
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    installments: Mapped[list] = mapped_column(JSON)


class JournalLine(Record, Base):
    __tablename__ = "journal_lines"
    __table_args__ = {"schema": "tenant"}
    posting_id: Mapped[str] = mapped_column(ForeignKey("tenant.ledger_entries.id"))
    account: Mapped[str] = mapped_column(String(40))
    amount_cents: Mapped[int] = mapped_column(Integer)
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
