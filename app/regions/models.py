from datetime import datetime

from sqlalchemy import Boolean, DateTime, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class PlatformRegion(Record, Base):
    """Platform-owned source of truth for supported onboarding regions."""

    __tablename__ = "platform_regions"
    __table_args__ = {"schema": "dhmis_control"}
    code: Mapped[str] = mapped_column(String(2), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    jurisdiction_provider: Mapped[str] = mapped_column(String(80))
    claims_route: Mapped[str] = mapped_column(String(120))
    locale: Mapped[str] = mapped_column(String(30))
    currency: Mapped[str] = mapped_column(String(3))
    tax_defaults: Mapped[dict] = mapped_column(JSON, default=dict)
    residency_defaults: Mapped[dict] = mapped_column(JSON, default=dict)
    code_set_type: Mapped[str] = mapped_column(String(20), default="")


class TenantCodeSetActivation(Record, Base):
    """Control-plane summary of tenant activation state, never code content."""

    __tablename__ = "tenant_code_set_activation"
    __table_args__ = {"schema": "dhmis_control"}
    organization_id: Mapped[str] = mapped_column(String(36), unique=True)
    code_set_type: Mapped[str] = mapped_column(String(20))
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    last_status_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
