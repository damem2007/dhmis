from sqlalchemy import JSON, Boolean, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class PlatformAdapterDefault(Record, Base):
    __tablename__ = "platform_adapter_defaults"
    __table_args__ = (
        UniqueConstraint("region", "capability"),
        {"schema": "dhmis_control"},
    )
    region: Mapped[str] = mapped_column(String(10), default="*")
    capability: Mapped[str] = mapped_column(String(80))
    provider_name: Mapped[str] = mapped_column(String(120))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class TenantAdapterOverride(Record, Base):
    __tablename__ = "tenant_adapter_overrides"
    __table_args__ = (
        UniqueConstraint("organization_id", "capability"),
        {"schema": "dhmis_control"},
    )
    organization_id: Mapped[str] = mapped_column(String(36))
    capability: Mapped[str] = mapped_column(String(80))
    provider_name: Mapped[str] = mapped_column(String(120))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    approved_by: Mapped[str] = mapped_column(String(100))
    approval_reason: Mapped[str] = mapped_column(String(1000), default="")


class AdapterCustomizationRequest(Record, Base):
    __tablename__ = "adapter_customization_requests"
    __table_args__ = {"schema": "dhmis_control"}
    organization_id: Mapped[str] = mapped_column(String(36))
    capability: Mapped[str] = mapped_column(String(80))
    provider_name: Mapped[str] = mapped_column(String(120))
    reason: Mapped[str] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(30), default="pending")
    requested_by: Mapped[str] = mapped_column(String(100))
    decided_by: Mapped[str] = mapped_column(String(100), default="")
    decision_reason: Mapped[str] = mapped_column(String(1000), default="")
    decision_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
