from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


# Defines the organization model, contract, or value object.
class Organization(Record, Base):
    __tablename__ = "organizations"
    __table_args__ = {"schema": "dhmis_control"}
    name: Mapped[str] = mapped_column(String(160))
    schema_name: Mapped[str] = mapped_column(String(64), unique=True)
    region: Mapped[str] = mapped_column(String(2), default="CA")
    status: Mapped[str] = mapped_column(String(30), default="pending")
    visibility: Mapped[str] = mapped_column(String(20), default="organization")
    branding: Mapped[dict] = mapped_column(JSON, default=dict)
    policy: Mapped[dict] = mapped_column(
        JSON,
        default=lambda: {
            "cancellation_notice_hours": 24,
            "cancellation_fee_cents": 0,
            "buffer_minutes": 0,
            "reminder_hours": 24,
        },
    )
    jurisdiction_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    plan: Mapped[str] = mapped_column(String(30), default="sandbox")
    last_error: Mapped[str] = mapped_column(String(120), default="")
    adapters: Mapped[dict] = mapped_column(JSON, default=dict)
    public_content: Mapped[dict] = mapped_column(JSON, default=dict)
    database_alias: Mapped[str] = mapped_column(String(80), default="primary")
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    domains: Mapped[list] = mapped_column(JSON, default=list)
    front_office_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    booking_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    patient_portal_enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class PlatformCommercialAccount(Record, Base):
    """Extensible DHMIS-to-tenant commercial ownership seam."""

    __tablename__ = "platform_commercial_accounts"
    __table_args__ = {"schema": "dhmis_control"}
    organization_id: Mapped[str] = mapped_column(String(36), unique=True)
    account_status: Mapped[str] = mapped_column(String(30), default="active")
    plan_code: Mapped[str] = mapped_column(String(80), default="sandbox")
    subscription_status: Mapped[str] = mapped_column(String(30), default="not_configured")
    external_reference: Mapped[str] = mapped_column(String(180), default="")
    commercial_metadata: Mapped[dict] = mapped_column(JSON, default=dict)


class PlatformPlan(Record, Base):
    """Platform-owned plan catalogue used for tenant subscriptions."""

    __tablename__ = "platform_plans"
    __table_args__ = {"schema": "dhmis_control"}
    code: Mapped[str] = mapped_column(String(80), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(String(500), default="")
    price_cents: Mapped[int] = mapped_column(Integer, default=0)
    currency: Mapped[str] = mapped_column(String(3), default="CAD")
    interval: Mapped[str] = mapped_column(String(20), default="month")
    trial_days: Mapped[int] = mapped_column(Integer, default=14)
    max_locations: Mapped[int | None] = mapped_column(Integer, nullable=True)
    features: Mapped[list] = mapped_column(JSON, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class PlatformFeature(Record, Base):
    """Stable, server-enforced entitlement in the platform feature catalogue."""

    __tablename__ = "platform_features"
    __table_args__ = {"schema": "dhmis_control"}
    key: Mapped[str] = mapped_column(String(120), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(String(500), default="")
    category: Mapped[str] = mapped_column(String(80), default="core")
    feature_type: Mapped[str] = mapped_column(String(20), default="boolean")
    unit: Mapped[str] = mapped_column(String(40), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class PlatformPlanFeature(Record, Base):
    """A plan's typed value for one catalogue feature."""

    __tablename__ = "platform_plan_features"
    __table_args__ = {"schema": "dhmis_control"}
    plan_id: Mapped[str] = mapped_column(ForeignKey("dhmis_control.platform_plans.id"))
    feature_id: Mapped[str] = mapped_column(ForeignKey("dhmis_control.platform_features.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    value: Mapped[int | None] = mapped_column(Integer, nullable=True)
    unlimited: Mapped[bool] = mapped_column(Boolean, default=False)
    included_quantity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    public_label: Mapped[str] = mapped_column(String(180), default="")


class PlatformSubscription(Record, Base):
    """Current platform subscription for one tenant organization."""

    __tablename__ = "platform_subscriptions"
    __table_args__ = {"schema": "dhmis_control"}
    organization_id: Mapped[str] = mapped_column(String(36), unique=True)
    plan_id: Mapped[str] = mapped_column(ForeignKey("dhmis_control.platform_plans.id"))
    status: Mapped[str] = mapped_column(String(30), default="trialing")
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False)
    external_reference: Mapped[str] = mapped_column(String(180), default="")
    subscription_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class PlatformConfiguration(Record, Base):
    """Defaults copied into new tenants plus platform-owned message templates."""

    __tablename__ = "platform_configuration"
    __table_args__ = {"schema": "dhmis_control"}
    default_visibility: Mapped[str] = mapped_column(String(20), default="organization")
    default_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    communication_templates: Mapped[dict] = mapped_column(JSON, default=dict)


class TenantSettings(Record, Base):
    """Tenant-owned runtime configuration stored inside each tenant schema."""

    __tablename__ = "tenant_settings"
    __table_args__ = {"schema": "tenant"}
    visibility: Mapped[str] = mapped_column(String(20), default="organization")
    branding: Mapped[dict] = mapped_column(JSON, default=dict)
    logo_url: Mapped[str] = mapped_column(
        String(1000), default="/assets/dhmis-logo-v2/svg/dhmis-lockup-website.svg", nullable=False
    )
    policy: Mapped[dict] = mapped_column(
        JSON,
        default=lambda: {
            "cancellation_notice_hours": 24,
            "cancellation_fee_cents": 0,
            "buffer_minutes": 0,
            "reminder_hours": 24,
        },
    )
    jurisdiction_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    public_content: Mapped[dict] = mapped_column(JSON, default=dict)
    communication_templates: Mapped[dict] = mapped_column(JSON, default=dict)
    operational_thresholds: Mapped[dict] = mapped_column(JSON, default=dict)
    booking_widget: Mapped[dict] = mapped_column(JSON, default=dict)
    migration_state: Mapped[dict] = mapped_column(JSON, default=dict)


# Defines the location model, contract, or value object.
class Location(Record, Base):
    __tablename__ = "locations"
    __table_args__ = {"schema": "tenant"}
    name: Mapped[str] = mapped_column(String(160))
    address: Mapped[str] = mapped_column(String(500), default="")
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    osm_place_id: Mapped[str] = mapped_column(String(120), default="")
    timezone: Mapped[str] = mapped_column(String(60), default="America/Vancouver")
    chairs: Mapped[list] = mapped_column(JSON, default=lambda: ["Op 1", "Op 2", "Op 3"])

    opening_hour: Mapped[int] = mapped_column(Integer, default=8)
    closing_hour: Mapped[int] = mapped_column(Integer, default=18)
    branding: Mapped[dict] = mapped_column(JSON, default=dict)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
