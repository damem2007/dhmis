from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, Uuid
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
            "invitation_expiry_hours": 24,
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


class OrganizationKey(Record, Base):
    """Wrapped tenant data-encryption key held in the control plane.

    The plaintext DEK is never persisted.  ``wrapped_key`` is usable only by
    the configured key provider, and ``recovery_metadata`` contains operational
    state without key material.
    """

    __tablename__ = "organization_keys"
    __table_args__ = {"schema": "dhmis_control"}
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("dhmis_control.organizations.id"), index=True
    )
    provider: Mapped[str] = mapped_column(String(40), default="local")
    # ``key_version`` identifies the tenant DEK used by application ciphertext.
    key_version: Mapped[str] = mapped_column(String(80), default="v1")
    # Provider versions identify the wrapping-key/envelope version. Keeping it
    # separate lets us rotate a tenant DEK without changing a cloud KMS key.
    provider_version: Mapped[str] = mapped_column(String(80), default="v1")
    wrapped_key: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    recovery_metadata: Mapped[dict] = mapped_column(JSON, default=dict)


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
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
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
    public_available: Mapped[bool] = mapped_column(Boolean, default=False)
    # Fixed plans expose one reviewed bundle. Selectable plans are private
    # curated contracts whose reviewed combinations are stored separately.
    configuration_mode: Mapped[str] = mapped_column(String(20), default="fixed")
    configuration_status: Mapped[str] = mapped_column(String(30), default="draft")
    configuration_notes: Mapped[dict] = mapped_column(JSON, default=dict)


class PlatformFeature(Record, Base):
    """Stable, server-enforced entitlement in the platform feature catalogue."""

    __tablename__ = "platform_features"
    __table_args__ = {"schema": "dhmis_control"}
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
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
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    plan_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), ForeignKey("dhmis_control.platform_plans.id"))
    feature_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False), ForeignKey("dhmis_control.platform_features.id")
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    value: Mapped[int | None] = mapped_column(Integer, nullable=True)
    unlimited: Mapped[bool] = mapped_column(Boolean, default=False)
    included_quantity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    public_label: Mapped[str] = mapped_column(String(180), default="")


class PlatformPlanCombination(Record, Base):
    """Reviewed experience bundle selectable only on a private curated plan."""

    __tablename__ = "platform_plan_combinations"
    __table_args__ = {"schema": "dhmis_control"}
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    plan_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False), ForeignKey("dhmis_control.platform_plans.id"), index=True
    )
    code: Mapped[str] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(160))
    feature_keys: Mapped[list] = mapped_column(JSON, default=list)
    price_cents: Mapped[int] = mapped_column(Integer, default=0)
    currency: Mapped[str] = mapped_column(String(3), default="CAD")
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class PlatformAddonProduct(Record, Base):
    """A priced commercial product used for tenant-specific add-on purchase."""

    __tablename__ = "platform_addon_products"
    __table_args__ = {"schema": "dhmis_control"}
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    feature_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False), ForeignKey("dhmis_control.platform_features.id"), index=True
    )
    code: Mapped[str] = mapped_column(String(80), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(String(500), default="")
    quantity: Mapped[int] = mapped_column(Integer, default=1)
    price_cents: Mapped[int] = mapped_column(Integer, default=0)
    currency: Mapped[str] = mapped_column(String(3), default="CAD")
    interval: Mapped[str] = mapped_column(String(20), default="month")
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class PlatformSubscription(Record, Base):
    """Current platform subscription for one tenant organization."""

    __tablename__ = "platform_subscriptions"
    __table_args__ = {"schema": "dhmis_control"}
    organization_id: Mapped[str] = mapped_column(String(36), unique=True)
    plan_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), ForeignKey("dhmis_control.platform_plans.id"))
    status: Mapped[str] = mapped_column(String(30), default="trialing")
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False)
    external_reference: Mapped[str] = mapped_column(String(180), default="")
    subscription_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class PlatformTenantAddon(Record, Base):
    """Individually billed entitlement assigned outside a tenant's base plan."""

    __tablename__ = "platform_tenant_addons"
    __table_args__ = {"schema": "dhmis_control"}
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    feature_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False), ForeignKey("dhmis_control.platform_features.id")
    )
    product_id: Mapped[str | None] = mapped_column(
        Uuid(as_uuid=False), ForeignKey("dhmis_control.platform_addon_products.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(30), default="active")
    quantity: Mapped[int] = mapped_column(Integer, default=1)
    unit_price_cents: Mapped[int] = mapped_column(Integer, default=0)
    discount_basis_points: Mapped[int] = mapped_column(Integer, default=0)
    currency: Mapped[str] = mapped_column(String(3), default="CAD")
    addon_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class PlatformCommercialLedgerEntry(Record, Base):
    """Commercial charge raised for a plan or tenant-specific add-on."""

    __tablename__ = "platform_commercial_ledger_entries"
    __table_args__ = {"schema": "dhmis_control"}
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    description: Mapped[str] = mapped_column(String(240))
    # Amounts are signed. A refund/reversal is a new negative entry linked to
    # its original entry; no accounting history is edited or deleted.
    gross_amount_cents: Mapped[int] = mapped_column(Integer, default=0)
    discount_cents: Mapped[int] = mapped_column(Integer, default=0)
    net_amount_cents: Mapped[int] = mapped_column(Integer, default=0)
    currency: Mapped[str] = mapped_column(String(3), default="CAD")
    status: Mapped[str] = mapped_column(String(30), default="open")
    reference: Mapped[str] = mapped_column(String(120), unique=True)
    reversal_of_entry_id: Mapped[str | None] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("dhmis_control.platform_commercial_ledger_entries.id"),
        nullable=True,
        index=True,
    )
    entry_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class OrganizationDomainRequest(Record, Base):
    """A tenant's managed or customer-owned application-host lifecycle."""

    __tablename__ = "organization_domain_requests"
    __table_args__ = {"schema": "dhmis_control"}
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("dhmis_control.organizations.id"), index=True
    )
    mode: Mapped[str] = mapped_column(String(20))  # managed | custom
    status: Mapped[str] = mapped_column(String(40), default="pending")
    public_hostname: Mapped[str | None] = mapped_column(String(253), nullable=True)
    backoffice_hostname: Mapped[str] = mapped_column(String(253))
    canonical: Mapped[bool] = mapped_column(Boolean, default=False)
    activation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suspension_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    request_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class OrganizationDomainHost(Record, Base):
    """One resolvable hostname in a domain request's public/admin bundle."""

    __tablename__ = "organization_domain_hosts"
    __table_args__ = {"schema": "dhmis_control"}
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    request_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False), ForeignKey("dhmis_control.organization_domain_requests.id"), index=True
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("dhmis_control.organizations.id"), index=True
    )
    hostname: Mapped[str] = mapped_column(String(253), unique=True)
    # ``managed_back_office`` is the platform-owned administrative fallback
    # retained while a customer-owned public domain is pending. It becomes a
    # redirect alias when the custom bundle is active; it is never canonical.
    role: Mapped[str] = mapped_column(String(30))  # public | back_office | managed_back_office
    routing_status: Mapped[str] = mapped_column(String(40), default="pending")
    tls_status: Mapped[str] = mapped_column(String(40), default="pending")
    canonical: Mapped[bool] = mapped_column(Boolean, default=False)


class OrganizationDomainVerification(Record, Base):
    """Tenant-owned domain verification challenge and observable DNS/HTTP state."""

    __tablename__ = "organization_domain_verifications"
    __table_args__ = {"schema": "dhmis_control"}
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    request_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False), ForeignKey("dhmis_control.organization_domain_requests.id"), index=True
    )
    method: Mapped[str] = mapped_column(String(20), default="dns")
    token: Mapped[str] = mapped_column(String(160))
    dns_name: Mapped[str] = mapped_column(String(253), default="")
    http_path: Mapped[str] = mapped_column(String(300), default="")
    ownership_status: Mapped[str] = mapped_column(String(40), default="pending")
    dns_status: Mapped[str] = mapped_column(String(40), default="pending")
    tls_status: Mapped[str] = mapped_column(String(40), default="pending")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class OrganizationDomainEvent(Record, Base):
    """Append-only domain activation, failure, suspension and recovery history."""

    __tablename__ = "organization_domain_events"
    __table_args__ = {"schema": "dhmis_control"}
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    request_id: Mapped[str] = mapped_column(
        Uuid(as_uuid=False), ForeignKey("dhmis_control.organization_domain_requests.id"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(60))
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class PlatformConfiguration(Record, Base):
    """Defaults copied into new tenants plus platform-owned message templates."""

    __tablename__ = "platform_configuration"
    __table_args__ = {"schema": "dhmis_control"}
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    # Immutable, human-readable singleton identity. It is never a primary key.
    name: Mapped[str] = mapped_column(String(80), unique=True, default="platform-settings")
    default_visibility: Mapped[str] = mapped_column(String(20), default="organization")
    default_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    password_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    communication_templates: Mapped[dict] = mapped_column(JSON, default=dict)


class TenantSettings(Record, Base):
    """Tenant-owned runtime configuration stored inside each tenant schema."""

    __tablename__ = "tenant_settings"
    __table_args__ = {"schema": "tenant"}
    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    # Each tenant schema owns one runtime-settings record with this business name.
    name: Mapped[str] = mapped_column(String(80), unique=True, default="organization-settings")
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
            "invitation_expiry_hours": 24,
        },
    )
    jurisdiction_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    public_content: Mapped[dict] = mapped_column(JSON, default=dict)
    communication_templates: Mapped[dict] = mapped_column(JSON, default=dict)
    operational_thresholds: Mapped[dict] = mapped_column(JSON, default=dict)
    booking_widget: Mapped[dict] = mapped_column(JSON, default=dict)
    clinical_chart: Mapped[dict] = mapped_column(JSON, default=dict)
    migration_state: Mapped[dict] = mapped_column(JSON, default=dict)


# Defines the location model, contract, or value object.
class Location(Record, Base):
    __tablename__ = "locations"
    __table_args__ = {"schema": "tenant"}
    name: Mapped[str] = mapped_column(String(160))
    address: Mapped[str] = mapped_column(String(500), default="")
    phone: Mapped[str] = mapped_column(String(40), default="")
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
