import ipaddress
import re
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import bleach
from pydantic import BaseModel, Field, model_validator

from app.identity.password_policy import PasswordPolicy
from app.integrations.registry import REGISTRY
from app.organizations.configuration import COMMUNICATION_TEMPLATE_VARIABLES
from app.organizations.tenant_resolution import (
    normalize_hostname,
    normalize_slug,
)


def normalize_widget_origin(value: str) -> str:
    """Normalize a verifiable website origin without changing its semantics."""

    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Widget origins must be HTTP(S) origins without paths or credentials")
    if parsed.scheme == "http":
        try:
            is_local_ip = ipaddress.ip_address(parsed.hostname).is_private or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            is_local_ip = parsed.hostname.lower() in {"localhost", "127.0.0.1"}
        if not is_local_ip:
            raise ValueError("HTTP widget origins are limited to local or private IP addresses")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Widget origins must not include a path, query, or fragment")
    port = parsed.port
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return urlunsplit((parsed.scheme, host + (f":{port}" if port else ""), "", "", ""))

# Defines the onboarding model, contract, or value object.
class Onboarding(BaseModel):
    organization_id: UUID | None = None
    name: str = Field(min_length=2, max_length=160)
    slug: str = Field(min_length=3, max_length=80)
    region: str = Field(default="CA", pattern="^[A-Z]{2}$")
    location_name: str = Field(min_length=2, max_length=160)
    location_address: str = Field(default="", max_length=500)
    location_phone: str = Field(default="", max_length=40)
    location_latitude: float | None = Field(default=None, ge=-90, le=90)
    location_longitude: float | None = Field(default=None, ge=-180, le=180)
    location_osm_place_id: str = Field(default="", max_length=120)
    location_timezone: str = Field(default="America/Vancouver", min_length=2, max_length=60)
    admin_name: str = Field(min_length=2, max_length=160)
    admin_email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    visibility: str = Field(pattern="^(organization|location)$", default="organization")
    branding: dict[str, str] = Field(default_factory=dict)
    domains: list[dict[str, str]] = Field(default_factory=list)
    front_office_enabled: bool = True
    booking_enabled: bool = True
    patient_portal_enabled: bool = True
    booking_widget_origin: str | None = Field(default=None, max_length=300)
    plan_code: str = Field(min_length=2, max_length=80)
    # A fixed plan has one server-reviewed experience bundle.  A private
    # curated plan may expose reviewed alternatives, selected by radio button
    # in onboarding; clients never assemble arbitrary feature checkboxes.
    selected_combination_code: str | None = Field(default=None, max_length=80)
    subscription_status: str = Field(default="trialing", pattern=r"^(trialing|active)$")
    trial_ends_at: datetime | None = None
    current_period_start: datetime | None = None
    current_period_end: datetime | None = None
    external_reference: str = Field(default="", max_length=180)
    custom_domain_hostname: str | None = Field(default=None, max_length=253)
    domain_mode: Literal["managed", "custom"] = "managed"
    custom_domain_surfaces: list[str] = Field(default_factory=lambda: ["public"], max_length=3)
    # Public self-onboarding is deliberately limited to an isolated trial.
    # Platform Admin provisioning leaves this disabled and can still configure
    # production domains, widgets, and other reviewed capabilities.
    trial_mode: bool = False
    trial_terms_accepted: bool = False
    data_processing_acknowledged: bool = False

    # Handle routing for this module.
    @model_validator(mode="after")
    def routing(self):
        self.slug = normalize_slug(self.slug)
        try:
            ZoneInfo(self.location_timezone)
        except ZoneInfoNotFoundError as error:
            raise ValueError("Unknown location timezone") from error
        for binding in self.domains:
            if set(binding) != {"hostname", "surface"} or binding["surface"] not in {
                "back-office", "public", "portal"
            }:
                raise ValueError("Each domain requires a hostname and application surface")
            binding["hostname"] = normalize_hostname(binding["hostname"])
        if self.custom_domain_hostname:
            self.custom_domain_hostname = normalize_hostname(self.custom_domain_hostname)
            if not self.custom_domain_surfaces or any(
                surface not in {"back-office", "public", "portal"} for surface in self.custom_domain_surfaces
            ):
                raise ValueError("Custom domain surfaces are invalid")
        if self.domain_mode == "custom" and not self.custom_domain_hostname:
            raise ValueError("A custom hostname is required when requesting a custom domain")
        if self.domain_mode == "managed" and self.custom_domain_hostname:
            raise ValueError("Custom hostname is only valid when requesting a custom domain")
        if self.trial_mode:
            if self.booking_widget_origin or self.custom_domain_hostname:
                raise ValueError("Secure trials cannot request custom domains or appointment widgets")
            if not self.trial_terms_accepted or not self.data_processing_acknowledged:
                raise ValueError("Secure trial terms and the no-PHI acknowledgement are required")
        return self


class PublicPlatformSignup(BaseModel):
    """Public self-onboarding payload submitted from Platform Home."""

    organization_id: UUID | None = None
    plan_code: str = Field(min_length=2, max_length=80)
    payment_method_token: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=2, max_length=160)
    slug: str = Field(min_length=3, max_length=80)
    region: str = Field(default="CA", pattern="^[A-Z]{2}$")
    location_name: str = Field(min_length=2, max_length=160)
    location_address: str = Field(default="", max_length=500)
    location_phone: str = Field(default="", max_length=40)
    location_timezone: str = Field(default="America/Vancouver", min_length=2, max_length=60)
    admin_name: str = Field(min_length=2, max_length=160)
    admin_email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    front_office_enabled: bool = True
    booking_enabled: bool = True
    patient_portal_enabled: bool = True
    # These fields remain accepted for backwards-compatible clients, but the
    # public flow rejects them. They require assisted production activation.
    booking_widget_origin: str | None = Field(default=None, max_length=300)
    custom_hostname: str | None = Field(default=None, max_length=253)
    custom_domain_surfaces: list[str] = Field(default_factory=lambda: ["public"], max_length=3)
    trial_terms_accepted: bool = False
    data_processing_acknowledged: bool = False

    @model_validator(mode="after")
    def normalize_request(self):
        self.slug = normalize_slug(self.slug)
        if self.custom_hostname:
            self.custom_hostname = normalize_hostname(self.custom_hostname)
            if not self.custom_domain_surfaces or any(
                surface not in {"back-office", "public", "portal"} for surface in self.custom_domain_surfaces
            ):
                raise ValueError("Custom domain surfaces are invalid")
        return self


class PublicPaymentMethodInput(BaseModel):
    """Minimal public request for exercising the sandbox payment gateway."""

    plan_code: str = Field(min_length=2, max_length=80)
    payment_method_token: str = Field(min_length=1, max_length=200)
    region: str = Field(default="CA", pattern="^[A-Z]{2}$")


# Defines the plan entitlement input model, contract, or value object.
class PlanEntitlementInput(BaseModel):
    key: str = Field(min_length=3, max_length=120)
    enabled: bool = True
    value: int | None = Field(default=None, ge=0)
    unlimited: bool = False
    included_quantity: int | None = Field(default=None, ge=0)
    public_label: str = Field(default="", max_length=180)


class PlanCombinationInput(BaseModel):
    """A reviewed selectable bundle for a private curated plan."""

    code: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    name: str = Field(min_length=2, max_length=160)
    feature_keys: list[str] = Field(default_factory=list, max_length=30)
    price_cents: int = Field(ge=0)
    currency: str = Field(default="CAD", min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    active: bool = True


# Defines the platform plan input model, contract, or value object.
class PlatformPlanInput(BaseModel):
    code: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=500)
    price_cents: int = Field(default=0, ge=0)
    currency: str = Field(default="CAD", min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    interval: str = Field(default="month", pattern=r"^(month|year|one_time)$")
    trial_days: int = Field(default=14, ge=0, le=365)
    max_locations: int | None = Field(default=None, ge=1, le=10000)
    features: list[str] = Field(default_factory=list, max_length=30)
    entitlements: list[PlanEntitlementInput] | None = None
    active: bool = True
    public_available: bool = False
    configuration_mode: Literal["fixed", "selectable"] = "fixed"
    combinations: list[PlanCombinationInput] = Field(default_factory=list, max_length=20)


class AppointmentWidgetAddonInput(BaseModel):
    """Purchase one configured Appointment Widget add-on product."""

    product_code: str = Field(min_length=2, max_length=80)
    discount_basis_points: int = Field(default=0, ge=0, le=10000)
    reason: str = Field(min_length=8, max_length=1000)


class PlatformAddonProductInput(BaseModel):
    """A named, priced commercial add-on product configured by Platform Admin."""

    feature_key: str = Field(default="module.appointment_widget", min_length=3, max_length=120)
    code: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=500)
    quantity: int = Field(default=1, ge=1, le=20)
    price_cents: int = Field(ge=0)
    currency: str = Field(default="CAD", min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    interval: Literal["month", "year", "one_time"] = "month"
    active: bool = True


class CommercialRefundInput(BaseModel):
    """Append-only reversal of one SaaS commercial ledger entry."""

    ledger_entry_id: str = Field(min_length=1, max_length=36)
    amount_cents: int = Field(gt=0)
    reason: str = Field(min_length=2, max_length=240)
    internal_note: str = Field(default="", max_length=2000)
    revoke_scope: Literal["tenant", "addon"] = "tenant"
    idempotency_key: str = Field(min_length=8, max_length=120)


class DomainVerificationInput(BaseModel):
    """A tenant administrator asks DHMIS to check its published proof."""

    method: Literal["dns", "http"] = "dns"


class DomainRequestDecisionInput(BaseModel):
    """Platform staff may cancel/suspend, but cannot attest ownership."""

    reason: str = Field(min_length=2, max_length=1000)


class PlatformSupportTicketInput(BaseModel):
    """Payload for creating a Support-owned ticket from platform modules."""

    tenant_id: UUID
    source: str = Field(default="billing", min_length=2, max_length=40)
    subscription_id: str | None = Field(default=None, max_length=36)
    category: str = Field(default="Billing", min_length=2, max_length=80)
    priority: str = Field(default="normal", pattern=r"^(low|normal|high|urgent)$")
    subject: str = Field(min_length=1, max_length=240)
    description: str = Field(min_length=1, max_length=4000)
    context: dict = Field(default_factory=dict)


class PlatformSupportTicketUpdate(BaseModel):
    """Support-owned lifecycle changes shared with the originating module."""

    action: str | None = Field(default=None, pattern=r"^(assign|unassign|status|note|resolve|close|reopen)$")
    status: str | None = Field(default=None, pattern=r"^(open|in_progress|pending|resolved|closed)$")
    priority: str | None = Field(default=None, pattern=r"^(low|normal|high|urgent)$")
    assignee_id: UUID | None = None
    resolution_code: str | None = Field(default=None, max_length=60)
    resolution_note: str | None = Field(default=None, max_length=2000)
    note: str | None = Field(default=None, max_length=2000)


# Defines the platform feature input model, contract, or value object.
class PlatformFeatureInput(BaseModel):
    key: str = Field(min_length=3, max_length=120, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=500)
    category: str = Field(default="core", min_length=2, max_length=80)
    feature_type: str = Field(default="boolean", pattern=r"^(boolean|limit|metered)$")
    unit: str = Field(default="", max_length=40)
    active: bool = True


# Defines the subscription input model, contract, or value object.
class SubscriptionInput(BaseModel):
    plan_code: str = Field(min_length=2, max_length=80)
    status: str = Field(default="trialing", pattern=r"^(trialing|active|paused|past_due|canceled)$")
    trial_ends_at: datetime | None = None
    current_period_start: datetime | None = None
    current_period_end: datetime | None = None
    cancel_at_period_end: bool = False
    external_reference: str = Field(default="", max_length=180)


# Defines the access assignment input model, contract, or value object.
class AccessAssignmentInput(BaseModel):
    role: str
    location_id: str | None = None
    scope: str = Field(default="location", pattern="^(location|organization)$")

    # Handle valid scope for this module.
    @model_validator(mode="after")
    def valid_scope(self):
        if (self.scope == "organization") != (self.location_id is None):
            raise ValueError("Organization scope has no location; location scope requires one")
        return self
    
# Defines the invite input model, contract, or value object.
class InviteInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    role: str | None = None
    is_provider: bool = False
    location_ids: list[str] = Field(default_factory=list)
    assignments: list[AccessAssignmentInput] = Field(default_factory=list)

# Defines the accept invite model, contract, or value object.
class AcceptInvite(BaseModel):
    organization_id: str | None = None
    tenant_slug: str | None = None
    token: str = Field(min_length=20, max_length=200)
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    password: str = Field(min_length=12, max_length=128)


# Defines the database cutover model, contract, or value object.
class DatabaseCutover(BaseModel):
    target_alias: str = Field(min_length=2, max_length=80)


# Defines the routing configuration model, contract, or value object.
class RoutingConfiguration(BaseModel):
    slug: str = Field(min_length=3, max_length=80)
    domains: list[dict[str, str]] = Field(default_factory=list)
    front_office_enabled: bool
    booking_enabled: bool
    patient_portal_enabled: bool

    # Validate or enforce validate routing before the operation continues.
    @model_validator(mode="after")
    def validate_routing(self):
        self.slug = normalize_slug(self.slug)
        for binding in self.domains:
            if set(binding) != {"hostname", "surface"} or binding["surface"] not in {
                "back-office", "public", "portal"
            }:
                raise ValueError("Each domain requires a hostname and application surface")
            binding["hostname"] = normalize_hostname(binding["hostname"])
        return self


# Defines the platform location input model, contract, or value object.
class PlatformLocationInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    address: str = Field(default="", max_length=500)
    phone: str = Field(default="", max_length=40)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    osm_place_id: str = Field(default="", max_length=120)
    timezone: str = Field(default="America/Vancouver", min_length=2, max_length=60)
    chairs: list[str] = Field(default_factory=lambda: ["Op 1", "Op 2", "Op 3"], min_length=1, max_length=100)
    opening_hour: int = Field(default=8, ge=0, le=23)
    closing_hour: int = Field(default=18, ge=1, le=24)

    # Validate or enforce validate location before the operation continues.
    @model_validator(mode="after")
    def validate_location(self):
        if self.closing_hour <= self.opening_hour:
            raise ValueError("Closing hour must follow opening hour")
        if len(set(self.chairs)) != len(self.chairs) or any(not chair.strip() for chair in self.chairs):
            raise ValueError("Operatories must have unique non-empty names")
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as error:
            raise ValueError("Unknown timezone") from error
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("Latitude and longitude must be supplied together")
        return self


# Defines the recovery action model, contract, or value object.
class RecoveryAction(BaseModel):
    staff_email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    action: str = Field(pattern="^(unlock|reset_mfa|password_reset)$")
    reason: str = Field(min_length=10, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)


class TenantInvitationResetAction(BaseModel):
    """Request a replacement for an expired, unused tenant administrator invitation."""

    staff_email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    reason: str = Field(min_length=10, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)


# Defines the policy model, contract, or value object.
class DiscountDefinition(BaseModel):
    """Reusable percentage/fixed discount stored in tenant practice policy."""
    id: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=160)
    percentage_bps: int = Field(default=0, ge=0, le=10000)
    fixed_cents: int = Field(default=0, ge=0, le=100000000)
    starts_on: str | None = Field(default=None, max_length=10)
    ends_on: str | None = Field(default=None, max_length=10)
    perpetual: bool = True
    active: bool = True

    # Validate or enforce validate discount before the operation continues.
    @model_validator(mode="after")
    def valid_discount(self):
        if self.percentage_bps == 0 and self.fixed_cents == 0:
            raise ValueError("A discount must include a percentage, fixed amount, or both")
        if not self.perpetual and not self.ends_on:
            raise ValueError("A non-perpetual discount must have an end date")
        if self.starts_on and self.ends_on and self.starts_on > self.ends_on:
            raise ValueError("Discount end date must be on or after its start date")
        return self


class Policy(BaseModel):
    """Tenant scheduling and billing policy exposed through organization settings."""
    cancellation_notice_hours: int = Field(ge=0, le=168, default=24)
    cancellation_fee_cents: int = Field(ge=0, le=100000, default=0)
    buffer_minutes: int = Field(ge=0, le=120, default=0)
    reminder_hours: int = Field(ge=1, le=168, default=24)
    invitation_expiry_hours: int = Field(ge=1, le=168, default=24)
    discount_application_mode: Literal[
        "invoice_before_insurance",
        "line_before_insurance",
        "invoice_after_insurance",
        "patient_after_insurance",
    ] = "invoice_before_insurance"
    discounts: list[DiscountDefinition] = Field(default_factory=list, max_length=100)
    password_policy: PasswordPolicy = Field(default_factory=PasswordPolicy)


# Defines the public content model, contract, or value object.
class PublicContent(BaseModel):
    contact_phone: str = Field(default="", max_length=40)
    contact_email: str = Field(default="", max_length=254)
    address: str = Field(default="", max_length=500)


# Defines the booking widget configuration model, contract, or value object.
class BookingWidgetConfiguration(BaseModel):
    mode: Literal["button", "div", "iframe"] = "button"
    accent_color: str = Field(default="#356b5d", pattern=r"^#[0-9a-fA-F]{6}$")
    text_color: str = Field(default="#14231c", pattern=r"^#[0-9a-fA-F]{6}$")
    background_color: str = Field(default="#f3f6f4", pattern=r"^#[0-9a-fA-F]{6}$")
    surface_color: str = Field(default="#ffffff", pattern=r"^#[0-9a-fA-F]{6}$")
    border_color: str = Field(default="#d8e3de", pattern=r"^#[0-9a-fA-F]{6}$")
    font_family: str = Field(default="inherit", max_length=160)
    font_url: str = Field(default="", max_length=1000)
    button_label: str = Field(default="Book an appointment", min_length=1, max_length=120)
    title: str = Field(default="Book an appointment", min_length=1, max_length=160)
    description: str = Field(default="Choose a time that works for you.", max_length=500)
    success_message: str = Field(default="Your appointment request has been received.", max_length=500)
    button_width: str = Field(default="auto", max_length=40, pattern=r"^(auto|[0-9]{1,4}px|[0-9]{1,3}%)$")
    button_height: int = Field(default=48, ge=32, le=96)
    button_radius: int = Field(default=8, ge=0, le=48)
    button_font_size: int = Field(default=16, ge=10, le=32)
    button_font_weight: Literal["400", "500", "600", "700", "800"] = "700"
    panel_width: int = Field(default=680, ge=280, le=1000)
    panel_radius: int = Field(default=14, ge=0, le=48)
    panel_padding: int = Field(default=20, ge=8, le=48)
    default_location_id: str = Field(default="", max_length=36)
    allowed_location_ids: list[str] = Field(default_factory=list)
    allowed_service_ids: list[str] = Field(default_factory=list)
    allowed_provider_ids: list[str] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list, max_length=20)
    origin_verifications: list[dict] = Field(default_factory=list, max_length=20)

    # Validate or enforce validate lists before the operation continues.
    @model_validator(mode="after")
    def validate_lists(self):
        for values in (
            self.allowed_location_ids,
            self.allowed_service_ids,
            self.allowed_provider_ids,
            self.allowed_origins,
        ):
            if len(values) != len(set(values)):
                raise ValueError("Booking widget lists cannot contain duplicate values")
        for origin in self.allowed_origins:
            try:
                normalize_widget_origin(origin)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
        for item in self.origin_verifications:
            if not isinstance(item, dict) or not item.get("origin") or not item.get("dns_name"):
                if not (isinstance(item, dict) and item.get("origin") and item.get("verification_method") in {"http", "admin"}) and not (isinstance(item, dict) and item.get("origin") and item.get("record_type") in {"HTTP", "ADMIN"}):
                    raise ValueError("Widget origin verifications must include origin and dns_name")
        if self.font_url and not self.font_url.startswith(("https://", "http://")):
            raise ValueError("Widget font URL must use HTTP(S)")
        if not re.fullmatch(r"[A-Za-z0-9 ,.'\"_-]+", self.font_family):
            raise ValueError("Widget font family contains unsupported characters")
        return self


# Defines the booking widget origin request contract.
class BookingWidgetOriginInput(BaseModel):
    origin: str = Field(min_length=4, max_length=300)


class BookingWidgetDecisionInput(BaseModel):
    status: Literal["approved", "rejected"]
    reason: str = Field(default="", max_length=1000)



# Defines the org settings model, contract, or value object.
class OrgSettings(BaseModel):
    visibility: str = Field(pattern="^(organization|location)$")
    branding: dict[str, str] = Field(default_factory=dict)
    logo_url: str | None = Field(default=None, max_length=1000)
    policy: Policy
    jurisdiction_policy: dict = Field(default_factory=dict)
    public_content: PublicContent | None = None
    booking_widget: BookingWidgetConfiguration | None = None

    # Handle safe config for this module.
    @model_validator(mode="after")
    def safe_config(self):
        allowed = {
            "--sage",
            "--sage-deep",
            "--sage-tint",
            "--amber",
            "--paper",
            "--surface",
            "--ink",
            "--font-ui",
            "--font-display",
        }
        import re

        for key, value in self.branding.items():
            if key not in allowed or not re.fullmatch(r"[a-zA-Z0-9#(), .%\-]+", value):
                raise ValueError("Unsupported theme token")
        if self.logo_url and not self.logo_url.startswith(("/", "http://", "https://")):
            raise ValueError("Logo must be a relative asset path or HTTP(S) URL")
        policy = self.jurisdiction_policy
        if set(policy) - {"consent_notice", "retention_days", "tax_rate_basis_points"}:
            raise ValueError("Unknown jurisdiction setting")
        if "tax_rate_basis_points" in policy and (
            not isinstance(policy["tax_rate_basis_points"], int)
            or not 0 <= policy["tax_rate_basis_points"] <= 2500
        ):
            raise ValueError("Invalid tax rate")
        if "retention_days" in policy and (
            not isinstance(policy["retention_days"], int) or policy["retention_days"] < 1
        ):
            raise ValueError("Invalid retention period")
        return self


# Defines the adapter request input model, contract, or value object.
class AdapterRequestInput(BaseModel):
    capability: str = Field(min_length=2, max_length=80)
    provider_name: str = Field(min_length=2, max_length=120)
    reason: str = Field(min_length=10, max_length=1000)

    # Handle known provider for this module.
    @model_validator(mode="after")
    def known_provider(self):
        if self.provider_name not in REGISTRY.get(self.capability, {}):
            raise ValueError("Unknown adapter provider")
        return self


# Defines the adapter decision model, contract, or value object.
class AdapterDecision(BaseModel):
    status: str = Field(pattern="^(approved|rejected)$")
    reason: str = Field(min_length=10, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)

# Defines the adapter default input model, contract, or value object.
class AdapterDefaultInput(BaseModel):
    region: str = Field(pattern=r"^(\*|[A-Z]{2})$")
    capability: str = Field(min_length=2, max_length=80)
    provider_name: str = Field(min_length=2, max_length=120)
    mode: Literal["auto", "sandbox", "live"] = "auto"
    active: bool = True
    reason: str = Field(min_length=8, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)

    @model_validator(mode="after")
    def valid_provider_mode(self):
        registration = REGISTRY.get(self.capability, {}).get(self.provider_name)
        if registration is None:
            raise ValueError("Unknown adapter provider")
        if self.mode == "live" and registration.sandbox:
            raise ValueError("Selected provider is sandbox-only")
        if self.mode == "sandbox" and not registration.sandbox:
            raise ValueError("Selected provider has no sandbox adapter")
        return self

# Defines the tenant activation input model, contract, or value object.
class TenantActivationInput(BaseModel):
    reason: str = Field(default="Activate tenant after onboarding", min_length=8, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)


# Defines the secure trial production activation input model, contract, or value object.
class ProductionActivationInput(BaseModel):
    reason: str = Field(min_length=8, max_length=1000)
    allow_phi_import: bool = True
    allow_custom_domains: bool = True
    allow_widgets: bool = True
    allow_sso_and_integrations: bool = True


# Defines one channel-specific communication body and optional email signature.
class CommunicationChannelTemplateInput(BaseModel):
    subject: str = Field(default="", max_length=240)
    body: str = Field(min_length=2, max_length=12_000)
    signature: str = Field(default="", max_length=4_000)


EMAIL_TEMPLATE_TAGS = [
    "a", "b", "blockquote", "br", "code", "div", "em", "h1", "h2", "h3",
    "hr", "i", "li", "ol", "p", "pre", "span", "strong", "table", "tbody",
    "td", "th", "thead", "tr", "u", "ul",
]
EMAIL_TEMPLATE_ATTRIBUTES = {
    "a": ["href", "title", "target", "rel"],
    "td": ["colspan", "rowspan"],
    "th": ["colspan", "rowspan"],
}


# Defines the communication template input model, contract, or value object.
class CommunicationTemplateInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    active: bool = True
    delivery_mode: Literal["selected", "all_available"] = "selected"
    selected_channels: list[str] = Field(default_factory=lambda: ["email"], min_length=1)
    channels: dict[str, CommunicationChannelTemplateInput] | None = None
    # These three fields accept the deployed flat representation and are
    # converted to a single channel entry by ``as_storage`` below.
    channel: str | None = Field(default=None, pattern="^(email|sms|whatsapp)$")
    subject: str = Field(default="", max_length=240)
    body: str | None = Field(default=None, max_length=12_000)

    @model_validator(mode="after")
    def supported_variables(self):
        channels = self.channels
        if channels is None:
            if not self.channel or self.body is None:
                raise ValueError("At least one channel template is required")
            channels = {
                self.channel: CommunicationChannelTemplateInput(
                    subject=self.subject if self.channel == "email" else "",
                    body=self.body,
                )
            }
            self.channels = channels
            self.selected_channels = [self.channel]
        if not channels:
            raise ValueError("At least one channel template is required")
        allowed_channels = {"email", "sms", "whatsapp"}
        if set(channels) - allowed_channels or set(self.selected_channels) - set(channels):
            raise ValueError("Selected channels must have a configured template")
        allowed_variables = set(COMMUNICATION_TEMPLATE_VARIABLES)
        for channel, content in channels.items():
            if channel == "sms" and len(content.body) > 480:
                raise ValueError("SMS templates cannot exceed 480 characters")
            if channel == "whatsapp" and len(content.body) > 4096:
                raise ValueError("WhatsApp templates cannot exceed 4096 characters")
            if channel != "email" and (content.subject or content.signature):
                raise ValueError("Only email templates support a subject and signature")
            variables = set(re.findall(r"\{\{([a-z_]+)\}\}", content.subject + content.body + content.signature))
            if variables - allowed_variables:
                raise ValueError("Template contains an unsupported variable")
        return self

    def as_storage(self) -> dict:
        """Persist the channel model and compatibility projection together."""

        from app.organizations.configuration import normalize_communication_template

        channels: dict[str, dict] = {}
        for channel, content in (self.channels or {}).items():
            if channel == "email":
                body = bleach.clean(
                    content.body,
                    tags=EMAIL_TEMPLATE_TAGS,
                    attributes=EMAIL_TEMPLATE_ATTRIBUTES,
                    protocols=["http", "https", "mailto"],
                    strip=True,
                )
                if content.signature:
                    signature = bleach.clean(
                        content.signature,
                        tags=EMAIL_TEMPLATE_TAGS,
                        attributes=EMAIL_TEMPLATE_ATTRIBUTES,
                        protocols=["http", "https", "mailto"],
                        strip=True,
                    )
                    body = f"{body.rstrip()}<br><br>{signature.strip()}"
                channels[channel] = {"subject": content.subject, "body": body, "signature": ""}
            else:
                channels[channel] = {
                    "subject": "",
                    "body": bleach.clean(content.body, tags=[], strip=True),
                    "signature": "",
                }
        return normalize_communication_template({
            "name": self.name,
            "active": self.active,
            "delivery_mode": self.delivery_mode,
            "selected_channels": self.selected_channels,
            "channels": channels,
        })


# Defines the platform defaults input model, contract, or value object.
class PlatformDefaultsInput(BaseModel):
    default_visibility: str = Field(pattern="^(organization|location)$")
    default_policy: Policy


# Defines the platform invite input model, contract, or value object.
class PlatformInviteInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    role: str = Field(default="platform-super-admin", min_length=1, max_length=160)


# Defines the platform user status input model, contract, or value object.
class PlatformUserStatusInput(BaseModel):
    active: bool


# Defines the platform password reset input model, contract, or value object.
class PlatformPasswordResetInput(BaseModel):
    reason: str = Field(min_length=10, max_length=1000)

# Defines the staff password reset model, contract, or value object.
class StaffPasswordReset(BaseModel):
    reason: str = Field(min_length=10, max_length=1000)


# Defines the staff suspension model, contract, or value object.
class StaffSuspension(BaseModel):
    hours: int = Field(ge=1, le=8760)

    # Defines the staff access model, contract, or value object.
class StaffAccess(BaseModel):
    role: str | None = None
    active: bool
    is_provider: bool | None = None
    location_ids: list[str] = Field(default_factory=list)
    assignments: list[AccessAssignmentInput] = Field(default_factory=list)
