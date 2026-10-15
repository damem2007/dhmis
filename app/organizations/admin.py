import json
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import quote
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import delete, func, or_, select, update

from app.billing.models import Invoice
from app.core.audit import audit
from app.core.database import control_session, organization_session
from app.core.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.core.repository import add, required, serialize
from app.core.timezones import annotate_geocode_results
from app.identity.access import invite_assignments, user_assignments
from app.identity.models import (
    StaffInvite,
    StaffInviteAssignment,
    StaffLocationAssignment,
    StaffUser,
)
from app.identity.passwords import hash_password
from app.identity.recovery import issue_password_reset, revoke_staff_sessions
from app.identity.router import throttle
from app.identity.security import digest
from app.identity.service import (
    Actor,
    db_session,
    default_role_name,
    organization_role_names,
    permit,
    user_has_module,
)
from app.integrations.configuration import attach_effective_adapters
from app.integrations.contracts import IntegrationFailure
from app.integrations.models import (
    AdapterCustomizationRequest,
    PlatformAdapterDefault,
    TenantAdapterOverride,
)
from app.integrations.registry import REGISTRY, provider_options, resolve_registered
from app.notifications.models import OutboxMessage
from app.notifications.service import deliver_message_now
from app.organizations.configuration import (
    COMMUNICATION_TEMPLATE_VARIABLES,
    DEFAULT_LOGO_URL,
    configure_tenant,
    platform_configuration,
    render_communication_template,
    tenant_settings,
)
from app.organizations.entitlements import require_location_capacity
from app.organizations.extraction import extraction_preflight
from app.organizations.jurisdiction import jurisdiction
from app.organizations.models import (
    Location,
    Organization,
    PlatformCommercialAccount,
    PlatformFeature,
    PlatformPlan,
    PlatformPlanFeature,
    PlatformSubscription,
)
from app.organizations.provisioning import activate, provision
from app.organizations.tenant_resolution import (
    normalize_hostname,
    normalize_slug,
    organization_from_login,
)
from app.platform_identity.delivery import enqueue_platform_email, enqueue_platform_notification
from app.platform_identity.models import (
    PlatformAuditEvent,
    PlatformInvite,
    PlatformOutboxMessage,
    PlatformPasswordResetChallenge,
    PlatformSession,
    PlatformSupportTicket,
    PlatformUser,
)
from app.platform_identity.service import PlatformActor, platform_audit, platform_or_bootstrap
from app.rbac.bootstrap import seed_tenant_super_admin
from app.rbac.default_roles import default_role_definitions
from app.rbac.dependencies import permit_platform_or_bootstrap
from app.rbac.models import (
    PlatformApprovalPolicy,
    PlatformChangeDecision,
    PlatformChangeRequest,
    PlatformRole,
    PlatformRoleAssignment,
    TenantRole,
    TenantRoleAssignment,
    TenantRoleGrant,
)
from app.rbac.policy import Decision
from app.rbac.runtime import decide_platform, platform_policy_context
from app.rbac.workflow import (
    authorize_runtime_action,
    complete_runtime_action,
    create_runtime_action_request,
    request_payload,
)

router = APIRouter(tags=["Organization administration"])
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
        return self


# Defines the plan entitlement input model, contract, or value object.
class PlanEntitlementInput(BaseModel):
    key: str = Field(min_length=3, max_length=120)
    enabled: bool = True
    value: int | None = Field(default=None, ge=0)
    unlimited: bool = False
    included_quantity: int | None = Field(default=None, ge=0)
    public_label: str = Field(default="", max_length=180)


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


async def assignment_role_scopes(db, role_name: str) -> set[str]:
    """Resolve assignment scopes from the published tenant role grants."""
    definition = next(
        (item for item in default_role_definitions() if item["name"] == role_name), None
    )
    if definition is not None:
        return {"organization" if definition["organization_scope"] else "location"}
    role = await db.scalar(
        select(TenantRole).where(TenantRole.name == role_name, TenantRole.status == "published")
    )
    if role is not None:
        grants = (
            await db.scalars(
                select(TenantRoleGrant).where(
                    TenantRoleGrant.role_id == role.id,
                    TenantRoleGrant.effect == "allow",
                )
            )
        ).all()
        return {grant.scope.lower() for grant in grants}
    return set()


# Validate or enforce validate assignment role before the operation continues.
async def validate_assignment_role(db, assignment: AccessAssignmentInput) -> None:
    scopes = await assignment_role_scopes(db, assignment.role)
    if not scopes:
        raise HTTPException(422, "Unknown role")
    if assignment.scope not in scopes:
        raise HTTPException(422, f"This role does not allow {assignment.scope} scope")


# Defines the invite input model, contract, or value object.
class InviteInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    role: str | None = None
    is_provider: bool = False
    location_ids: list[str] = Field(default_factory=list)
    assignments: list[AccessAssignmentInput] = Field(default_factory=list)


# Handle assignment inputs for this module.
def assignment_inputs(body) -> list[AccessAssignmentInput]:
    if body.assignments:
        return body.assignments
    if not body.role:
        raise HTTPException(422, "At least one role assignment is required")
    return [
        AccessAssignmentInput(role=body.role, location_id=identifier)
        for identifier in body.location_ids
    ] or [AccessAssignmentInput(role=body.role, scope="organization")]


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


# Handle platform recovery actor for this module.
async def platform_recovery_actor(
    request: Request,
    body: RecoveryAction,
    actor: PlatformActor = Depends(platform_or_bootstrap),
):
    permission = {
        "unlock": "support.locked_account_recovery.unlock_account",
        "reset_mfa": "support.mfa_recovery.reset_mfa",
        "password_reset": "support.password_recovery.initiate_password_reset",
    }[body.action]
    return await permit_platform_or_bootstrap(
        permission,
        workflow_handles_approval=True,
    )(request, actor)


# Defines the policy model, contract, or value object.
class Policy(BaseModel):
    cancellation_notice_hours: int = Field(ge=0, le=168, default=24)
    cancellation_fee_cents: int = Field(ge=0, le=100000, default=0)
    buffer_minutes: int = Field(ge=0, le=120, default=0)
    reminder_hours: int = Field(ge=1, le=168, default=24)


# Defines the public content model, contract, or value object.
class PublicContent(BaseModel):
    contact_phone: str = Field(default="", max_length=40)
    contact_email: str = Field(default="", max_length=254)
    address: str = Field(default="", max_length=500)


# Defines the booking widget configuration model, contract, or value object.
class BookingWidgetConfiguration(BaseModel):
    accent_color: str = Field(default="#356b5d", pattern=r"^#[0-9a-fA-F]{6}$")
    default_location_id: str = Field(default="", max_length=36)
    allowed_location_ids: list[str] = Field(default_factory=list)
    allowed_service_ids: list[str] = Field(default_factory=list)
    allowed_provider_ids: list[str] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list, max_length=20)

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
            if not re.fullmatch(r"https://[a-zA-Z0-9.-]+(?::\d{2,5})?", origin):
                raise ValueError("Widget origins must be exact HTTPS origins")
        return self


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


# Handle integration request actor for this module.
async def integration_request_actor(
    request: Request,
    body: AdapterDecision,
    actor: PlatformActor = Depends(platform_or_bootstrap),
):
    permission = (
        "integrations.tenant_adapter_override.activate_override"
        if body.status == "approved"
        else "integrations.tenant_adapter_override.reject"
    )
    return await permit_platform_or_bootstrap(
        permission,
        workflow_handles_approval=True,
    )(request, actor)


# Defines the adapter default input model, contract, or value object.
class AdapterDefaultInput(BaseModel):
    region: str = Field(pattern=r"^(\*|[A-Z]{2})$")
    capability: str = Field(min_length=2, max_length=80)
    provider_name: str = Field(min_length=2, max_length=120)
    active: bool = True
    reason: str = Field(min_length=8, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)

    # Handle known provider for this module.
    @model_validator(mode="after")
    def known_provider(self):
        if self.provider_name not in REGISTRY.get(self.capability, {}):
            raise ValueError("Unknown adapter provider")
        return self


# Defines the tenant activation input model, contract, or value object.
class TenantActivationInput(BaseModel):
    reason: str = Field(default="Activate tenant after onboarding", min_length=8, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)


# Defines the communication template input model, contract, or value object.
class CommunicationTemplateInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    channel: str = Field(pattern="^(email|sms)$")
    subject: str = Field(default="", max_length=240)
    body: str = Field(min_length=2, max_length=4000)
    active: bool = True

    # Handle supported variables for this module.
    @model_validator(mode="after")
    def supported_variables(self):
        allowed = set(COMMUNICATION_TEMPLATE_VARIABLES)
        variables = set(re.findall(r"\{\{([a-z_]+)\}\}", self.subject + self.body))
        if variables - allowed:
            raise ValueError("Template contains an unsupported variable")
        return self


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


# Handle staff invitation url for this module.
def staff_invitation_url(raw_token: str, tenant_slug: str) -> str:
    from app.core.config import settings
    base = settings().tenant_admin_public_url_template.format(tenant_slug=tenant_slug).rstrip("/")
    return f"{base}/?invite={quote(raw_token, safe='')}"


# Handle invite for this module.
async def invite(db, body, actor, clinic_name="your clinic", *, delivery_actor=None, tenant_slug=""):
    assignments = assignment_inputs(body)
    assignment_keys = [(item.scope, item.location_id) for item in assignments]
    if len(assignment_keys) != len(set(assignment_keys)):
        raise HTTPException(422, "A scope can only be assigned once per invitation")
    for item in assignments:
        await validate_assignment_role(db, item)
        if item.location_id:
            await required(db, Location, item.location_id)
    if await db.scalar(select(StaffUser).where(StaffUser.email == body.email.lower())):
        raise HTTPException(409, "Staff account already exists")
    invitations = (
        await db.scalars(
            select(StaffInvite).where(StaffInvite.email == body.email.lower(), StaffInvite.used.is_(False))
        )
    ).all()
    now = int(time.time())
    for existing in invitations:
        if existing.expires <= now and existing.status == "pending":
            existing.status = "expired"
        existing_assignments = await invite_assignments(db, existing)
        if existing.status == "pending" and assignment_keys and any(
            (item.scope, item.location_id) in assignment_keys for item in existing_assignments
        ):
            raise HTTPException(409, "An access assignment is already pending for this scope")
    compatibility_role = assignments[0].role
    compatibility_locations = [item.location_id for item in assignments if item.location_id]
    raw = secrets.token_urlsafe(32)
    record = await add(
        db,
        StaffInvite,
        {
            "name": body.name,
            "email": body.email.lower(),
            "role": compatibility_role,
            "is_provider": body.is_provider,
            "location_ids": compatibility_locations,
            "token_hash": digest(raw),
            "expires": now + 86400,
            "status": "pending",
        },
        actor,
    )
    db.add_all(
        [
            StaffInviteAssignment(
                invite_id=record.id,
                email=record.email,
                location_id=item.location_id,
                scope=item.scope,
                role=item.role,
                status="pending",
                created_by=actor,
                updated_by=actor,
            )
            for item in assignments
        ]
    )
    template = (await tenant_settings(db)).communication_templates["staff-invitation"]
    expires_at = datetime.fromtimestamp(record.expires, UTC).strftime("%B %-d, %Y at %-I:%M %p UTC")
    subject, message_body = render_communication_template(
        template,
        {
            "recipient_name": record.name,
            "clinic_name": clinic_name,
            "role": compatibility_role.replace("_", " "),
            "tenant_slug": tenant_slug,
            "platform_name": "DHMIS Platform",
            "invitation_expires_at": expires_at,
            "invitation_expires_in": "24 hours",
            "invitation_link": staff_invitation_url(raw, tenant_slug),
        },
    )
    await deliver_message_now(db, delivery_actor or actor, OutboxMessage(
            kind="staff.invitation",
            payload={
                "destination": record.email,
                "subject": subject,
                "body": message_body,
                "channel": template.get("channel", "email"),
                "user_id": record.id,
            },
            idempotency_key=f"staff-invitation:{record.id}",
            created_by=actor,
            updated_by=actor,
        ))
    audit(
        db,
        actor,
        "invite",
        "staff",
        record.id,
        assignments=[item.model_dump() for item in assignments],
    )
    return {"invite_id": record.id, "token": raw, "invitation_link": staff_invitation_url(raw, tenant_slug), "expires_in": 86400}


# Handle onboarding for this module.
@router.post("/platform/organizations", status_code=201)
async def onboarding(
    body: Onboarding,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("organizations.tenant_onboarding.provision")),
):
    # Validate branding through the same settings contract used after onboarding.
    OrgSettings(visibility=body.visibility, branding=body.branding, logo_url="", policy=Policy())
    async with control_session() as db:
        defaults = await platform_configuration(db)
        default_policy = Policy(**defaults.default_policy).model_dump()
        default_templates = dict(defaults.communication_templates)
        organizations = (await db.scalars(select(Organization))).all()
        assigned = {
            binding["hostname"]
            for organization in organizations
            for binding in organization.domains
        }
        if assigned.intersection(binding["hostname"] for binding in body.domains):
            raise HTTPException(409, "Custom domain is already assigned")
    org = await provision(
        body.name,
        str(body.organization_id) if body.organization_id else None,
        body.slug,
        body.region,
    )
    async with organization_session(org) as db:
        runtime = await configure_tenant(
            db,
            visibility=body.visibility,
            branding=body.branding,
            policy=default_policy,
            actor_id=actor.user_id,
        )
        runtime.communication_templates = default_templates
        # Platform provisioning uses a string audit identity for tenant writes,
        # while immediate delivery needs the tenant-scoped provider context.
        delivery_actor = Actor(
            actor.user_id,
            org,
            actor.name,
            "platform",
            settings=runtime,
            adapter_names=await attach_effective_adapters(org),
            assignment_scope="organization",
        )
        location = await db.scalar(select(Location).order_by(Location.created_at))
        if location is None:
            location = await add(
                db,
                Location,
                {
                    "name": body.location_name,
                    "address": body.location_address,
                    "phone": body.location_phone,
                    "latitude": body.location_latitude,
                    "longitude": body.location_longitude,
                    "osm_place_id": body.location_osm_place_id,
                    "timezone": body.location_timezone,
                },
                "platform",
            )
        elif body.location_phone:
            # Complete onboarding captures the phone for an existing first location too.
            location.phone = body.location_phone
            location.updated_by = actor.user_id
        existing = await db.scalar(select(StaffUser).where(StaffUser.email == body.admin_email.lower()))
        invitation = (
            None
            if existing
            else await invite(
                db,
                InviteInput(
                    name=body.admin_name,
                    email=body.admin_email,
                    assignments=[AccessAssignmentInput(role=default_role_name(), scope="organization")],
                ),
                "platform",
                org.name,
                delivery_actor=delivery_actor,
                tenant_slug=org.slug,
            )
        )
        audit(db, "platform", "onboard", "organization", org.id)
    async with control_session() as db:
        row = await db.get(Organization, org.id)
        row.domains = body.domains
        row.front_office_enabled = body.front_office_enabled
        row.booking_enabled = body.booking_enabled
        row.patient_portal_enabled = body.patient_portal_enabled
        row.updated_by = actor.user_id
        commercial = await db.scalar(
            select(PlatformCommercialAccount).where(
                PlatformCommercialAccount.organization_id == org.id
            )
        )
        if commercial is None:
            db.add(
                PlatformCommercialAccount(
                    organization_id=org.id,
                    account_status="active",
                    plan_code=row.plan,
                    created_by=actor.user_id,
                    updated_by=actor.user_id,
                )
            )
        platform_audit(db, actor.user_id, "organization.provision", organization_id=org.id)
    await activate(org.id)
    return {
        "organization_id": org.id,
        "slug": org.slug,
        "location_id": location.id,
        "invitation": invitation,
        "status": "active",
    }


@router.get("/platform/geocode/search")
async def search_location(
    q: str = Query(min_length=3, max_length=180),
    region: str = Query(default="CA", min_length=2, max_length=2, pattern="^[A-Za-z]{2}$"),
    detail: bool = Query(default=False),
    actor: PlatformActor = Depends(
        permit_platform_or_bootstrap("organizations.initial_location_bootstrap.update")
    ),
):
    """Search the configured geocoding provider for an onboarding address."""

    del actor  # dependency enforces authenticated platform access
    async with control_session() as db:
        defaults = (
            await db.scalars(
                select(PlatformAdapterDefault).where(
                    PlatformAdapterDefault.capability == "geocoding_provider",
                    PlatformAdapterDefault.active,
                    PlatformAdapterDefault.region.in_(["*", region.upper()]),
                )
            )
        ).all()
    selected = next((row for row in defaults if row.region == region.upper()), None) or next(
        (row for row in defaults if row.region == "*"), None
    )
    if selected is None:
        raise HTTPException(503, "No geocoding provider is configured")
    try:
        provider = resolve_registered(
            "geocoding_provider",
            selected.provider_name,
            region=region.upper(),
            enforce_live=False,
        )
        search = getattr(provider, "search_addresses", provider.search) if detail else provider.search
        return annotate_geocode_results(await search(q, region.upper(), limit=5), region)
    except IntegrationFailure as error:
        raise HTTPException(502, str(error)) from error


# Handle organization locations for this module.
@router.get("/platform/organizations/{identifier}/locations")
async def organization_locations(
    identifier: str,
    actor: PlatformActor = Depends(
        permit_platform_or_bootstrap("organizations.organization_tenant_record.read")
    ),
):
    del actor
    async with control_session() as db:
        organization = await db.get(Organization, identifier)
    if organization is None:
        raise HTTPException(404, "Organization not found")
    async with organization_session(organization) as db:
        rows = (await db.scalars(select(Location).order_by(Location.name, Location.id))).all()
        return [serialize(row) for row in rows]


# Update update organization location while preserving existing validation and audit behavior.
@router.put("/platform/organizations/{identifier}/locations/{location_id}")
async def update_organization_location(
    identifier: str,
    location_id: str,
    body: PlatformLocationInput,
    actor: PlatformActor = Depends(
        permit_platform_or_bootstrap("organizations.initial_location_bootstrap.update")
    ),
):
    async with control_session() as db:
        organization = await db.get(Organization, identifier)
    if organization is None:
        raise HTTPException(404, "Organization not found")
    async with organization_session(organization) as db:
        row = await db.get(Location, location_id, with_for_update=True)
        if row is None:
            raise HTTPException(404, "Location not found")
        for key, value in body.model_dump().items():
            setattr(row, key, value)
        row.updated_by = actor.user_id
        audit(db, actor.user_id, "configure", "locations", row.id)
        await db.flush()
        return serialize(row)


@router.post("/platform/organizations/{identifier}/locations", status_code=201)
async def create_organization_location(
    identifier: str,
    body: PlatformLocationInput,
    actor: PlatformActor = Depends(
        permit_platform_or_bootstrap("organizations.initial_location_bootstrap.create")
    ),
):
    """Complete or extend tenant onboarding with a platform-managed location."""

    async with control_session() as db:
        organization = await db.get(Organization, identifier)
    if organization is None:
        raise HTTPException(404, "Organization not found")
    async with organization_session(organization) as db:
        current_count = await db.scalar(
            select(func.count()).select_from(Location).where(Location.active.is_(True))
        ) or 0
        await require_location_capacity(identifier, current_count)
        row = await add(db, Location, body.model_dump(), actor.user_id)
        audit(db, actor.user_id, "create", "locations", row.id)
        await db.flush()
        return serialize(row)


# Handle platform organizations for this module.
@router.get("/platform/organizations")
async def platform_organizations(actor: PlatformActor = Depends(permit_platform_or_bootstrap("organizations.organization_tenant_record.read"))):
    async with control_session() as db:
        rows = (await db.scalars(select(Organization).order_by(Organization.name))).all()
        accounts = {
            row.organization_id: row
            for row in (await db.scalars(select(PlatformCommercialAccount))).all()
        }
        platform_audit(db, actor.user_id, "organization.list")
        return [
            {
                "id": row.id,
                "name": row.name,
                "slug": row.slug,
                "region": row.region,
                "status": row.status,
                "database_alias": row.database_alias,
                "domains": row.domains,
                "front_office_enabled": row.front_office_enabled,
                "booking_enabled": row.booking_enabled,
                "patient_portal_enabled": row.patient_portal_enabled,
                "last_error": row.last_error,
                "commercial": {
                    "account_status": accounts[row.id].account_status,
                    "plan_code": accounts[row.id].plan_code,
                    "subscription_status": accounts[row.id].subscription_status,
                }
                if row.id in accounts
                else None,
            }
            for row in rows
        ]


@router.post("/platform/organizations/{identifier}/activate")
async def activate_organization(
    identifier: str,
    body: TenantActivationInput = TenantActivationInput(),
    actor: PlatformActor = Depends(
        permit_platform_or_bootstrap(
            "organizations.tenant_onboarding.activate",
            workflow_handles_approval=True,
        )
    ),
):
    """Activate a migrated tenant after its first location and admin handoff exist."""

    async with control_session() as db:
        organization = await db.get(Organization, identifier)
    if organization is None:
        raise HTTPException(404, "Organization not found")
    if organization.status == "active":
        return {"organization_id": organization.id, "status": "active", "changed": False}
    if organization.status != "migrated":
        raise HTTPException(
            409,
            f"Organization must be migrated before activation (current status: {organization.status})",
        )

    async with organization_session(organization) as db:
        location = await db.scalar(select(Location).limit(1))
        administrator = await db.scalar(
            select(StaffUser)
            .where(StaffUser.active, StaffUser.role.in_(organization_role_names()))
            .limit(1)
        )
        invitation = await db.scalar(
            select(StaffInvite)
            .where(
                StaffInvite.status == "pending",
                StaffInvite.used.is_(False),
                StaffInvite.expires > int(time.time()),
            )
            .limit(1)
        )
    if location is None:
        return {
            "organization_id": organization.id,
            "status": "incomplete",
            "changed": False,
            "next_action": "complete_setup",
            "detail": "Complete the first location before activating this tenant",
        }
    if administrator is None and invitation is None:
        return {
            "organization_id": organization.id,
            "status": "incomplete",
            "changed": False,
            "next_action": "send_invitation",
            "detail": "Send or accept the administrator invitation before activating this tenant",
        }

    approval = None
    async with control_session() as db:
        assignment = await db.scalar(
            select(PlatformRoleAssignment)
            .where(PlatformRoleAssignment.user_id == actor.user_id)
            .order_by(PlatformRoleAssignment.created_at)
        )
        assigned_role = await db.get(PlatformRole, assignment.role_id) if assignment else None
        is_platform_super_admin = (
            actor.is_bootstrap_operator
            or actor.user_id == "bootstrap"
            or assigned_role is not None
            and assigned_role.id == "platform-super-admin"
            or actor.role.strip().lower().replace(" ", "-") == "platform-super-admin"
        )
        decision = Decision(allowed=True, trace=("bootstrap authority",)) if is_platform_super_admin else await decide_platform(
            db,
            actor.user_id,
            "organizations.tenant_onboarding.activate",
        )
        if not decision.allowed or decision.needs_step_up:
            raise HTTPException(403, "Permission denied")
        if decision.needs_approval and not is_platform_super_admin:
            runtime_payload = {"organization_id": identifier}
            if body.approval_request_id:
                approval = await authorize_runtime_action(
                    db,
                    request_id=body.approval_request_id,
                    permission_key="organizations.tenant_onboarding.activate",
                    payload=runtime_payload,
                    maker_id=actor.user_id,
                    request_model=PlatformChangeRequest,
                )
            else:
                approval, created = await create_runtime_action_request(
                    db,
                    permission_key="organizations.tenant_onboarding.activate",
                    payload=runtime_payload,
                    reason=body.reason,
                    maker_id=actor.user_id,
                    context=await platform_policy_context(db),
                    request_model=PlatformChangeRequest,
                    policy_model=PlatformApprovalPolicy,
                )
                platform_audit(
                    db,
                    actor.user_id,
                    "organization.activation.approval-requested",
                    organization_id=identifier,
                    reason=body.reason,
                    details={"request_id": approval.id, "created": created},
                )
                return JSONResponse(
                    status_code=202,
                    content=jsonable_encoder({
                        "status": "approval_required",
                        "request": await request_payload(db, approval, PlatformChangeDecision),
                    }),
                )

    await activate(organization.id)
    async with control_session() as db:
        platform_audit(
            db,
            actor.user_id,
            "organization.activate",
            organization_id=organization.id,
        )
    if approval:
        async with control_session() as db:
            applied_request = await db.get(
                PlatformChangeRequest,
                approval.id,
                with_for_update=True,
            )
            if applied_request is not None:
                await complete_runtime_action(
                    applied_request,
                    {"resource": "organization", "resource_id": organization.id},
                )
    return {"organization_id": organization.id, "status": "active", "changed": True}


# Handle platform organizations query for this module.
@router.get("/platform/organizations/query")
async def platform_organizations_query(
    search: str | None = Query(default=None, max_length=160),
    status: str | None = Query(default=None, max_length=30),
    plan: str | None = Query(default=None, max_length=80),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=10, le=MAX_PAGE_SIZE),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("organizations.organization_tenant_record.read")),
):
    async with control_session() as db:
        query = select(Organization)
        if search:
            term = f"%{search.strip()}%"
            query = query.where(
                or_(
                    Organization.name.ilike(term),
                    Organization.slug.ilike(term),
                    Organization.region.ilike(term),
                )
            )
        if status:
            query = query.where(Organization.status == status)
        if plan:
            query = query.join(
                PlatformCommercialAccount,
                PlatformCommercialAccount.organization_id == Organization.id,
            ).where(PlatformCommercialAccount.plan_code == plan)
        total = await db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
        rows = (
            await db.scalars(
                query.order_by(Organization.name, Organization.id)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
        accounts = {
            row.organization_id: row
            for row in (
                await db.scalars(
                    select(PlatformCommercialAccount).where(
                        PlatformCommercialAccount.organization_id.in_([item.id for item in rows])
                    )
                )
            ).all()
        } if rows else {}
        platform_audit(
            db,
            actor.user_id,
            "organization.query",
            details={"page": page, "page_size": page_size},
        )
        return {
            "page": page,
            "page_size": page_size,
            "total": total,
            "items": [
                {
                    "id": row.id,
                    "name": row.name,
                    "slug": row.slug,
                    "region": row.region,
                    "status": row.status,
                    "database_alias": row.database_alias,
                    "domains": row.domains,
                    "front_office_enabled": row.front_office_enabled,
                    "booking_enabled": row.booking_enabled,
                    "patient_portal_enabled": row.patient_portal_enabled,
                    "last_error": row.last_error,
                    "commercial": {
                        "account_status": accounts[row.id].account_status,
                        "plan_code": accounts[row.id].plan_code,
                        "subscription_status": accounts[row.id].subscription_status,
                    } if row.id in accounts else None,
                }
                for row in rows
            ],
        }


# Handle platform audit events for this module.
@router.get("/platform/audit")
async def platform_audit_events(actor: PlatformActor = Depends(permit_platform_or_bootstrap("audit.platform_audit_events.read"))):
    async with control_session() as db:
        rows = (
            await db.scalars(
                select(PlatformAuditEvent)
                .order_by(PlatformAuditEvent.created_at.desc())
                .limit(500)
            )
        ).all()
        platform_audit(db, actor.user_id, "platform.audit.read")
        return [
            {
                "id": row.id,
                "created_at": row.created_at,
                "actor_id": row.actor_id,
                "action": row.action,
                "organization_id": row.organization_id,
                "reason": row.reason,
                "details": row.details,
            }
            for row in rows
        ]


# Handle platform audit query for this module.
@router.get("/platform/audit/query")
async def platform_audit_query(
    search: str | None = Query(default=None, max_length=160),
    action: str | None = Query(default=None, max_length=100),
    organization_id: str | None = Query(default=None, max_length=36),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=10, le=MAX_PAGE_SIZE),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("audit.platform_audit_events.search")),
):
    async with control_session() as db:
        query = select(PlatformAuditEvent)
        if search:
            term = f"%{search.strip()}%"
            query = query.where(
                or_(
                    PlatformAuditEvent.actor_id.ilike(term),
                    PlatformAuditEvent.action.ilike(term),
                    PlatformAuditEvent.reason.ilike(term),
                )
            )
        if action:
            query = query.where(PlatformAuditEvent.action == action)
        if organization_id:
            query = query.where(PlatformAuditEvent.organization_id == organization_id)
        total = await db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
        rows = (
            await db.scalars(
                query.order_by(PlatformAuditEvent.created_at.desc(), PlatformAuditEvent.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
        platform_audit(
            db,
            actor.user_id,
            "platform.audit.query",
            details={"page": page, "page_size": page_size},
        )
        return {
            "page": page,
            "page_size": page_size,
            "total": total,
            "items": [serialize(row) for row in rows],
        }


# Handle platform integration status for this module.
@router.get("/platform/integrations/status")
async def platform_integration_status(actor: PlatformActor = Depends(permit_platform_or_bootstrap("platform_ops.integration_provider_health.read"))):
    async with control_session() as db:
        defaults = (
            await db.scalars(
                select(PlatformAdapterDefault).order_by(
                    PlatformAdapterDefault.capability, PlatformAdapterDefault.region
                )
            )
        ).all()
        result = []
        for capability, registrations in REGISTRY.items():
            applicable = [row for row in defaults if row.capability == capability and row.active]
            selected = next((row for row in applicable if row.region == "*"), None) or next(iter(applicable), None)
            registration = registrations.get(selected.provider_name) if selected else None
            result.append(
                {
                    "capability": capability,
                    "registered_providers": sorted(registrations),
                    "configured": bool(applicable),
                    "provider_name": selected.provider_name if selected else "",
                    "ready": bool(selected and registration),
                    "sandbox_only": bool(registration and registration.sandbox),
                    "state": (
                        "unavailable" if not registrations
                        else "registered" if not applicable
                        else "unavailable" if registration is None
                        else "sandbox-only" if registration.sandbox
                        else "ready"
                    ),
                    "regional_defaults": [
                        {
                            "region": row.region,
                            "provider_name": row.provider_name,
                            "active": row.active,
                            "installed": row.provider_name in registrations,
                        }
                        for row in applicable
                    ],
                }
            )
        platform_audit(db, actor.user_id, "integration.status.read")
        return result


# Handle platform jobs for this module.
@router.get("/platform/jobs")
async def platform_jobs(
    include_tenants: bool = Query(default=False),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("platform_ops.background_job_health.read")),
):
    async with control_session() as db:
        organizations = []
        if include_tenants:
            organizations = (
                await db.scalars(
                    select(Organization)
                    .where(Organization.status == "active")
                    .order_by(Organization.name)
                )
            ).all()
        platform_grouped = (
            await db.execute(
                select(PlatformOutboxMessage.status, func.count()).group_by(
                    PlatformOutboxMessage.status
                )
            )
        ).all()
        platform_counts = {status_name: int(count) for status_name, count in platform_grouped}
        platform_oldest_due = await db.scalar(
            select(func.min(PlatformOutboxMessage.due_at)).where(
                PlatformOutboxMessage.status.in_(["pending", "retry"])
            )
        )
        platform_rows = (
            await db.scalars(
                select(PlatformOutboxMessage)
                .order_by(PlatformOutboxMessage.updated_at.desc())
                .limit(20)
            )
        ).all()
    counts: dict[str, int] = dict(platform_counts)
    recent = []
    oldest_due = platform_oldest_due
    for row in platform_rows:
        recent.append(
            {
                "id": row.id,
                "organization_id": None,
                "organization_name": "DHMIS Platform",
                "kind": row.kind,
                "status": row.status,
                "attempts": row.attempts,
                "due_at": row.due_at,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
        )
    for organization in organizations:
        try:
            async with organization_session(organization) as tenant_db:
                grouped = (
                    await tenant_db.execute(
                        select(OutboxMessage.status, func.count())
                        .group_by(OutboxMessage.status)
                    )
                ).all()
                for status_name, count in grouped:
                    counts[status_name] = counts.get(status_name, 0) + int(count)
                due = await tenant_db.scalar(
                    select(func.min(OutboxMessage.due_at)).where(
                        OutboxMessage.status.in_(["pending", "retry"])
                    )
                )
                if due and (oldest_due is None or due < oldest_due):
                    oldest_due = due
                rows = (
                    await tenant_db.scalars(
                        select(OutboxMessage)
                        .order_by(OutboxMessage.updated_at.desc())
                        .limit(10)
                    )
                ).all()
                recent.extend(
                    {
                        "id": row.id,
                        "organization_id": organization.id,
                        "organization_name": organization.name,
                        "kind": row.kind,
                        "status": row.status,
                        "attempts": row.attempts,
                        "due_at": row.due_at,
                        "created_at": row.created_at,
                        "updated_at": row.updated_at,
                    }
                    for row in rows
                )
        except Exception:
            counts["unavailable"] = counts.get("unavailable", 0) + 1
    recent.sort(key=lambda item: item["updated_at"], reverse=True)
    now = datetime.now(UTC)
    second = 30 if now.second < 30 else 60
    next_run = now.replace(microsecond=0) + timedelta(seconds=second - now.second)
    async with control_session() as db:
        platform_audit(db, actor.user_id, "jobs.status.read")
    return {
        "worker": {
            "name": "notifications.tick + platform_identity.delivery.platform_tick",
            "type": "ARQ cron worker",
            "status": "configured",
            "schedule": "Every 30 seconds",
            "next_scheduled_execution": next_run,
            "max_concurrent_jobs": 2,
            "lifecycle_actions": [],
        },
        "queue": {
            "name": "tenant and control-plane notification outboxes" if include_tenants else "platform notification outbox",
            "counts": counts,
            "backlog": sum(counts.get(key, 0) for key in ("pending", "retry")),
            "oldest_due_at": oldest_due,
            "health": "degraded" if counts.get("failed", 0) or counts.get("unavailable", 0) else "healthy",
        },
        "control_plane_queue": {
            "name": "platform notification outbox",
            "counts": platform_counts,
            "backlog": sum(platform_counts.get(key, 0) for key in ("pending", "retry")),
            "oldest_due_at": platform_oldest_due,
            "health": "degraded" if platform_counts.get("failed", 0) else "healthy",
        },
        "recent": recent[:50],
    }


# Handle platform plan payload for this module.
def platform_plan_payload(plan: PlatformPlan) -> dict:
    features = plan.features or []
    if isinstance(features, str):
        try:
            features = json.loads(features)
        except json.JSONDecodeError:
            features = [features]
    return {
        "id": plan.id,
        "code": plan.code,
        "name": plan.name,
        "description": plan.description,
        "price_cents": plan.price_cents,
        "currency": plan.currency,
        "interval": plan.interval,
        "trial_days": plan.trial_days,
        "max_locations": plan.max_locations,
        "features": features,
        "active": plan.active,
    }


# Handle platform plan payload with entitlements for this module.
async def platform_plan_payload_with_entitlements(db, plan: PlatformPlan) -> dict:
    payload = platform_plan_payload(plan)
    rows = (
        await db.execute(
            select(PlatformPlanFeature, PlatformFeature)
            .join(PlatformFeature, PlatformFeature.id == PlatformPlanFeature.feature_id)
            .where(PlatformPlanFeature.plan_id == plan.id, PlatformFeature.active)
            .order_by(PlatformFeature.category, PlatformFeature.name)
        )
    ).all()
    payload["entitlements"] = [
        {
            "key": feature.key,
            "name": feature.name,
            "description": feature.description,
            "category": feature.category,
            "feature_type": feature.feature_type,
            "unit": feature.unit,
            "enabled": assignment.enabled,
            "value": assignment.value,
            "unlimited": assignment.unlimited,
            "included_quantity": assignment.included_quantity,
            "public_label": assignment.public_label,
        }
        for assignment, feature in rows
    ]
    location = next((item for item in payload["entitlements"] if item["key"] == "limit.locations"), None)
    if location:
        payload["max_locations"] = None if location["unlimited"] else location["value"]
    return payload


# Update sync plan entitlements while preserving existing validation and audit behavior.
async def sync_plan_entitlements(db, plan: PlatformPlan, entitlements: list[PlanEntitlementInput] | None, actor_id: str):
    if entitlements is None:
        return
    await db.execute(delete(PlatformPlanFeature).where(PlatformPlanFeature.plan_id == plan.id))
    location_limit: PlanEntitlementInput | None = next((item for item in entitlements if item.key == "limit.locations"), None)
    if location_limit is not None:
        plan.max_locations = None if location_limit.unlimited else location_limit.value
    for item in entitlements:
        feature = await db.scalar(select(PlatformFeature).where(PlatformFeature.key == item.key, PlatformFeature.active))
        if feature is None:
            raise HTTPException(422, f"Unknown or inactive plan feature: {item.key}")
        if feature.feature_type == "boolean" and (item.value is not None or item.unlimited or item.included_quantity is not None):
            raise HTTPException(422, f"Boolean feature {item.key} cannot have a numeric value")
        if feature.feature_type == "limit" and not item.unlimited and item.value is None:
            raise HTTPException(422, f"Limit feature {item.key} requires a value or unlimited")
        db.add(PlatformPlanFeature(
            plan_id=plan.id,
            feature_id=feature.id,
            enabled=item.enabled,
            value=item.value,
            unlimited=item.unlimited,
            included_quantity=item.included_quantity,
            public_label=item.public_label,
            created_by=actor_id,
            updated_by=actor_id,
        ))


SUPPORT_TICKET_TRANSITIONS = {
    "open": {"open", "in_progress", "pending", "resolved", "closed"},
    "in_progress": {"open", "in_progress", "pending", "resolved", "closed"},
    "pending": {"open", "in_progress", "pending", "resolved", "closed"},
    "resolved": {"open", "resolved", "closed"},
    "closed": {"open", "closed"},
}


# Internal helper for ticket event.
def _ticket_event(ticket: PlatformSupportTicket, actor_id: str, kind: str, **details):
    context = dict(ticket.context or {})
    events = list(context.get("events") or [])
    events.append({"kind": kind, "actor_id": actor_id, "at": datetime.now(UTC).isoformat(), **details})
    context["events"] = events[-100:]
    ticket.context = context


# Internal helper for ticket payload.
def _ticket_payload(ticket: PlatformSupportTicket, organizations: dict[str, Organization], users: dict[str, PlatformUser]):
    context = ticket.context or {}
    return {
        "id": ticket.id,
        "organization_id": ticket.organization_id,
        "organization_name": organizations.get(ticket.organization_id).name if ticket.organization_id in organizations else "Unknown tenant",
        "source": ticket.source,
        "subscription_id": ticket.subscription_id,
        "category": ticket.category,
        "priority": ticket.priority,
        "subject": ticket.subject,
        "description": ticket.description,
        "status": ticket.status,
        "assignee_id": ticket.assignee_id,
        "assignee_name": users.get(ticket.assignee_id).name if ticket.assignee_id and ticket.assignee_id in users else None,
        "resolution_code": ticket.resolution_code,
        "resolution_note": ticket.resolution_note,
        "resolved_at": ticket.resolved_at,
        "closed_at": ticket.closed_at,
        "events": context.get("events") or [],
        "created_at": ticket.created_at,
        "updated_at": ticket.updated_at,
    }


@router.get("/platform/support/tickets")
async def platform_support_tickets(
    tenant_id: UUID | None = Query(default=None),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("support.tenant_support_case.read")),
):
    """Read Support-owned tickets for a tenant; billing remains read-only."""

    async with control_session() as db:
        organization = await db.get(Organization, str(tenant_id)) if tenant_id else None
        if tenant_id and organization is None:
            raise HTTPException(404, "Organization not found")
        query = select(PlatformSupportTicket).order_by(PlatformSupportTicket.created_at.desc())
        if organization is not None:
            query = query.where(PlatformSupportTicket.organization_id == organization.id)
        rows = (await db.scalars(query)).all()
        organization_ids = {ticket.organization_id for ticket in rows}
        organizations = {
            row.id: row
            for row in (await db.scalars(select(Organization).where(Organization.id.in_(organization_ids)))).all()
        } if organization_ids else {}
        assignee_ids = {ticket.assignee_id for ticket in rows if ticket.assignee_id}
        users = {
            row.id: row
            for row in (await db.scalars(select(PlatformUser).where(PlatformUser.id.in_(assignee_ids)))).all()
        } if assignee_ids else {}
        platform_audit(
            db,
            actor.user_id,
            "support.tickets.read",
            organization_id=organization.id if organization else None,
            details={"count": len(rows), "source": "support" if tenant_id is None else "billing"},
        )
        return [_ticket_payload(row, organizations, users) for row in rows]


@router.post("/platform/support/tickets", status_code=201)
async def create_platform_support_ticket(
    body: PlatformSupportTicketInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("support.tenant_support_case.create")),
):
    """Create a Support-owned ticket initiated by Billing or another module."""

    async with control_session() as db:
        organization = await db.get(Organization, str(body.tenant_id))
        if organization is None:
            raise HTTPException(404, "Organization not found")
        ticket = PlatformSupportTicket(
            organization_id=organization.id,
            source=body.source,
            subscription_id=body.subscription_id,
            category=body.category,
            priority=body.priority,
            subject=body.subject,
            description=body.description,
            status="open",
            context={**body.context, "events": [{"kind": "created", "actor_id": actor.user_id, "at": datetime.now(UTC).isoformat()}]},
            created_by=actor.user_id,
            updated_by=actor.user_id,
        )
        db.add(ticket)
        await db.flush()
        platform_audit(
            db,
            actor.user_id,
            "support.ticket.create",
            organization_id=organization.id,
            reason=body.subject,
            details={
                "ticket_id": ticket.id,
                "source": body.source,
                "category": body.category,
                "priority": body.priority,
            },
        )
        enqueue_platform_notification(
            db,
            kind="support.ticket.created",
            reference_id=ticket.id,
            actor_id=actor.user_id,
            payload={
                "ticket_id": ticket.id,
                "organization_id": organization.id,
                "organization_name": organization.name,
                "source": body.source,
                "subject": ticket.subject,
                "status": ticket.status,
                "detail": f"{organization.name} · {ticket.subject}",
                "cta_label": "Open Support",
                "target_url": f"/admin/support/?tenant={organization.id}",
            },
        )
        return _ticket_payload(ticket, {organization.id: organization}, {})


@router.get("/platform/support/assignees")
async def platform_support_assignees(
    search: str = Query(default="", max_length=120),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("support.tenant_support_case.read")),
):
    """Return active platform users available to own Support tickets."""

    async with control_session() as db:
        query = select(PlatformUser).where(PlatformUser.active.is_(True)).order_by(PlatformUser.name, PlatformUser.email)
        term = search.strip()
        if term:
            pattern = f"%{term}%"
            query = query.where(or_(PlatformUser.name.ilike(pattern), PlatformUser.email.ilike(pattern)))
        query = query.limit(25)
        rows = (await db.scalars(query)).all()
        platform_audit(db, actor.user_id, "support.assignees.read", details={"count": len(rows), "search": bool(term)})
        return [{"id": row.id, "name": row.name, "email": row.email, "role": row.role} for row in rows]


@router.get("/platform/support/activity")
async def platform_support_activity(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    ticket_id: str | None = Query(default=None, max_length=36),
    tenant_id: UUID | None = Query(default=None),
    search: str = Query(default="", max_length=120),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("support.tenant_support_case.read")),
):
    """Return paginated Support lifecycle events without duplicating ticket ownership."""

    async with control_session() as db:
        organization = await db.get(Organization, str(tenant_id)) if tenant_id else None
        if tenant_id and organization is None:
            raise HTTPException(404, "Organization not found")
        query = select(PlatformSupportTicket).order_by(PlatformSupportTicket.updated_at.desc(), PlatformSupportTicket.created_at.desc())
        if ticket_id:
            query = query.where(PlatformSupportTicket.id == ticket_id)
        if organization:
            query = query.where(PlatformSupportTicket.organization_id == organization.id)
        rows = (await db.scalars(query)).all()
        organization_ids = {ticket.organization_id for ticket in rows}
        organizations = {
            row.id: row
            for row in (await db.scalars(select(Organization).where(Organization.id.in_(organization_ids)))).all()
        } if organization_ids else {}
        term = search.strip().lower()
        items = []
        for ticket in rows:
            context = ticket.context or {}
            for index, event in enumerate(context.get("events") or []):
                haystack = " ".join(
                    str(value or "")
                    for value in (ticket.subject, ticket.organization_id, organizations.get(ticket.organization_id).name if ticket.organization_id in organizations else "", event.get("kind"), event.get("note"), event.get("actor_id"))
                ).lower()
                if term and term not in haystack:
                    continue
                items.append({
                    "id": f"{ticket.id}:{index}",
                    "ticket_id": ticket.id,
                    "subject": ticket.subject,
                    "organization_id": ticket.organization_id,
                    "organization_name": organizations.get(ticket.organization_id).name if ticket.organization_id in organizations else "Unknown tenant",
                    "kind": event.get("kind", "updated"),
                    "actor_id": event.get("actor_id"),
                    "at": event.get("at") or ticket.updated_at,
                    "note": event.get("note"),
                    "status": event.get("status"),
                    "previous_status": event.get("previous_status"),
                    "priority": event.get("priority"),
                    "assignee_id": event.get("assignee_id"),
                })
        items.sort(key=lambda item: item.get("at") or "", reverse=True)
        total = len(items)
        start = (page - 1) * page_size
        platform_audit(
            db,
            actor.user_id,
            "support.activity.read",
            organization_id=organization.id if organization else None,
            details={"page": page, "page_size": page_size, "total": total, "ticket_id": ticket_id},
        )
        return {"page": page, "page_size": page_size, "total": total, "items": items[start:start + page_size]}


@router.patch("/platform/support/tickets/{ticket_id}")
async def update_platform_support_ticket(
    ticket_id: str,
    body: PlatformSupportTicketUpdate,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("support.tenant_support_case.update")),
):
    """Apply an auditable Support lifecycle transition to the shared ticket record."""

    async with control_session() as db:
        ticket = await db.get(PlatformSupportTicket, ticket_id)
        if ticket is None:
            raise HTTPException(404, "Support ticket not found")
        before = {
            "status": ticket.status,
            "priority": ticket.priority,
            "assignee_id": ticket.assignee_id,
            "resolution_code": ticket.resolution_code,
            "resolution_note": ticket.resolution_note,
        }
        action = body.action
        next_status = body.status
        assignee_id = ticket.assignee_id
        if action == "assign":
            assignee_id = actor.user_id
        elif action == "unassign":
            assignee_id = None
        elif action == "reopen":
            next_status = "open"
        elif action == "resolve":
            next_status = "resolved"
        elif action == "close":
            next_status = "closed"
        if body.assignee_id is not None and action not in {"assign", "unassign"}:
            assignee = await db.get(PlatformUser, str(body.assignee_id))
            if assignee is None or not assignee.active:
                raise HTTPException(422, "Assignee is not an active platform user")
            assignee_id = assignee.id
        if next_status is None and body.priority is None and body.assignee_id is None and body.resolution_code is None and body.resolution_note is None and body.note is None and action not in {"assign", "unassign"}:
            raise HTTPException(422, "At least one ticket lifecycle update is required")
        if next_status is not None and next_status not in SUPPORT_TICKET_TRANSITIONS.get(ticket.status, {ticket.status}):
            raise HTTPException(409, f"Cannot move a {ticket.status} ticket to {next_status}")
        if next_status in {"resolved", "closed"} and next_status != ticket.status and not (body.note or body.resolution_note or ticket.resolution_note):
            raise HTTPException(422, "A resolution note is required before resolving or closing a ticket")
        changed = False
        if next_status is not None and next_status != ticket.status:
            ticket.status = next_status
            changed = True
            if next_status == "resolved":
                ticket.resolved_at = datetime.now(UTC)
            elif next_status == "closed":
                ticket.closed_at = datetime.now(UTC)
            elif next_status == "open":
                ticket.closed_at = None
                ticket.resolved_at = None
            _ticket_event(ticket, actor.user_id, "status_changed", previous_status=before["status"], status=next_status, note=body.note or "")
        if body.priority is not None and body.priority != ticket.priority:
            ticket.priority = body.priority
            changed = True
            _ticket_event(ticket, actor.user_id, "priority_changed", priority=body.priority)
        if assignee_id != ticket.assignee_id:
            ticket.assignee_id = assignee_id
            changed = True
            _ticket_event(ticket, actor.user_id, "assigned" if assignee_id else "unassigned", assignee_id=assignee_id)
        if body.resolution_code is not None:
            ticket.resolution_code = body.resolution_code
            changed = True
        if body.resolution_note is not None:
            ticket.resolution_note = body.resolution_note
            changed = True
        if body.note and action not in {"resolve", "close"}:
            changed = True
            _ticket_event(ticket, actor.user_id, "note", note=body.note)
        if not changed:
            raise HTTPException(422, "The ticket already has the requested lifecycle state")
        ticket.updated_by = actor.user_id
        await db.flush()
        organization = await db.get(Organization, ticket.organization_id)
        after = {
            "status": ticket.status,
            "priority": ticket.priority,
            "assignee_id": ticket.assignee_id,
            "resolution_code": ticket.resolution_code,
            "resolution_note": ticket.resolution_note,
        }
        platform_audit(
            db,
            actor.user_id,
            "support.ticket.update",
            organization_id=ticket.organization_id,
            reason=body.note or action or body.status or body.priority or "Support ticket updated",
            details={"ticket_id": ticket.id, "before": before, "after": after},
        )
        event_kind = "support.ticket.status_changed" if before["status"] != ticket.status else "support.ticket.updated"
        enqueue_platform_notification(
            db,
            kind=event_kind,
            reference_id=f"{ticket.id}:{datetime.now(UTC).isoformat()}",
            actor_id=actor.user_id,
            payload={
                "ticket_id": ticket.id,
                "organization_id": ticket.organization_id,
                "organization_name": organization.name if organization else "Unknown tenant",
                "source": ticket.source,
                "subject": ticket.subject,
                "previous_status": before["status"],
                "status": ticket.status,
                "detail": f"{organization.name if organization else 'Unknown tenant'} · {ticket.subject}",
                "cta_label": "Open Support",
                "target_url": f"/admin/support/?tenant={ticket.organization_id}",
            },
        )
        users = {}
        if ticket.assignee_id:
            assignee = await db.get(PlatformUser, ticket.assignee_id)
            if assignee:
                users[assignee.id] = assignee
        return _ticket_payload(ticket, {organization.id: organization} if organization else {}, users)


# Handle platform billing features for this module.
@router.get("/platform/billing/features")
async def platform_billing_features(
    include_inactive: bool = Query(default=False),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.plan_assignment.read")),
):
    async with control_session() as db:
        query = select(PlatformFeature).order_by(PlatformFeature.category, PlatformFeature.name)
        if not include_inactive:
            query = query.where(PlatformFeature.active)
        rows = (await db.scalars(query)).all()
        platform_audit(db, actor.user_id, "billing.features.read", details={"include_inactive": include_inactive})
        return [
            {
                "id": row.id, "key": row.key, "name": row.name, "description": row.description,
                "category": row.category, "feature_type": row.feature_type, "unit": row.unit, "active": row.active,
            }
            for row in rows
        ]


# Create or issue create platform feature while applying existing validation and authorization.
@router.post("/platform/billing/features", status_code=201)
async def create_platform_feature(
    body: PlatformFeatureInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.plan_assignment.create")),
):
    async with control_session() as db:
        if await db.scalar(select(PlatformFeature).where(PlatformFeature.key == body.key)):
            raise HTTPException(409, "A feature with this key already exists")
        feature = PlatformFeature(**body.model_dump(), created_by=actor.user_id, updated_by=actor.user_id)
        db.add(feature)
        await db.flush()
        platform_audit(db, actor.user_id, "billing.feature.create", details={"feature_key": feature.key})
        return {"id": feature.id, **body.model_dump()}


# Update update platform feature while preserving existing validation and audit behavior.
@router.put("/platform/billing/features/{feature_id}")
async def update_platform_feature(
    feature_id: str,
    body: PlatformFeatureInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.plan_assignment.update")),
):
    async with control_session() as db:
        feature = await db.get(PlatformFeature, feature_id)
        if feature is None:
            raise HTTPException(404, "Feature not found")
        duplicate = await db.scalar(select(PlatformFeature).where(PlatformFeature.key == body.key, PlatformFeature.id != feature_id))
        if duplicate:
            raise HTTPException(409, "A feature with this key already exists")
        for key, value in body.model_dump().items():
            setattr(feature, key, value)
        feature.updated_by = actor.user_id
        await db.flush()
        platform_audit(db, actor.user_id, "billing.feature.update", details={"feature_id": feature_id, "feature_key": feature.key})
        return {"id": feature.id, **body.model_dump()}


@router.get("/public/platform/plans")
async def public_platform_plans():
    """Return active commercial plans for the public Platform Home pricing page."""
    async with control_session() as db:
        plans = (await db.scalars(select(PlatformPlan).where(PlatformPlan.active))).all()
        plans = sorted(plans, key=lambda plan: (plan.price_cents == 0, plan.price_cents, plan.name))
        return [await platform_plan_payload_with_entitlements(db, plan) for plan in plans]


# Handle platform billing plans for this module.
@router.get("/platform/billing/plans")
async def platform_billing_plans(
    include_inactive: bool = Query(default=False),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.plan_assignment.read")),
):
    async with control_session() as db:
        query = select(PlatformPlan).order_by(PlatformPlan.active.desc(), PlatformPlan.price_cents, PlatformPlan.name)
        if not include_inactive:
            query = query.where(PlatformPlan.active)
        plans = (await db.scalars(query)).all()
        platform_audit(db, actor.user_id, "billing.plans.read", details={"include_inactive": include_inactive})
        return [await platform_plan_payload_with_entitlements(db, plan) for plan in plans]


# Create or issue create platform plan while applying existing validation and authorization.
@router.post("/platform/billing/plans", status_code=201)
async def create_platform_plan(
    body: PlatformPlanInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.plan_assignment.create")),
):
    async with control_session() as db:
        if await db.scalar(select(PlatformPlan).where(PlatformPlan.code == body.code)):
            raise HTTPException(409, "A plan with this code already exists")
        plan = PlatformPlan(**body.model_dump(exclude={"entitlements"}), created_by=actor.user_id, updated_by=actor.user_id)
        db.add(plan)
        await db.flush()
        await sync_plan_entitlements(db, plan, body.entitlements, actor.user_id)
        platform_audit(db, actor.user_id, "billing.plan.create", details={"plan_code": plan.code})
        return await platform_plan_payload_with_entitlements(db, plan)


# Update update platform plan while preserving existing validation and audit behavior.
@router.put("/platform/billing/plans/{plan_id}")
async def update_platform_plan(
    plan_id: str,
    body: PlatformPlanInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.plan_assignment.update")),
):
    async with control_session() as db:
        plan = await db.get(PlatformPlan, plan_id)
        if plan is None:
            raise HTTPException(404, "Plan not found")
        duplicate = await db.scalar(select(PlatformPlan).where(PlatformPlan.code == body.code, PlatformPlan.id != plan_id))
        if duplicate:
            raise HTTPException(409, "A plan with this code already exists")
        for key, value in body.model_dump(exclude={"entitlements"}).items():
            setattr(plan, key, value)
        plan.updated_by = actor.user_id
        await sync_plan_entitlements(db, plan, body.entitlements, actor.user_id)
        await db.flush()
        platform_audit(db, actor.user_id, "billing.plan.update", details={"plan_id": plan_id, "plan_code": plan.code})
        return await platform_plan_payload_with_entitlements(db, plan)


# Handle platform billing subscriptions for this module.
@router.get("/platform/billing/subscriptions")
async def platform_billing_subscriptions(
    search: str | None = Query(default=None, max_length=160),
    status: str | None = Query(default=None, max_length=30),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=10, le=MAX_PAGE_SIZE),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.subscription_record.read")),
):
    async with control_session() as db:
        query = (
            select(Organization, PlatformCommercialAccount, PlatformSubscription, PlatformPlan)
            .join(PlatformCommercialAccount, PlatformCommercialAccount.organization_id == Organization.id)
            .outerjoin(PlatformSubscription, PlatformSubscription.organization_id == Organization.id)
            .outerjoin(PlatformPlan, PlatformPlan.id == PlatformSubscription.plan_id)
        )
        if search:
            term = f"%{search.strip()}%"
            query = query.where(or_(Organization.name.ilike(term), Organization.slug.ilike(term)))
        if status:
            query = query.where(PlatformSubscription.status == status)
        total = await db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
        rows = (await db.execute(query.order_by(Organization.name, Organization.id).offset((page - 1) * page_size).limit(page_size))).all()
        items = []
        for organization, account, subscription, plan in rows:
            items.append({
                "organization_id": organization.id,
                "organization_name": organization.name,
                "slug": organization.slug,
                "account_status": account.account_status,
                "legacy_plan_code": account.plan_code,
                "subscription_status": subscription.status if subscription else account.subscription_status,
                "subscription": {
                    "id": subscription.id,
                    "plan": await platform_plan_payload_with_entitlements(db, plan) if plan else None,
                    "trial_ends_at": subscription.trial_ends_at,
                    "current_period_start": subscription.current_period_start,
                    "current_period_end": subscription.current_period_end,
                    "cancel_at_period_end": subscription.cancel_at_period_end,
                    "external_reference": subscription.external_reference,
                } if subscription else None,
            })
        platform_audit(db, actor.user_id, "billing.subscriptions.read", details={"page": page, "page_size": page_size})
        return {"page": page, "page_size": page_size, "total": total, "items": jsonable_encoder(items)}


@router.get("/platform/organizations/{identifier}/billing/ledger")
async def platform_organization_billing_ledger(
    identifier: str,
    months: int = Query(default=12, ge=1, le=60),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.subscription_record.read")),
):
    """Return live tenant invoice totals for the Billing & plans detail chart."""
    async with control_session() as db:
        organization = await db.get(Organization, identifier)
        if organization is None:
            raise HTTPException(404, "Organization not found")
        platform_audit(
            db,
            actor.user_id,
            "billing.ledger.read",
            organization_id=identifier,
            details={"months": months},
        )

    now = datetime.now(UTC)
    current_month = datetime(now.year, now.month, 1, tzinfo=UTC)
    month_keys: list[tuple[int, int]] = []
    for offset in range(months - 1, -1, -1):
        month_index = current_month.month - 1 - offset
        year = current_month.year + month_index // 12
        month = month_index % 12 + 1
        month_keys.append((year, month))
    month_lookup = {key: index for index, key in enumerate(month_keys)}
    month_totals = [0] * len(month_keys)
    month_invoice_counts = [0] * len(month_keys)

    async with organization_session(organization) as tenant_db:
        invoices = (
            await tenant_db.scalars(
                select(Invoice)
                .where(Invoice.created_at >= current_month)
                .order_by(Invoice.created_at.desc())
            )
        ).all()

    invoice_items = []
    for invoice in invoices:
        created_at = invoice.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        key = (created_at.year, created_at.month)
        month_index = month_lookup.get(key)
        if month_index is None:
            continue
        amount_cents = int(invoice.total_cents + invoice.adjustment_cents)
        month_totals[month_index] += amount_cents
        month_invoice_counts[month_index] += 1
        invoice_items.append(
            {
                "id": invoice.id,
                "created_at": created_at.isoformat(),
                "amount_cents": amount_cents,
                "paid_cents": int(invoice.paid_cents),
                "status": invoice.status,
            }
        )

    return {
        "months": [
            {
                "month": f"{year:04d}-{month:02d}",
                "amount_cents": month_totals[index],
                "invoice_count": month_invoice_counts[index],
            }
            for index, (year, month) in enumerate(month_keys)
        ],
        "invoices": invoice_items,
    }


# Update set platform subscription while preserving existing validation and audit behavior.
@router.put("/platform/organizations/{identifier}/subscription")
async def set_platform_subscription(
    identifier: str,
    body: SubscriptionInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.subscription_record.update", workflow_handles_approval=True)),
):
    async with control_session() as db:
        organization = await db.get(Organization, identifier)
        if organization is None:
            raise HTTPException(404, "Organization not found")
        plan = await db.scalar(select(PlatformPlan).where(PlatformPlan.code == body.plan_code))
        if plan is None or (not plan.active and body.status != "canceled"):
            raise HTTPException(400, "The selected plan is unavailable")
        account = await db.scalar(select(PlatformCommercialAccount).where(PlatformCommercialAccount.organization_id == identifier))
        if account is None:
            account = PlatformCommercialAccount(organization_id=identifier, created_by=actor.user_id, updated_by=actor.user_id)
            db.add(account)
        subscription = await db.scalar(select(PlatformSubscription).where(PlatformSubscription.organization_id == identifier))
        if subscription is None:
            subscription = PlatformSubscription(organization_id=identifier, created_by=actor.user_id, updated_by=actor.user_id)
            db.add(subscription)
        subscription.plan_id = plan.id
        subscription.status = body.status
        subscription.trial_ends_at = body.trial_ends_at
        subscription.current_period_start = body.current_period_start
        subscription.current_period_end = body.current_period_end
        subscription.cancel_at_period_end = body.cancel_at_period_end
        subscription.external_reference = body.external_reference
        subscription.updated_by = actor.user_id
        account.plan_code = plan.code
        account.subscription_status = body.status
        account.updated_by = actor.user_id
        organization.plan = plan.code
        organization.updated_by = actor.user_id
        await db.flush()
        platform_audit(db, actor.user_id, "billing.subscription.update", organization_id=identifier, details={"plan_code": plan.code, "status": body.status})
        return {
            "organization_id": identifier,
            "plan": await platform_plan_payload_with_entitlements(db, plan),
            "status": subscription.status,
            "trial_ends_at": subscription.trial_ends_at,
            "current_period_start": subscription.current_period_start,
            "current_period_end": subscription.current_period_end,
            "cancel_at_period_end": subscription.cancel_at_period_end,
        }


# Handle platform financial operations for this module.
@router.get("/platform/financial-operations/query")
async def platform_financial_operations(
    search: str | None = Query(default=None, max_length=160),
    status: str | None = Query(default=None, max_length=30),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=10, le=MAX_PAGE_SIZE),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.commercial_account.read")),
):
    async with control_session() as db:
        query = select(Organization, PlatformCommercialAccount).join(
            PlatformCommercialAccount,
            PlatformCommercialAccount.organization_id == Organization.id,
        )
        if search:
            term = f"%{search.strip()}%"
            query = query.where(
                or_(Organization.name.ilike(term), Organization.slug.ilike(term))
            )
        if status:
            query = query.where(PlatformCommercialAccount.subscription_status == status)
        total = await db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
        rows = (
            await db.execute(
                query.order_by(Organization.name, Organization.id)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
    items = []
    for organization, account in rows:
        invoiced_cents = 0
        paid_cents = 0
        open_invoices = 0
        locations = 0
        staff_seats = 0
        try:
            async with organization_session(organization) as tenant_db:
                invoiced_cents, paid_cents, open_invoices = (
                    await tenant_db.execute(
                        select(
                            func.coalesce(func.sum(Invoice.total_cents), 0),
                            func.coalesce(func.sum(Invoice.paid_cents), 0),
                            func.count().filter(Invoice.status != "paid"),
                        )
                    )
                ).one()
                locations = await tenant_db.scalar(
                    select(func.count()).select_from(Location).where(Location.active.is_(True))
                ) or 0
                staff_seats = await tenant_db.scalar(
                    select(func.count()).select_from(StaffUser).where(StaffUser.active)
                ) or 0
        except Exception:
            pass
        items.append(
            {
                "organization_id": organization.id,
                "organization_name": organization.name,
                "slug": organization.slug,
                "plan_code": account.plan_code,
                "account_status": account.account_status,
                "subscription_status": account.subscription_status,
                "external_reference": account.external_reference,
                "locations": int(locations),
                "staff_seats": int(staff_seats),
                "invoiced_cents": int(invoiced_cents),
                "paid_cents": int(paid_cents),
                "open_invoices": int(open_invoices),
            }
        )
    async with control_session() as db:
        platform_audit(
            db,
            actor.user_id,
            "financial-operations.query",
            details={"page": page, "page_size": page_size},
        )
    return {"page": page, "page_size": page_size, "total": total, "items": items}


# Retrieve get platform defaults for the current request or workflow.
@router.get("/platform/settings/defaults")
async def get_platform_defaults(actor: PlatformActor = Depends(platform_or_bootstrap)):
    async with control_session() as db:
        row = await platform_configuration(db)
        platform_audit(db, actor.user_id, "platform-defaults.read")
        return {
            "default_visibility": row.default_visibility,
            "default_policy": Policy(**row.default_policy).model_dump(),
        }


# Update set platform defaults while preserving existing validation and audit behavior.
@router.put("/platform/settings/defaults")
async def set_platform_defaults(
    body: PlatformDefaultsInput,
    actor: PlatformActor = Depends(platform_or_bootstrap),
):
    async with control_session() as db:
        row = await platform_configuration(db)
        row.default_visibility = body.default_visibility
        row.default_policy = body.default_policy.model_dump()
        row.updated_by = actor.user_id
        platform_audit(db, actor.user_id, "platform-defaults.configure")
        return body.model_dump()


# Handle platform communication templates for this module.
@router.get("/platform/communication-templates")
async def platform_communication_templates(
    actor: PlatformActor = Depends(platform_or_bootstrap),
):
    async with control_session() as db:
        row = await platform_configuration(db)
        platform_audit(db, actor.user_id, "platform-template.list")
        return row.communication_templates


# Update set platform communication template while preserving existing validation and audit behavior.
@router.put("/platform/communication-templates/{key}")
async def set_platform_communication_template(
    key: str,
    body: CommunicationTemplateInput,
    actor: PlatformActor = Depends(platform_or_bootstrap),
):
    if not re.fullmatch(r"[a-z0-9-]{3,80}", key):
        raise HTTPException(422, "Invalid template key")
    async with control_session() as db:
        row = await platform_configuration(db)
        row.communication_templates = {**row.communication_templates, key: body.model_dump()}
        row.updated_by = actor.user_id
        platform_audit(db, actor.user_id, "platform-template.configure", details={"key": key})
        return row.communication_templates[key]


# Handle platform access query for this module.
@router.get("/platform/access/query")
async def platform_access_query(
    search: str | None = Query(default=None, max_length=160),
    status: str | None = Query(default=None, pattern="^(active|disabled|pending|expired|revoked)$"),
    role: str | None = Query(default=None, max_length=80),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=10, le=MAX_PAGE_SIZE),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("access.platform_user.read")),
):
    now = int(time.time())
    async with control_session() as db:
        assignment_rows = (
            await db.execute(
                select(PlatformRoleAssignment.user_id, PlatformRoleAssignment.role_id, PlatformRole.name)
                .join(PlatformRole, PlatformRole.id == PlatformRoleAssignment.role_id)
            )
        ).all()
        assignments_by_user: dict[str, list[dict[str, str | None]]] = {}
        for user_id, role_id, role_name in assignment_rows:
            assignments_by_user.setdefault(user_id, []).append(
                {"role": role_name, "role_id": role_id, "scope": "Platform", "location_id": None}
            )
        platform_roles = {
            role.id: role.name
            for role in (await db.scalars(select(PlatformRole))).all()
        }
        users = (await db.scalars(select(PlatformUser).order_by(PlatformUser.created_at.desc()))).all()
        invitations = (
            await db.scalars(select(PlatformInvite).order_by(PlatformInvite.created_at.desc()))
        ).all()
        items = [
            {
                "id": row.id,
                "kind": "user",
                "name": row.name,
                "email": row.email,
                "role": (assignments_by_user.get(row.id) or [{}])[0].get("role") or row.role,
                "assignments": assignments_by_user.get(row.id, []),
                "status": "active" if row.active else "disabled",
                "mfa_enabled": row.mfa_enabled,
                "created_at": row.created_at,
                "expires": None,
            }
            for row in users
        ] + [
            {
                "id": row.id,
                "kind": "invitation",
                "name": row.name,
                "email": row.email,
                "role": platform_roles.get(row.role, row.role),
                "role_id": row.role,
                "status": "expired" if row.status == "pending" and row.expires <= now else row.status,
                "mfa_enabled": False,
                "created_at": row.created_at,
                "expires": row.expires,
            }
            for row in invitations
        ]
        if search:
            term = search.strip().lower()
            items = [item for item in items if term in f"{item['name']} {item['email']}".lower()]
        if status:
            items = [item for item in items if item["status"] == status]
        if role:
            role_value = role.strip().lower()
            items = [
                item for item in items
                if any(
                    role_value in {str(assignment.get("role_id", "")).lower(), str(assignment.get("role", "")).lower()}
                    for assignment in item.get("assignments", [])
                ) or role_value in {
                    str(item.get("role_id", "")).lower(),
                    str(item.get("role", "")).lower(),
                }
            ]
        items.sort(key=lambda item: item["created_at"], reverse=True)
        total = len(items)
        start = (page - 1) * page_size
        platform_audit(db, actor.user_id, "platform-access.query")
        return {"page": page, "page_size": page_size, "total": total, "items": items[start:start + page_size]}


# Handle platform notifications for this module.
@router.get("/platform/notifications")
async def platform_notifications(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10, ge=10, le=50),
    actor: PlatformActor = Depends(platform_or_bootstrap),
):
    async with control_session() as db:
        total = await db.scalar(select(func.count()).select_from(PlatformOutboxMessage)) or 0
        unread_count = await db.scalar(
            select(func.count()).select_from(PlatformOutboxMessage).where(
                PlatformOutboxMessage.status.in_(("pending", "retry", "failed"))
            )
        ) or 0
        rows = (
            await db.scalars(
                select(PlatformOutboxMessage)
                .order_by(PlatformOutboxMessage.created_at.desc())
                .offset((page - 1) * size)
                .limit(size)
            )
        ).all()
        items = []
        for row in rows:
            status = row.status or "pending"
            severity = "danger" if status in {"failed", "retry"} else "warning" if status == "pending" else "info"
            kind = row.kind.replace(".", " ").replace("_", " ").strip().capitalize()
            payload = row.payload if isinstance(row.payload, dict) else {}
            detail = payload.get("detail") or payload.get("subject") or payload.get("title") or (
                "Delivery failed and needs attention" if status in {"failed", "retry"}
                else "Delivery is queued" if status == "pending" else "Delivery completed"
            )
            cta_label = payload.get("cta_label")
            if not cta_label:
                cta_label = (
                    "Review payment" if "payment" in row.kind or "billing" in row.kind
                    else "View appointment" if "appointment" in row.kind or "schedule" in row.kind
                    else "View patient item" if "patient" in row.kind
                    else "View invitation" if "invitation" in row.kind
                    else "Review recovery" if "password" in row.kind or "recovery" in row.kind
                    else "View notification"
                )
            items.append({
                "id": row.id,
                "kind": row.kind,
                "title": kind,
                "detail": str(detail),
                "status": status,
                "severity": severity,
                "created_at": row.created_at,
                "unread": status in {"pending", "retry", "failed"},
                "cta_label": str(cta_label),
                "target_url": payload.get("target_url"),
            })
        platform_audit(db, actor.user_id, "platform-notifications.read")
        return {
            "items": items,
            "page": page,
            "size": size,
            "total": total,
            "pages": (total + size - 1) // size,
            "unread_count": unread_count,
        }


# Create or issue create platform invite while applying existing validation and authorization.
@router.post("/platform/invites", status_code=201)
async def create_platform_invite(
    body: PlatformInviteInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("access.platform_user.create")),
):
    raw = secrets.token_urlsafe(32)
    async with control_session() as db:
        if await db.scalar(select(PlatformUser).where(PlatformUser.email == body.email.lower())):
            raise HTTPException(409, "Platform user already exists")
        role_identifier = body.role.strip()
        if role_identifier == "platform_admin":
            role_identifier = "platform-super-admin"
        role = await db.scalar(
            select(PlatformRole).where(
                (PlatformRole.id == role_identifier)
                | (func.lower(PlatformRole.name) == role_identifier.lower())
            )
        )
        if role is None or role.status != "published":
            raise HTTPException(422, "Select a published platform role")
        old = (
            await db.scalars(
                select(PlatformInvite).where(
                    PlatformInvite.email == body.email.lower(), PlatformInvite.status == "pending"
                )
            )
        ).all()
        for invitation in old:
            invitation.status = "revoked"
            invitation.updated_by = actor.user_id
        row = PlatformInvite(
            name=body.name,
            email=body.email.lower(),
            role=role.id,
            token_hash=digest(raw),
            expires=int(time.time()) + 86400,
            created_by=actor.user_id,
            updated_by=actor.user_id,
        )
        db.add(row)
        await db.flush()
        delivery = await enqueue_platform_email(
            db,
            kind="platform.invitation",
            destination=row.email,
            recipient_name=row.name,
            raw_token=raw,
            reference_id=row.id,
            actor_id=actor.user_id,
            template_values={
                "role": role.name,
                "invitation_expires_at": datetime.fromtimestamp(row.expires, UTC).strftime("%B %-d, %Y at %-I:%M %p UTC"),
                "invitation_expires_in": "24 hours",
            },
        )
        platform_audit(db, actor.user_id, "platform-invite.create", details={"invite_id": row.id})
        return {
            "invite_id": row.id,
            "delivery_id": delivery.id,
            "delivery_status": delivery.status,
            "expires": row.expires,
        }


# Handle resend platform invite for this module.
@router.post("/platform/invites/{identifier}/resend", status_code=201)
async def resend_platform_invite(
    identifier: str,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("access.platform_user.update")),
):
    async with control_session() as db:
        invitation = await required(db, PlatformInvite, identifier, lock=True)
        if invitation.status not in {"pending", "expired"}:
            raise HTTPException(409, "Invitation cannot be resent")
        invitation.status = "revoked"
        invitation.updated_by = actor.user_id
        raw = secrets.token_urlsafe(32)
        replacement = PlatformInvite(
            name=invitation.name,
            email=invitation.email,
            role=invitation.role,
            token_hash=digest(raw),
            expires=int(time.time()) + 86400,
            created_by=actor.user_id,
            updated_by=actor.user_id,
        )
        db.add(replacement)
        await db.flush()
        delivery = await enqueue_platform_email(
            db,
            kind="platform.invitation",
            destination=replacement.email,
            recipient_name=replacement.name,
            raw_token=raw,
            reference_id=replacement.id,
            actor_id=actor.user_id,
            template_values={
                "role": (await db.get(PlatformRole, replacement.role)).name,
                "invitation_expires_at": datetime.fromtimestamp(replacement.expires, UTC).strftime("%B %-d, %Y at %-I:%M %p UTC"),
                "invitation_expires_in": "24 hours",
            },
        )
        platform_audit(db, actor.user_id, "platform-invite.resend", details={"invite_id": replacement.id})
        return {
            "invite_id": replacement.id,
            "delivery_id": delivery.id,
            "delivery_status": delivery.status,
            "expires": replacement.expires,
        }


# Apply the revoke platform invite lifecycle transition and its existing safeguards.
@router.post("/platform/invites/{identifier}/revoke")
async def revoke_platform_invite(
    identifier: str,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("access.platform_user.update")),
):
    async with control_session() as db:
        invitation = await required(db, PlatformInvite, identifier, lock=True)
        if invitation.status != "pending":
            raise HTTPException(409, "Invitation is not pending")
        invitation.status = "revoked"
        invitation.updated_by = actor.user_id
        platform_audit(db, actor.user_id, "platform-invite.revoke", details={"invite_id": invitation.id})
        return {"revoked": True}


# Update set platform user status while preserving existing validation and audit behavior.
@router.put("/platform/users/{identifier}/status")
async def set_platform_user_status(
    identifier: str,
    body: PlatformUserStatusInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("access.platform_user.update")),
):
    if identifier == actor.user_id and not body.active:
        raise HTTPException(409, "You cannot disable your own platform account")
    async with control_session() as db:
        user = await required(db, PlatformUser, identifier, lock=True)
        user.active = body.active
        user.token_version += 1
        user.updated_by = actor.user_id
        platform_audit(db, actor.user_id, "platform-user.status", details={"user_id": user.id, "active": body.active})
        return {"id": user.id, "active": user.active}


# Handle initiate platform password reset for this module.
@router.post("/platform/users/{identifier}/password-reset", status_code=201)
async def initiate_platform_password_reset(
    identifier: str,
    body: PlatformPasswordResetInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("support.password_recovery.initiate_password_reset")),
):
    raw = secrets.token_urlsafe(32)
    now = int(time.time())
    async with control_session() as db:
        user = await required(db, PlatformUser, identifier, lock=True)
        if not user.active:
            raise HTTPException(409, "Password reset requires an active platform account")
        previous = (
            await db.scalars(
                select(PlatformPasswordResetChallenge).where(
                    PlatformPasswordResetChallenge.user_id == user.id,
                    PlatformPasswordResetChallenge.used.is_(False),
                )
            )
        ).all()
        for challenge in previous:
            challenge.used = True
            challenge.updated_by = actor.user_id
        challenge = PlatformPasswordResetChallenge(
            user_id=user.id,
            token_hash=digest(raw),
            expires=now + 3600,
            initiated_by=actor.user_id,
            reason=body.reason,
            created_by=actor.user_id,
            updated_by=actor.user_id,
        )
        db.add(challenge)
        await db.flush()
        delivery = await enqueue_platform_email(
            db,
            kind="platform.password-reset",
            destination=user.email,
            recipient_name=user.name,
            raw_token=raw,
            reference_id=challenge.id,
            actor_id=actor.user_id,
        )
        await db.execute(
            update(PlatformSession)
            .where(PlatformSession.user_id == user.id, PlatformSession.revoked.is_(False))
            .values(revoked=True, updated_by=actor.user_id)
        )
        user.token_version += 1
        user.updated_by = actor.user_id
        platform_audit(
            db,
            actor.user_id,
            "platform-user.password-reset.initiate",
            reason=body.reason,
            details={"user_id": user.id, "challenge_id": challenge.id, "delivery_id": delivery.id},
        )
        return {
            "user_id": user.id,
            "delivery_id": delivery.id,
            "delivery_status": delivery.status,
            "expires": challenge.expires,
        }


# Handle platform adapter defaults for this module.
@router.get("/platform/adapter-defaults")
async def platform_adapter_defaults(actor: PlatformActor = Depends(permit_platform_or_bootstrap("integrations.platform_adapter_default.read"))):
    async with control_session() as db:
        rows = (
            await db.scalars(
                select(PlatformAdapterDefault).order_by(
                    PlatformAdapterDefault.region, PlatformAdapterDefault.capability
                )
            )
        ).all()
        platform_audit(db, actor.user_id, "adapter-default.list")
        return [serialize(row) for row in rows]


# Update set platform adapter default while preserving existing validation and audit behavior.
@router.put("/platform/adapter-defaults")
async def set_platform_adapter_default(
    body: AdapterDefaultInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("integrations.platform_adapter_default.update", workflow_handles_approval=True)),
):
    async with control_session() as db:
        runtime_payload = body.model_dump(exclude={"reason", "approval_request_id"})
        decision = await decide_platform(
            db,
            actor.user_id,
            "integrations.platform_adapter_default.update",
        )
        approval = None
        if decision.needs_approval:
            if body.approval_request_id:
                approval = await authorize_runtime_action(
                    db,
                    request_id=body.approval_request_id,
                    permission_key="integrations.platform_adapter_default.update",
                    payload=runtime_payload,
                    maker_id=actor.user_id,
                    request_model=PlatformChangeRequest,
                )
            else:
                approval, created = await create_runtime_action_request(
                    db,
                    permission_key="integrations.platform_adapter_default.update",
                    payload=runtime_payload,
                    reason=body.reason,
                    maker_id=actor.user_id,
                    context=await platform_policy_context(db),
                    request_model=PlatformChangeRequest,
                    policy_model=PlatformApprovalPolicy,
                )
                platform_audit(
                    db,
                    actor.user_id,
                    "adapter-default.approval-requested",
                    reason=body.reason,
                    details={"request_id": approval.id, "created": created, **runtime_payload},
                )
                return JSONResponse(
                    status_code=202,
                    content=jsonable_encoder({
                        "status": "approval_required",
                        "request": await request_payload(db, approval, PlatformChangeDecision),
                    }),
                )
        row = await db.scalar(
            select(PlatformAdapterDefault).where(
                PlatformAdapterDefault.region == body.region,
                PlatformAdapterDefault.capability == body.capability,
            )
        )
        if row is None:
            row = PlatformAdapterDefault(
                **runtime_payload, created_by=actor.user_id, updated_by=actor.user_id
            )
            db.add(row)
        else:
            row.provider_name = body.provider_name
            row.active = body.active
            row.updated_by = actor.user_id
        platform_audit(
            db,
            actor.user_id,
            "adapter-default.configure",
            details={"region": body.region, "capability": body.capability},
        )
        if approval:
            await complete_runtime_action(
                approval,
                {"resource": "platform_adapter_default", "resource_id": row.id},
            )
        await db.flush()
        return serialize(row)


# Handle platform integration requests for this module.
@router.get("/platform/integration-requests")
async def platform_integration_requests(
    status: str | None = Query(default=None, pattern="^(pending|approved|rejected)$"),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("integrations.customization_request.read")),
):
    async with control_session() as db:
        query = select(AdapterCustomizationRequest).order_by(
            AdapterCustomizationRequest.created_at.desc()
        )
        if status:
            query = query.where(AdapterCustomizationRequest.status == status)
        rows = (await db.scalars(query.limit(500))).all()
        platform_audit(db, actor.user_id, "adapter-request.list")
        return [serialize(row) for row in rows]


# Handle decide integration request for this module.
@router.put("/platform/integration-requests/{identifier}")
async def decide_integration_request(
    identifier: str,
    body: AdapterDecision,
    actor: PlatformActor = Depends(integration_request_actor),
):
    async with control_session() as db:
        request = await db.scalar(
            select(AdapterCustomizationRequest)
            .where(AdapterCustomizationRequest.id == identifier)
            .with_for_update()
        )
        if request is None:
            raise HTTPException(404, "Integration request not found")
        if request.status != "pending":
            raise HTTPException(409, "Integration request has already been decided")
        permission_key = (
            "integrations.tenant_adapter_override.activate_override"
            if body.status == "approved"
            else "integrations.tenant_adapter_override.reject"
        )
        # The bootstrap key is an explicit control-plane provisioning authority.
        # It is not a platform user assignment and therefore cannot be evaluated
        # through the platform RBAC graph. Keep the bypass scoped to this
        # provider-request decision endpoint; authenticated platform users still
        # go through the normal permission and maker-checker evaluation below.
        authorization = (
            Decision(allowed=True, trace=("bootstrap authority",))
            if actor.user_id == "bootstrap"
            else await decide_platform(db, actor.user_id, permission_key)
        )
        if not authorization.allowed or authorization.needs_step_up:
            raise HTTPException(403, "Permission denied")
        runtime_payload = {
            "customization_request_id": request.id,
            "organization_id": request.organization_id,
            "capability": request.capability,
            "provider_name": request.provider_name,
            "status": body.status,
            "reason": body.reason,
        }
        approval = None
        if authorization.needs_approval:
            if body.approval_request_id:
                approval = await authorize_runtime_action(
                    db,
                    request_id=body.approval_request_id,
                    permission_key=permission_key,
                    payload=runtime_payload,
                    maker_id=actor.user_id,
                    request_model=PlatformChangeRequest,
                )
            else:
                approval, created = await create_runtime_action_request(
                    db,
                    permission_key=permission_key,
                    payload=runtime_payload,
                    reason=body.reason,
                    maker_id=actor.user_id,
                    context=await platform_policy_context(db),
                    request_model=PlatformChangeRequest,
                    policy_model=PlatformApprovalPolicy,
                )
                platform_audit(
                    db,
                    actor.user_id,
                    "adapter-request.approval-requested",
                    organization_id=request.organization_id,
                    reason=body.reason,
                    details={"request_id": approval.id, "created": created, "permission_key": permission_key},
                )
                return JSONResponse(
                    status_code=202,
                    content=jsonable_encoder({
                        "status": "approval_required",
                        "request": await request_payload(db, approval, PlatformChangeDecision),
                    }),
                )
        request.status = body.status
        request.decided_by = actor.user_id
        request.decision_reason = body.reason
        request.updated_by = actor.user_id
        if body.status == "approved":
            override = await db.scalar(
                select(TenantAdapterOverride).where(
                    TenantAdapterOverride.organization_id == request.organization_id,
                    TenantAdapterOverride.capability == request.capability,
                )
            )
            if override is None:
                override = TenantAdapterOverride(
                    organization_id=request.organization_id,
                    capability=request.capability,
                    provider_name=request.provider_name,
                    active=True,
                    approved_by=actor.user_id,
                    approval_reason=body.reason,
                    created_by=actor.user_id,
                    updated_by=actor.user_id,
                )
                db.add(override)
            else:
                override.provider_name = request.provider_name
                override.active = True
                override.approved_by = actor.user_id
                override.approval_reason = body.reason
                override.updated_by = actor.user_id
        platform_audit(
            db,
            actor.user_id,
            f"adapter-request.{body.status}",
            organization_id=request.organization_id,
            reason=body.reason,
            details={
                "capability": request.capability,
                "provider_name": request.provider_name,
            },
        )
        await db.flush()
        if approval:
            await complete_runtime_action(
                approval,
                {"resource": "adapter_customization_request", "resource_id": request.id},
            )
        return serialize(request)


# Update configure routing while preserving existing validation and audit behavior.
@router.put("/platform/organizations/{identifier}/routing")
async def configure_routing(
    identifier: str,
    body: RoutingConfiguration,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("routing.tenant_routing_metadata.update", workflow_handles_approval=True)),
):
    async with control_session() as db:
        row = await db.get(Organization, identifier)
        if row is None:
            raise HTTPException(404, "Organization not found")
        conflict = await db.scalar(
            select(Organization).where(Organization.slug == body.slug, Organization.id != identifier)
        )
        if conflict:
            raise HTTPException(409, "Slug is already assigned")
        organizations = (
            await db.scalars(select(Organization).where(Organization.id != identifier))
        ).all()
        assigned = {
            binding["hostname"]
            for organization in organizations
            for binding in organization.domains
        }
        if assigned.intersection(binding["hostname"] for binding in body.domains):
            raise HTTPException(409, "Custom domain is already assigned")
        for key, value in body.model_dump().items():
            setattr(row, key, value)
        row.updated_by = actor.user_id
        platform_audit(db, actor.user_id, "organization.routing", organization_id=row.id)
        return body.model_dump()


# Handle extraction check for this module.
@router.get("/platform/organizations/{identifier}/extraction-preflight")
async def extraction_check(
    identifier: str,
    target_alias: str = Query(min_length=2, max_length=80),
    actor: PlatformActor = Depends(platform_or_bootstrap),
):
    async with control_session() as db:
        organization = await db.get(Organization, identifier)
    if organization is None:
        raise HTTPException(404, "Organization not found")
    try:
        result = await extraction_preflight(organization, target_alias)
        async with control_session() as db:
            platform_audit(
                db, actor.user_id, "organization.extraction-preflight", organization_id=identifier
            )
        return result
    except (RuntimeError, ValueError) as error:
        raise HTTPException(422, str(error)) from None


# Handle database cutover for this module.
@router.put("/platform/organizations/{identifier}/database-alias")
async def database_cutover(
    identifier: str,
    body: DatabaseCutover,
    actor: PlatformActor = Depends(platform_or_bootstrap),
):
    async with control_session() as db:
        organization = await db.get(Organization, identifier)
    if organization is None:
        raise HTTPException(404, "Organization not found")
    try:
        result = await extraction_preflight(organization, body.target_alias)
    except (RuntimeError, ValueError) as error:
        raise HTTPException(422, str(error)) from None
    if not result["ready"]:
        raise HTTPException(409, "Target database has not passed extraction preflight")
    async with control_session() as db:
        row = await db.get(Organization, identifier)
        row.database_alias = body.target_alias
        row.updated_by = actor.user_id
        platform_audit(db, actor.user_id, "organization.database-cutover", organization_id=identifier)
    return {"organization_id": identifier, "database_alias": body.target_alias}


# Handle recover administrator for this module.
@router.post("/platform/organizations/{identifier}/recovery")
async def recover_administrator(
    identifier: str,
    body: RecoveryAction,
    actor: PlatformActor = Depends(platform_recovery_actor),
):
    async with control_session() as db:
        organization = await db.get(Organization, identifier)
    if organization is None:
        raise HTTPException(404, "Organization not found")
    permission_key = {
        "unlock": "support.locked_account_recovery.unlock_account",
        "reset_mfa": "support.mfa_recovery.reset_mfa",
        "password_reset": "support.password_recovery.initiate_password_reset",
    }[body.action]
    runtime_payload = {
        "organization_id": identifier,
        "staff_email": body.staff_email.lower(),
        "action": body.action,
        "reason": body.reason,
    }
    approval = None
    async with control_session() as control_db:
        decision = await decide_platform(control_db, actor.user_id, permission_key)
        if not decision.allowed or decision.needs_step_up:
            raise HTTPException(403, "Permission denied")
        if decision.needs_approval:
            if body.approval_request_id:
                approval = await authorize_runtime_action(
                    control_db,
                    request_id=body.approval_request_id,
                    permission_key=permission_key,
                    payload=runtime_payload,
                    maker_id=actor.user_id,
                    request_model=PlatformChangeRequest,
                )
            else:
                approval, created = await create_runtime_action_request(
                    control_db,
                    permission_key=permission_key,
                    payload=runtime_payload,
                    reason=body.reason,
                    maker_id=actor.user_id,
                    context=await platform_policy_context(control_db),
                    request_model=PlatformChangeRequest,
                    policy_model=PlatformApprovalPolicy,
                )
                platform_audit(
                    control_db,
                    actor.user_id,
                    "organization.admin-recovery.approval-requested",
                    organization_id=identifier,
                    reason=body.reason,
                    details={"request_id": approval.id, "created": created, "permission_key": permission_key},
                )
                return JSONResponse(
                    status_code=202,
                    content=jsonable_encoder({
                        "status": "approval_required",
                        "request": await request_payload(control_db, approval, PlatformChangeDecision),
                    }),
                )
        async with organization_session(organization) as db:
            user = await db.scalar(
                select(StaffUser).where(StaffUser.email == body.staff_email.lower()).with_for_update()
            )
            organization_assignment = (
                await db.scalar(
                    select(StaffLocationAssignment.id).where(
                        StaffLocationAssignment.user_id == user.id if user else None,
                        StaffLocationAssignment.scope == "organization",
                        StaffLocationAssignment.active,
                    )
                )
                if user
                else None
            )
            if user is None or organization_assignment is None:
                raise HTTPException(404, "Organization administrator not found")
            if body.action == "unlock":
                user.active = True
            elif body.action == "reset_mfa":
                user.mfa_enabled = False
                user.mfa_secret = ""
                user.mfa_counter = -1
                await revoke_staff_sessions(db, user, actor_id=actor.user_id)
                user.token_version += 1
            else:
                await issue_password_reset(
                    db,
                    user,
                    initiated_by=actor.user_id,
                    reason=body.reason,
                    clinic_name=organization.name,
                )
                await revoke_staff_sessions(db, user, actor_id=actor.user_id)
                user.token_version += 1
            user.updated_by = actor.user_id
            audit(
                db,
                actor.user_id,
                "platform.recovery",
                "staff",
                user.id,
                reason=body.reason,
                action=body.action,
            )
        if approval:
            await complete_runtime_action(
                approval,
                {"resource": "staff_recovery", "resource_id": runtime_payload["staff_email"]},
            )
        platform_audit(
            control_db,
            actor.user_id,
            "organization.admin-recovery",
            organization_id=identifier,
            reason=body.reason,
            details={"action": body.action, "staff_email": body.staff_email.lower(), "approval_request_id": approval.id if approval else None},
        )
    return {"status": "completed", "action": body.action}


# Handle accept invite for this module.
@router.post("/auth/invites/accept")
async def accept_invite(body: AcceptInvite):
    if not await throttle("invite:" + digest(body.token)):
        raise HTTPException(429, "Try again later")
    org = await organization_from_login(body.organization_id, body.tenant_slug)
    async with organization_session(org) as db:
        invitation = await db.scalar(
            select(StaffInvite).where(StaffInvite.token_hash == digest(body.token)).with_for_update()
        )
        if invitation is None or invitation.used or invitation.expires < int(time.time()):
            raise HTTPException(401, "Invalid invitation")
        if invitation.email.lower() != body.email.lower():
            raise HTTPException(401, "The email does not match this invitation")
        pending_assignments = await invite_assignments(db, invitation)
        user = await add(
            db,
            StaffUser,
            {
                "email": invitation.email,
                "name": invitation.name,
                "role": invitation.role,
                "is_provider": invitation.is_provider,
                "location_ids": invitation.location_ids,
                "password_hash": hash_password(body.password),
            },
            "invitation",
        )
        invitation.used = True
        invitation.status = "accepted"
        invitation.accepted_at = datetime.now(UTC)
        invitation.updated_by = user.id
        now = datetime.now(UTC)
        db.add_all(
            [
                StaffLocationAssignment(
                    user_id=user.id,
                    location_id=item.location_id,
                    scope=item.scope,
                    role=item.role,
                    active=True,
                    assigned_at=now,
                    created_by=user.id,
                    updated_by=user.id,
                )
                for item in pending_assignments
            ]
        )
        await db.flush()
        await seed_tenant_super_admin(db, user.id, sync_legacy=True)
        for item in pending_assignments:
            item.status = "accepted"
            item.updated_by = user.id
        audit(
            db,
            user.id,
            "invite.accept",
            "staff",
            user.id,
            assignments=[
                {"scope": item.scope, "location_id": item.location_id, "role": item.role}
                for item in pending_assignments
            ],
        )
    return {"status": "created", "mfa_enrollment_required": True}


# Handle staff invite for this module.
@router.post("/organization/invites", status_code=201)
async def staff_invite(body: InviteInput, db=Depends(db_session), actor=Depends(permit("settings"))):
    assignments = assignment_inputs(body)
    if actor.assignment_scope != "organization" and any(
        item.scope == "organization" or item.location_id not in actor.location_ids
        for item in assignments
    ):
        raise HTTPException(403, "Cannot grant access outside your assigned location")
    return await invite(db, body, actor.user_id, actor.organization.name, tenant_slug=actor.organization.slug)


# Handle organization access for this module.
@router.get("/organization/access")
async def organization_access(db=Depends(db_session), actor=Depends(permit("settings"))):
    now = int(time.time())
    user_query = select(StaffUser)
    invitation_query = select(StaffInvite)
    if actor.assignment_scope != "organization":
        user_query = user_query.where(
            select(StaffLocationAssignment.id)
            .where(
                StaffLocationAssignment.user_id == StaffUser.id,
                StaffLocationAssignment.active,
                StaffLocationAssignment.location_id.in_(actor.location_ids),
            )
            .exists()
        )
        invitation_query = invitation_query.where(
            select(StaffInviteAssignment.id)
            .where(
                StaffInviteAssignment.invite_id == StaffInvite.id,
                StaffInviteAssignment.location_id.in_(actor.location_ids),
            )
            .exists()
        )
    users = (await db.scalars(user_query.order_by(StaffUser.name))).all()
    invitations = (
        await db.scalars(invitation_query.order_by(StaffInvite.created_at.desc()))
    ).all()
    for invitation in invitations:
        if invitation.status == "pending" and invitation.expires <= now:
            invitation.status = "expired"
            invitation.updated_by = actor.user_id
    staff_items = []
    for row in users:
        assignments = await user_assignments(db, row)
        staff_items.append(
            {
                "id": row.id,
                "name": row.name,
                "email": row.email,
                "role": row.role,
                "is_provider": row.is_provider,
                "location_ids": row.location_ids,
                "assignments": [
                    {
                        "id": item.id,
                        "scope": item.scope,
                        "location_id": item.location_id,
                        "role": item.role,
                    }
                    for item in assignments
                ],
                "mfa_enabled": row.mfa_enabled,
                "active": row.active,
                "suspended_until": row.suspended_until,
                "archived_at": row.archived_at,
                "photo_url": row.photo_url,
                "external_identity": row.external_subject is not None,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
        )
    invitation_items = []
    for row in invitations:
        item = serialize(row)
        item["assignments"] = [
            {
                "id": assignment.id,
                "scope": assignment.scope,
                "location_id": assignment.location_id,
                "role": assignment.role,
            }
            for assignment in await invite_assignments(db, row)
        ]
        invitation_items.append(item)
    return {"staff": staff_items, "invitations": invitation_items}


# Handle organization access roles for this module.
@router.get("/organization/access/roles")
async def organization_access_roles(db=Depends(db_session), actor=Depends(permit("settings"))):
    rows = (
        await db.scalars(
            select(TenantRole)
            .where(TenantRole.status == "published")
            .order_by(TenantRole.name)
        )
    ).all()
    result = []
    for role in rows:
        grants = (
            await db.scalars(
                select(TenantRoleGrant).where(TenantRoleGrant.role_id == role.id)
            )
        ).all()
        scopes = sorted({grant.scope.lower() for grant in grants if grant.effect == "allow"})
        result.append(
            {
                "id": role.id,
                "name": role.name,
                "locked": role.id == "tenant-super-admin",
                "scopes": scopes,
            }
        )
    return result


# Handle organization access query for this module.
@router.get("/organization/access/query")
async def organization_access_query(
    kind: str = Query(pattern="^(staff|invitation)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=10, le=MAX_PAGE_SIZE),
    search: str = Query(default="", max_length=160),
    status: str = Query(default="", max_length=30),
    role: str = Query(default="", max_length=30),
    location_id: str = Query(default="", max_length=36),
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    offset = (page - 1) * page_size
    if kind == "staff":
        query = select(StaffUser)
        if search:
            needle = f"%{search.strip()}%"
            query = query.where(or_(StaffUser.name.ilike(needle), StaffUser.email.ilike(needle)))
        if status == "active":
            query = query.where(StaffUser.active, StaffUser.archived_at.is_(None), or_(StaffUser.suspended_until.is_(None), StaffUser.suspended_until <= datetime.now(UTC)))
        elif status == "inactive":
            query = query.where(StaffUser.active.is_(False), StaffUser.archived_at.is_(None))
        elif status == "suspended":
            query = query.where(StaffUser.active, StaffUser.archived_at.is_(None), StaffUser.suspended_until > datetime.now(UTC))
        elif status == "archived":
            query = query.where(StaffUser.archived_at.is_not(None))
        if role or location_id or actor.assignment_scope != "organization":
            role_row = None
            if role:
                role_row = await db.scalar(
                    select(TenantRole).where(
                        TenantRole.status == "published",
                        or_(
                            TenantRole.id == role,
                            func.lower(TenantRole.name) == role.strip().lower(),
                        ),
                    )
                )
            if role_row is not None:
                assignment_filter = select(TenantRoleAssignment.id).where(
                    TenantRoleAssignment.user_id == StaffUser.id,
                    TenantRoleAssignment.role_id == role_row.id,
                )
                if role_row.id != "tenant-super-admin":
                    super_admin_assignment = select(TenantRoleAssignment.id).where(
                        TenantRoleAssignment.user_id == StaffUser.id,
                        TenantRoleAssignment.role_id == "tenant-super-admin",
                    ).exists()
                    assignment_filter = assignment_filter.where(~super_admin_assignment)
                if actor.assignment_scope != "organization":
                    assignment_filter = assignment_filter.where(
                        TenantRoleAssignment.location_id.in_(actor.location_ids)
                    )
                if location_id:
                    assignment_filter = assignment_filter.where(
                        TenantRoleAssignment.location_id == location_id
                    )
            else:
                assignment_filter = select(StaffLocationAssignment.id).where(
                    StaffLocationAssignment.user_id == StaffUser.id,
                    StaffLocationAssignment.active,
                )
                if actor.assignment_scope != "organization":
                    assignment_filter = assignment_filter.where(
                        StaffLocationAssignment.location_id.in_(actor.location_ids)
                    )
                if role:
                    assignment_filter = assignment_filter.where(StaffLocationAssignment.role == role)
                if location_id:
                    assignment_filter = assignment_filter.where(
                        StaffLocationAssignment.location_id == location_id
                    )
            query = query.where(assignment_filter.exists())
        total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = (
            await db.scalars(
                query.order_by(StaffUser.name, StaffUser.id).offset(offset).limit(page_size)
            )
        ).all()
        items = []
        for row in rows:
            assignments = await user_assignments(db, row)
            items.append(
                {
                    "id": row.id,
                    "name": row.name,
                    "email": row.email,
                    "role": row.role,
                    "is_provider": row.is_provider,
                    "location_ids": row.location_ids,
                    "assignments": [
                        {
                            "id": item.id,
                            "scope": item.scope,
                            "location_id": item.location_id,
                            "role": item.role,
                        }
                        for item in assignments
                    ],
                    "mfa_enabled": row.mfa_enabled,
                    "active": row.active,
                    "suspended_until": row.suspended_until,
                    "archived_at": row.archived_at,
                    "photo_url": row.photo_url,
                    "external_identity": row.external_subject is not None,
                    "created_at": row.created_at,
                    "updated_at": row.updated_at,
                }
            )
    else:
        expired_ids = select(StaffInvite.id).where(
            StaffInvite.status == "pending", StaffInvite.expires <= int(time.time())
        )
        await db.execute(
            update(StaffInvite)
            .where(StaffInvite.id.in_(expired_ids))
            .values(status="expired", updated_by=actor.user_id)
        )
        await db.execute(
            update(StaffInviteAssignment)
            .where(StaffInviteAssignment.invite_id.in_(expired_ids))
            .values(status="expired", updated_by=actor.user_id)
        )
        query = select(StaffInvite)
        if search:
            needle = f"%{search.strip()}%"
            query = query.where(or_(StaffInvite.name.ilike(needle), StaffInvite.email.ilike(needle)))
        if status:
            query = query.where(StaffInvite.status == status)
        if role or location_id or actor.assignment_scope != "organization":
            assignment_filter = select(StaffInviteAssignment.id).where(
                StaffInviteAssignment.invite_id == StaffInvite.id
            )
            if actor.assignment_scope != "organization":
                assignment_filter = assignment_filter.where(
                    StaffInviteAssignment.location_id.in_(actor.location_ids)
                )
            if role:
                assignment_filter = assignment_filter.where(StaffInviteAssignment.role == role)
            if location_id:
                assignment_filter = assignment_filter.where(
                    StaffInviteAssignment.location_id == location_id
                )
            query = query.where(assignment_filter.exists())
        total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = (
            await db.scalars(
                query.order_by(StaffInvite.created_at.desc(), StaffInvite.id)
                .offset(offset)
                .limit(page_size)
            )
        ).all()
        items = []
        now = int(time.time())
        for row in rows:
            if row.status == "pending" and row.expires <= now:
                row.status = "expired"
                row.updated_by = actor.user_id
            item = serialize(row)
            item["assignments"] = [
                {
                    "id": assignment.id,
                    "scope": assignment.scope,
                    "location_id": assignment.location_id,
                    "role": assignment.role,
                }
                for assignment in await invite_assignments(db, row)
            ]
            items.append(item)
    audit(
        db,
        actor.user_id,
        "access.list",
        "staff_access",
        kind=kind,
        page=page,
        page_size=page_size,
        filters={"search": search, "status": status, "role": role, "location_id": location_id},
    )
    return {"page": page, "page_size": page_size, "total": total, "items": items}


# Handle resend invitation for this module.
@router.post("/organization/invites/{identifier}/resend")
async def resend_invitation(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    prior = await required(db, StaffInvite, identifier, lock=True)
    if prior.status not in {"pending", "expired"} or (
        prior.used and prior.status != "expired"
    ):
        raise HTTPException(409, "Only pending or expired invitations can be resent")
    prior.used = True
    prior.status = "revoked" if prior.status == "pending" else "expired"
    prior.revoked_at = datetime.now(UTC) if prior.status == "revoked" else None
    prior.updated_by = actor.user_id
    prior_assignments = await invite_assignments(db, prior)
    for item in prior_assignments:
        item.status = prior.status
        item.updated_by = actor.user_id
    raw = secrets.token_urlsafe(32)
    replacement = await add(
        db,
        StaffInvite,
        {
            "name": prior.name,
            "email": prior.email,
            "role": prior.role,
            "is_provider": prior.is_provider,
            "location_ids": prior.location_ids,
            "token_hash": digest(raw),
            "expires": int(time.time()) + 86400,
            "status": "pending",
            "resend_count": prior.resend_count + 1,
            "supersedes_id": prior.id,
        },
        actor.user_id,
    )
    db.add_all(
        [
            StaffInviteAssignment(
                invite_id=replacement.id,
                email=replacement.email,
                location_id=item.location_id,
                scope=item.scope,
                role=item.role,
                status="pending",
                created_by=actor.user_id,
                updated_by=actor.user_id,
            )
            for item in prior_assignments
        ]
    )
    template = (await tenant_settings(db)).communication_templates["staff-invitation"]
    expires_at = datetime.fromtimestamp(replacement.expires, UTC).strftime("%B %-d, %Y at %-I:%M %p UTC")
    subject, message_body = render_communication_template(
        template,
        {
            "recipient_name": replacement.name,
            "clinic_name": actor.organization.name,
            "role": replacement.role.replace("_", " "),
            "tenant_slug": actor.organization.slug,
            "platform_name": "DHMIS Platform",
            "invitation_expires_at": expires_at,
            "invitation_expires_in": "24 hours",
            "invitation_link": staff_invitation_url(raw, actor.organization.slug),
        },
    )
    await deliver_message_now(db, actor, OutboxMessage(
            kind="staff.invitation",
            payload={
                "destination": replacement.email,
                "subject": subject,
                "body": message_body,
                "user_id": replacement.id,
            },
            idempotency_key=f"staff-invitation:{replacement.id}",
            created_by=actor.user_id,
            updated_by=actor.user_id,
        ))
    audit(db, actor.user_id, "invite.resend", "staff", replacement.id, supersedes_id=prior.id)
    return {"invite_id": replacement.id, "token": raw, "invitation_link": staff_invitation_url(raw, actor.organization.slug), "expires_in": 86400}


# Apply the revoke invitation lifecycle transition and its existing safeguards.
@router.post("/organization/invites/{identifier}/revoke")
async def revoke_invitation(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    invitation = await required(db, StaffInvite, identifier, lock=True)
    if invitation.status != "pending" or invitation.used:
        raise HTTPException(409, "Only pending invitations can be revoked")
    invitation.status = "revoked"
    invitation.used = True
    invitation.revoked_at = datetime.now(UTC)
    invitation.updated_by = actor.user_id
    for item in await invite_assignments(db, invitation):
        item.status = "revoked"
        item.updated_by = actor.user_id
    audit(db, actor.user_id, "invite.revoke", "staff", invitation.id)
    return {"status": "revoked"}


# Defines the staff password reset model, contract, or value object.
class StaffPasswordReset(BaseModel):
    reason: str = Field(min_length=10, max_length=1000)


# Defines the staff suspension model, contract, or value object.
class StaffSuspension(BaseModel):
    hours: int = Field(ge=1, le=8760)


# Internal helper for change staff lifecycle.
async def _change_staff_lifecycle(identifier: str, db, actor, *, active: bool | None = None, suspended_until=None, archived: bool | None = None):
    user = await required(db, StaffUser, identifier, lock=True)
    if user.id == actor.user_id and (active is False or archived is True or suspended_until is not None):
        raise HTTPException(409, "You cannot suspend, disable, or archive your own administrator account")
    if archived is True and user.active:
        raise HTTPException(409, "Disable the staff account before archiving it")
    if archived is False:
        user.archived_at = None
        user.active = True
    elif archived is True:
        user.archived_at = datetime.now(UTC)
        user.active = False
    elif active is not None:
        user.active = active
    if suspended_until is not None:
        user.suspended_until = suspended_until
    elif active is False or archived is not False:
        user.suspended_until = None
    await revoke_staff_sessions(db, user, actor_id=actor.user_id)
    user.token_version += 1
    user.updated_by = actor.user_id
    audit(db, actor.user_id, "staff.lifecycle", "staff", user.id, active=user.active, suspended_until=user.suspended_until, archived=bool(user.archived_at))
    return {"id": user.id, "active": user.active, "suspended_until": user.suspended_until, "archived_at": user.archived_at}


# Handle reset staff password for this module.
@router.post("/organization/staff/{identifier}/password-reset", status_code=202)
async def reset_staff_password(
    identifier: str,
    body: StaffPasswordReset,
    db=Depends(db_session),
    actor=Depends(permit("support_reset")),
):
    user = await required(db, StaffUser, identifier, lock=True)
    await issue_password_reset(
        db,
        user,
        initiated_by=actor.user_id,
        reason=body.reason,
        clinic_name=actor.organization.name,
    )
    await revoke_staff_sessions(db, user, actor_id=actor.user_id)
    user.token_version += 1
    user.updated_by = actor.user_id
    audit(
        db,
        actor.user_id,
        "password-reset.issue",
        "staff",
        user.id,
        reason=body.reason,
    )
    return {"status": "queued"}


# Handle suspend staff for this module.
@router.post("/organization/staff/{identifier}/suspend")
async def suspend_staff(identifier: str, body: StaffSuspension, db=Depends(db_session), actor=Depends(permit("settings"))):
    return await _change_staff_lifecycle(identifier, db, actor, active=True, suspended_until=datetime.now(UTC) + timedelta(hours=body.hours))


# Apply the disable staff lifecycle transition and its existing safeguards.
@router.post("/organization/staff/{identifier}/disable")
async def disable_staff(identifier: str, db=Depends(db_session), actor=Depends(permit("settings"))):
    return await _change_staff_lifecycle(identifier, db, actor, active=False)


# Apply the archive staff lifecycle transition and its existing safeguards.
@router.post("/organization/staff/{identifier}/archive")
async def archive_staff(identifier: str, db=Depends(db_session), actor=Depends(permit("settings"))):
    return await _change_staff_lifecycle(identifier, db, actor, archived=True)


# Handle restore staff for this module.
@router.post("/organization/staff/{identifier}/restore")
async def restore_staff(identifier: str, db=Depends(db_session), actor=Depends(permit("settings"))):
    return await _change_staff_lifecycle(identifier, db, actor, archived=False)


# Retrieve get settings for the current request or workflow.
@router.get("/organization/settings")
async def get_settings(db=Depends(db_session), actor=Depends(permit("settings"))):
    row = await tenant_settings(db)
    return {
        "visibility": row.visibility,
        "branding": row.branding,
        "logo_url": row.logo_url or DEFAULT_LOGO_URL,
        "policy": Policy(**row.policy).model_dump(),
        "effective_adapters": actor.adapter_names,
        "jurisdiction_policy": row.jurisdiction_policy,
        "jurisdiction": jurisdiction(actor.organization.region).defaults(row.jurisdiction_policy),
        "public_content": {
            "contact_phone": "",
            "contact_email": "",
            "address": "",
            **row.public_content,
        },
        "operational_thresholds": row.operational_thresholds,
        "booking_widget": {
            "accent_color": "#356b5d",
            "default_location_id": "",
            "allowed_location_ids": [],
            "allowed_service_ids": [],
            "allowed_provider_ids": [],
            "allowed_origins": [],
            **row.booking_widget,
        },
    }


# Retrieve get provider options for the current request or workflow.
@router.get("/organization/provider-options")
async def get_provider_options(actor=Depends(permit("settings"))):
    return {
        "effective": actor.adapter_names,
        "available": provider_options(include_live=True),
        "managed_by": "platform-control-plane",
    }


# Handle organization integration requests for this module.
@router.get("/organization/integration-requests")
async def organization_integration_requests(actor=Depends(permit("settings"))):
    async with control_session() as db:
        rows = (
            await db.scalars(
                select(AdapterCustomizationRequest)
                .where(AdapterCustomizationRequest.organization_id == actor.organization.id)
                .order_by(AdapterCustomizationRequest.created_at.desc())
                .limit(200)
            )
        ).all()
        return [serialize(row) for row in rows]


# Create or issue request integration customization while applying existing validation and authorization.
@router.post("/organization/integration-requests", status_code=201)
async def request_integration_customization(
    body: AdapterRequestInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    async with control_session() as control:
        duplicate = await control.scalar(
            select(AdapterCustomizationRequest).where(
                AdapterCustomizationRequest.organization_id == actor.organization.id,
                AdapterCustomizationRequest.capability == body.capability,
                AdapterCustomizationRequest.provider_name == body.provider_name,
                AdapterCustomizationRequest.status == "pending",
            )
        )
        if duplicate:
            raise HTTPException(409, "An equivalent integration request is already pending")
        row = AdapterCustomizationRequest(
            organization_id=actor.organization.id,
            **body.model_dump(),
            requested_by=actor.user_id,
            created_by=actor.user_id,
            updated_by=actor.user_id,
        )
        control.add(row)
        await control.flush()
        result = serialize(row)
    audit(
        db,
        actor.user_id,
        "integration.customization-request",
        "organization",
        actor.organization.id,
        capability=body.capability,
        provider_name=body.provider_name,
    )
    return result


# Update set settings while preserving existing validation and audit behavior.
@router.put("/organization/settings")
async def set_settings(body: OrgSettings, db=Depends(db_session), actor=Depends(permit("settings"))):
    if body.booking_widget and body.booking_widget.default_location_id:
        await required(db, Location, body.booking_widget.default_location_id)
    for identifier in body.booking_widget.allowed_location_ids if body.booking_widget else []:
        await required(db, Location, identifier)
    from app.billing.models import Service

    for identifier in body.booking_widget.allowed_service_ids if body.booking_widget else []:
        await required(db, Service, identifier)
    for identifier in body.booking_widget.allowed_provider_ids if body.booking_widget else []:
        provider = await required(db, StaffUser, identifier)
        if (
            not provider.active
            or not provider.is_provider
            or provider.archived_at is not None
            or (provider.suspended_until and provider.suspended_until > datetime.now(UTC))
            or not await user_has_module(db, provider, "clinical")
        ):
            raise HTTPException(422, "Widget providers must be active, explicitly enabled clinical providers")
    await configure_tenant(db, actor_id=actor.user_id, **body.model_dump())
    audit(db, actor.user_id, "configure", "organization", actor.organization.id)
    return body.model_dump()


# Handle communication templates for this module.
@router.get("/organization/communication-templates")
async def communication_templates(
    db=Depends(db_session), actor=Depends(permit("settings"))
):
    return (await tenant_settings(db)).communication_templates


# Update update communication template while preserving existing validation and audit behavior.
@router.put("/organization/communication-templates/{key}")
async def update_communication_template(
    key: str,
    body: CommunicationTemplateInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    if not re.fullmatch(r"[a-z0-9-]{3,80}", key):
        raise HTTPException(422, "Invalid template key")
    runtime = await tenant_settings(db)
    runtime.communication_templates = {
        **runtime.communication_templates,
        key: body.model_dump(),
    }
    runtime.updated_by = actor.user_id
    audit(db, actor.user_id, "template.configure", "communication_templates", key)
    return runtime.communication_templates[key]


# Handle test communication template for this module.
@router.post("/organization/communication-templates/{key}/test", status_code=202)
async def test_communication_template(
    key: str,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    runtime = await tenant_settings(db)
    template = runtime.communication_templates.get(key)
    if template is None:
        raise HTTPException(404, "Communication template not found")
    user = await db.get(StaffUser, actor.user_id)
    replacements = {
        "clinic_name": actor.organization.name,
        "clinic_phone": runtime.public_content.get("contact_phone", "the clinic"),
        "patient_first_name": "Sample",
        "provider_name": actor.name,
        "appointment_date": "October 24",
        "appointment_time": "1:00 PM",
        "installment_amount": "$60.00",
        "due_date": "September 30",
        "plan_balance": "$120.00",
        "recipient_name": actor.name,
        "role": "super admin",
        "tenant_slug": actor.organization.slug,
        "platform_name": "DHMIS Platform",
        "invitation_expires_at": "October 10, 2026 at 10:00 AM UTC",
        "invitation_expires_in": "24 hours",
        "invitation_link": "https://example.invalid/invitation",
        "reset_link": "https://example.invalid/password-reset",
    }
    subject = template.get("subject", "DHMIS template test")
    body = template["body"]
    for variable, value in replacements.items():
        subject = subject.replace("{{" + variable + "}}", value)
        body = body.replace("{{" + variable + "}}", value)
    message = OutboxMessage(
        kind="communication-template.test",
        payload={
            "destination": user.email,
            "subject": "[Test] " + subject,
            "body": body,
            "user_id": user.id,
        },
        idempotency_key=f"template-test:{key}:{secrets.token_hex(12)}",
        created_by=actor.user_id,
        updated_by=actor.user_id,
    )
    db.add(message)
    audit(db, actor.user_id, "template.test", "communication_templates", key)
    return {"status": "queued"}


# Handle staff for this module.
@router.get("/organization/staff")
async def staff(db=Depends(db_session), actor=Depends(permit("settings"))):
    users = (await db.scalars(select(StaffUser))).all()
    return [
        {
            "id": x.id,
            "name": x.name,
            "email": x.email,
            "role": x.role,
            "is_provider": x.is_provider,
            "mfa_enabled": x.mfa_enabled,
            "active": x.active,
            "suspended_until": x.suspended_until,
            "archived_at": x.archived_at,
            "location_ids": x.location_ids,
        }
        for x in users
    ]


# Defines the staff access model, contract, or value object.
class StaffAccess(BaseModel):
    role: str | None = None
    active: bool
    is_provider: bool | None = None
    location_ids: list[str] = Field(default_factory=list)
    assignments: list[AccessAssignmentInput] = Field(default_factory=list)


# Handle staff access for this module.
@router.put("/organization/staff/{identifier}")
async def staff_access(
    identifier: str, body: StaffAccess, db=Depends(db_session), actor=Depends(permit("settings"))
):
    requested = assignment_inputs(body)
    if actor.assignment_scope != "organization" and any(
        item.scope == "organization" or item.location_id not in actor.location_ids
        for item in requested
    ):
        raise HTTPException(403, "Cannot change access outside your assigned location")
    organization_scope_requested = False
    for item in requested:
        if item.scope == "organization":
            organization_scope_requested = True
            break
    if identifier == actor.user_id and (not body.active or not organization_scope_requested):
        raise HTTPException(409, "Cannot remove your own administrator access")
    keys = [(item.scope, item.location_id) for item in requested]
    if len(keys) != len(set(keys)):
        raise HTTPException(422, "Only one effective role is allowed for each access scope")
    for item in requested:
        await validate_assignment_role(db, item)
        if item.location_id:
            await required(db, Location, item.location_id)
    user = await required(db, StaffUser, identifier, lock=True)
    if user.archived_at is not None and body.active:
        raise HTTPException(409, "Restore the archived staff account before enabling it")
    current = await user_assignments(db, user)
    current_by_key = {(item.scope, item.location_id): item for item in current}
    now = datetime.now(UTC)
    changes = []
    for item in requested:
        key = (item.scope, item.location_id)
        assignment = current_by_key.pop(key, None)
        if assignment is None:
            db.add(
                StaffLocationAssignment(
                    user_id=user.id,
                    location_id=item.location_id,
                    scope=item.scope,
                    role=item.role,
                    active=True,
                    assigned_at=now,
                    created_by=actor.user_id,
                    updated_by=actor.user_id,
                )
            )
            changes.append({"scope": item.scope, "location_id": item.location_id, "from": None, "to": item.role})
        elif assignment.role != item.role:
            changes.append(
                {
                    "scope": item.scope,
                    "location_id": item.location_id,
                    "from": assignment.role,
                    "to": item.role,
                }
            )
            assignment.role = item.role
            assignment.assigned_at = now
            assignment.replaced_at = None
            assignment.updated_by = actor.user_id
    for assignment in current_by_key.values():
        assignment.active = False
        assignment.replaced_at = now
        assignment.updated_by = actor.user_id
        changes.append(
            {
                "scope": assignment.scope,
                "location_id": assignment.location_id,
                "from": assignment.role,
                "to": None,
            }
        )
    user.role = requested[0].role
    user.active = body.active
    if body.is_provider is not None:
        user.is_provider = body.is_provider
    user.location_ids = [item.location_id for item in requested if item.location_id]
    user.token_version += 1
    user.updated_by = actor.user_id
    audit(db, actor.user_id, "access.update", "staff", identifier, changes=changes)
    return {"updated": True, "changes": changes}
