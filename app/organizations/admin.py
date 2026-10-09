import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import func, or_, select, update

from app.billing.models import Invoice
from app.core.audit import audit
from app.core.database import control_session, organization_session
from app.core.repository import add, required, serialize
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
from app.identity.service import db_session, default_role_name, permit, user_has_module
from app.integrations.models import (
    AdapterCustomizationRequest,
    PlatformAdapterDefault,
    TenantAdapterOverride,
)
from app.integrations.registry import REGISTRY, provider_options
from app.notifications.models import OutboxMessage
from app.organizations.configuration import (
    configure_tenant,
    platform_configuration,
    render_communication_template,
    tenant_settings,
)
from app.organizations.extraction import extraction_preflight
from app.organizations.jurisdiction import jurisdiction
from app.organizations.models import Location, Organization, PlatformCommercialAccount
from app.organizations.provisioning import activate, provision
from app.organizations.tenant_resolution import (
    normalize_hostname,
    normalize_slug,
    organization_from_login,
)
from app.platform_identity.delivery import enqueue_platform_email
from app.platform_identity.models import (
    PlatformAuditEvent,
    PlatformInvite,
    PlatformOutboxMessage,
    PlatformPasswordResetChallenge,
    PlatformSession,
    PlatformUser,
)
from app.platform_identity.service import PlatformActor, platform_audit, platform_or_bootstrap
from app.rbac.bootstrap import seed_tenant_super_admin
from app.rbac.default_roles import default_role_definitions
from app.rbac.dependencies import permit_platform_or_bootstrap
from app.rbac.policy import Decision
from app.rbac.models import (
    PlatformApprovalPolicy,
    PlatformChangeDecision,
    PlatformChangeRequest,
    PlatformRole,
    PlatformRoleAssignment,
    TenantRole,
    TenantRoleGrant,
)
from app.rbac.runtime import decide_platform, platform_policy_context
from app.rbac.workflow import (
    authorize_runtime_action,
    complete_runtime_action,
    create_runtime_action_request,
    request_payload,
)

router = APIRouter(tags=["Organization administration"])
class Onboarding(BaseModel):
    organization_id: UUID | None = None
    name: str = Field(min_length=2, max_length=160)
    slug: str = Field(min_length=3, max_length=80)
    region: str = Field(default="CA", pattern="^[A-Z]{2}$")
    location_name: str = Field(min_length=2, max_length=160)
    admin_name: str = Field(min_length=2, max_length=160)
    admin_email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    visibility: str = Field(pattern="^(organization|location)$", default="organization")
    branding: dict[str, str] = Field(default_factory=dict)
    domains: list[dict[str, str]] = Field(default_factory=list)
    front_office_enabled: bool = True
    booking_enabled: bool = True
    patient_portal_enabled: bool = True

    @model_validator(mode="after")
    def routing(self):
        self.slug = normalize_slug(self.slug)
        for binding in self.domains:
            if set(binding) != {"hostname", "surface"} or binding["surface"] not in {
                "back-office", "public", "portal"
            }:
                raise ValueError("Each domain requires a hostname and application surface")
            binding["hostname"] = normalize_hostname(binding["hostname"])
        return self


class AccessAssignmentInput(BaseModel):
    role: str
    location_id: str | None = None
    scope: str = Field(default="location", pattern="^(location|organization)$")

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


async def validate_assignment_role(db, assignment: AccessAssignmentInput) -> None:
    scopes = await assignment_role_scopes(db, assignment.role)
    if not scopes:
        raise HTTPException(422, "Unknown role")
    if assignment.scope not in scopes:
        raise HTTPException(422, f"This role does not allow {assignment.scope} scope")


class InviteInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    role: str | None = None
    location_ids: list[str] = Field(default_factory=list)
    assignments: list[AccessAssignmentInput] = Field(default_factory=list)


def assignment_inputs(body) -> list[AccessAssignmentInput]:
    if body.assignments:
        return body.assignments
    if not body.role:
        raise HTTPException(422, "At least one role assignment is required")
    return [
        AccessAssignmentInput(role=body.role, location_id=identifier)
        for identifier in body.location_ids
    ] or [AccessAssignmentInput(role=body.role, scope="organization")]


class AcceptInvite(BaseModel):
    organization_id: str | None = None
    tenant_slug: str | None = None
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=12, max_length=128)


class DatabaseCutover(BaseModel):
    target_alias: str = Field(min_length=2, max_length=80)


class RoutingConfiguration(BaseModel):
    slug: str = Field(min_length=3, max_length=80)
    domains: list[dict[str, str]] = Field(default_factory=list)
    front_office_enabled: bool
    booking_enabled: bool
    patient_portal_enabled: bool

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


class RecoveryAction(BaseModel):
    staff_email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    action: str = Field(pattern="^(unlock|reset_mfa|password_reset)$")
    reason: str = Field(min_length=10, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)


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


class Policy(BaseModel):
    cancellation_notice_hours: int = Field(ge=0, le=168, default=24)
    cancellation_fee_cents: int = Field(ge=0, le=100000, default=0)
    buffer_minutes: int = Field(ge=0, le=120, default=0)
    reminder_hours: int = Field(ge=1, le=168, default=24)


class PublicContent(BaseModel):
    contact_phone: str = Field(default="", max_length=40)
    contact_email: str = Field(default="", max_length=254)
    address: str = Field(default="", max_length=500)


class BookingWidgetConfiguration(BaseModel):
    accent_color: str = Field(default="#356b5d", pattern=r"^#[0-9a-fA-F]{6}$")
    default_location_id: str = Field(default="", max_length=36)
    allowed_location_ids: list[str] = Field(default_factory=list)
    allowed_service_ids: list[str] = Field(default_factory=list)
    allowed_provider_ids: list[str] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list, max_length=20)

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


class OrgSettings(BaseModel):
    visibility: str = Field(pattern="^(organization|location)$")
    branding: dict[str, str] = Field(default_factory=dict)
    policy: Policy
    jurisdiction_policy: dict = Field(default_factory=dict)
    public_content: PublicContent | None = None
    booking_widget: BookingWidgetConfiguration | None = None

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


class AdapterRequestInput(BaseModel):
    capability: str = Field(min_length=2, max_length=80)
    provider_name: str = Field(min_length=2, max_length=120)
    reason: str = Field(min_length=10, max_length=1000)

    @model_validator(mode="after")
    def known_provider(self):
        if self.provider_name not in REGISTRY.get(self.capability, {}):
            raise ValueError("Unknown adapter provider")
        return self


class AdapterDecision(BaseModel):
    status: str = Field(pattern="^(approved|rejected)$")
    reason: str = Field(min_length=10, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)


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


class AdapterDefaultInput(BaseModel):
    region: str = Field(pattern=r"^(\*|[A-Z]{2})$")
    capability: str = Field(min_length=2, max_length=80)
    provider_name: str = Field(min_length=2, max_length=120)
    active: bool = True
    reason: str = Field(min_length=8, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)

    @model_validator(mode="after")
    def known_provider(self):
        if self.provider_name not in REGISTRY.get(self.capability, {}):
            raise ValueError("Unknown adapter provider")
        return self


class CommunicationTemplateInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    channel: str = Field(pattern="^(email|sms)$")
    subject: str = Field(default="", max_length=240)
    body: str = Field(min_length=2, max_length=4000)
    active: bool = True

    @model_validator(mode="after")
    def supported_variables(self):
        allowed = {
            "clinic_name",
            "clinic_phone",
            "patient_first_name",
            "provider_name",
            "appointment_date",
            "appointment_time",
            "installment_amount",
            "due_date",
            "plan_balance",
            "recipient_name",
            "invitation_link",
            "reset_link",
        }
        variables = set(re.findall(r"\{\{([a-z_]+)\}\}", self.subject + self.body))
        if variables - allowed:
            raise ValueError("Template contains an unsupported variable")
        return self


class PlatformDefaultsInput(BaseModel):
    default_visibility: str = Field(pattern="^(organization|location)$")
    default_policy: Policy


class PlatformInviteInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    role: str = Field(default="platform_admin", pattern=r"^platform_admin$")


class PlatformUserStatusInput(BaseModel):
    active: bool


class PlatformPasswordResetInput(BaseModel):
    reason: str = Field(min_length=10, max_length=1000)


async def invite(db, body, actor, clinic_name="your clinic"):
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
    subject, message_body = render_communication_template(
        template,
        {
            "recipient_name": record.name,
            "clinic_name": clinic_name,
            "invitation_link": raw,
        },
    )
    db.add(
        OutboxMessage(
            kind="staff.invitation",
            payload={
                "destination": record.email,
                "subject": subject,
                "body": message_body,
                "user_id": record.id,
            },
            idempotency_key=f"staff-invitation:{record.id}",
            created_by=actor,
            updated_by=actor,
        )
    )
    audit(
        db,
        actor,
        "invite",
        "staff",
        record.id,
        assignments=[item.model_dump() for item in assignments],
    )
    return {"invite_id": record.id, "token": raw, "expires_in": 86400}


@router.post("/platform/organizations", status_code=201)
async def onboarding(
    body: Onboarding,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("organizations.tenant_onboarding.provision")),
):
    # Validate branding through the same settings contract used after onboarding.
    OrgSettings(visibility=body.visibility, branding=body.branding, policy=Policy())
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
        location = await db.scalar(select(Location).order_by(Location.created_at))
        if location is None:
            location = await add(db, Location, {"name": body.location_name}, "platform")
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


@router.get("/platform/organizations/query")
async def platform_organizations_query(
    search: str | None = Query(default=None, max_length=160),
    status: str | None = Query(default=None, max_length=30),
    plan: str | None = Query(default=None, max_length=80),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=10, le=100),
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


@router.get("/platform/audit/query")
async def platform_audit_query(
    search: str | None = Query(default=None, max_length=160),
    action: str | None = Query(default=None, max_length=100),
    organization_id: str | None = Query(default=None, max_length=36),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=10, le=100),
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


@router.get("/platform/financial-operations/query")
async def platform_financial_operations(
    search: str | None = Query(default=None, max_length=160),
    status: str | None = Query(default=None, max_length=30),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=10, le=100),
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
                locations = await tenant_db.scalar(select(func.count()).select_from(Location)) or 0
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


@router.get("/platform/settings/defaults")
async def get_platform_defaults(actor: PlatformActor = Depends(platform_or_bootstrap)):
    async with control_session() as db:
        row = await platform_configuration(db)
        platform_audit(db, actor.user_id, "platform-defaults.read")
        return {
            "default_visibility": row.default_visibility,
            "default_policy": Policy(**row.default_policy).model_dump(),
        }


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


@router.get("/platform/communication-templates")
async def platform_communication_templates(
    actor: PlatformActor = Depends(platform_or_bootstrap),
):
    async with control_session() as db:
        row = await platform_configuration(db)
        platform_audit(db, actor.user_id, "platform-template.list")
        return row.communication_templates


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


@router.get("/platform/access/query")
async def platform_access_query(
    search: str | None = Query(default=None, max_length=160),
    status: str | None = Query(default=None, pattern="^(active|disabled|pending|expired|revoked)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=10, le=100),
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
                "role": row.role,
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
                "role": row.role,
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
        items.sort(key=lambda item: item["created_at"], reverse=True)
        total = len(items)
        start = (page - 1) * page_size
        platform_audit(db, actor.user_id, "platform-access.query")
        return {"page": page, "page_size": page_size, "total": total, "items": items[start:start + page_size]}


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
            detail = payload.get("subject") or payload.get("title") or (
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


@router.post("/platform/invites", status_code=201)
async def create_platform_invite(
    body: PlatformInviteInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("access.platform_user.create")),
):
    raw = secrets.token_urlsafe(32)
    async with control_session() as db:
        if await db.scalar(select(PlatformUser).where(PlatformUser.email == body.email.lower())):
            raise HTTPException(409, "Platform user already exists")
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
            role=body.role,
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
        )
        platform_audit(db, actor.user_id, "platform-invite.create", details={"invite_id": row.id})
        return {
            "invite_id": row.id,
            "delivery_id": delivery.id,
            "delivery_status": delivery.status,
            "expires": row.expires,
        }


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
        )
        platform_audit(db, actor.user_id, "platform-invite.resend", details={"invite_id": replacement.id})
        return {
            "invite_id": replacement.id,
            "delivery_id": delivery.id,
            "delivery_status": delivery.status,
            "expires": replacement.expires,
        }


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
        pending_assignments = await invite_assignments(db, invitation)
        user = await add(
            db,
            StaffUser,
            {
                "email": invitation.email,
                "name": invitation.name,
                "role": invitation.role,
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


@router.post("/organization/invites", status_code=201)
async def staff_invite(body: InviteInput, db=Depends(db_session), actor=Depends(permit("settings"))):
    assignments = assignment_inputs(body)
    if actor.assignment_scope != "organization" and any(
        item.scope == "organization" or item.location_id not in actor.location_ids
        for item in assignments
    ):
        raise HTTPException(403, "Cannot grant access outside your assigned location")
    return await invite(db, body, actor.user_id, actor.organization.name)


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
                "locked": role.locked,
                "scopes": scopes,
            }
        )
    return result


@router.get("/organization/access/query")
async def organization_access_query(
    kind: str = Query(pattern="^(staff|invitation)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=10, le=100),
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
            query = query.where(StaffUser.active)
        elif status == "inactive":
            query = query.where(StaffUser.active.is_(False))
        if role or location_id or actor.assignment_scope != "organization":
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
    subject, message_body = render_communication_template(
        template,
        {
            "recipient_name": replacement.name,
            "clinic_name": actor.organization.name,
            "invitation_link": raw,
        },
    )
    db.add(
        OutboxMessage(
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
        )
    )
    audit(db, actor.user_id, "invite.resend", "staff", replacement.id, supersedes_id=prior.id)
    return {"invite_id": replacement.id, "token": raw, "expires_in": 86400}


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


class StaffPasswordReset(BaseModel):
    reason: str = Field(min_length=10, max_length=1000)


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


@router.get("/organization/settings")
async def get_settings(db=Depends(db_session), actor=Depends(permit("settings"))):
    row = await tenant_settings(db)
    return {
        "visibility": row.visibility,
        "branding": row.branding,
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


@router.get("/organization/provider-options")
async def get_provider_options(actor=Depends(permit("settings"))):
    return {
        "effective": actor.adapter_names,
        "available": provider_options(include_live=True),
        "managed_by": "platform-control-plane",
    }


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
        if not provider.active or not await user_has_module(db, provider, "clinical"):
            raise HTTPException(422, "Widget providers must be active clinical providers")
    await configure_tenant(db, actor_id=actor.user_id, **body.model_dump())
    audit(db, actor.user_id, "configure", "organization", actor.organization.id)
    return body.model_dump()


@router.get("/organization/communication-templates")
async def communication_templates(
    db=Depends(db_session), actor=Depends(permit("settings"))
):
    return (await tenant_settings(db)).communication_templates


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


@router.get("/organization/staff")
async def staff(db=Depends(db_session), actor=Depends(permit("settings"))):
    users = (await db.scalars(select(StaffUser))).all()
    return [
        {
            "id": x.id,
            "name": x.name,
            "email": x.email,
            "role": x.role,
            "mfa_enabled": x.mfa_enabled,
            "active": x.active,
            "location_ids": x.location_ids,
        }
        for x in users
    ]


class StaffAccess(BaseModel):
    role: str | None = None
    active: bool
    location_ids: list[str] = Field(default_factory=list)
    assignments: list[AccessAssignmentInput] = Field(default_factory=list)


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
    user.location_ids = [item.location_id for item in requested if item.location_id]
    user.token_version += 1
    user.updated_by = actor.user_id
    audit(db, actor.user_id, "access.update", "staff", identifier, changes=changes)
    return {"updated": True, "changes": changes}
