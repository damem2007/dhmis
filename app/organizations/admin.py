import hashlib
import json
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import quote
from uuid import UUID, uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy import delete, func, or_, select, update

from app.billing.models import Invoice
from app.core.audit import audit
from app.core.config import settings
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
from app.identity.password_policy import PasswordPolicy, validate_password
from app.identity.passwords import hash_password
from app.identity.recovery import issue_password_reset, revoke_staff_sessions
from app.identity.router import throttle
from app.identity.security import digest
from app.identity.service import (
    Actor,
    db_session,
    organization_role_names,
    permit,
    user_has_module,
)
from app.integrations.configuration import attach_effective_adapters
from app.integrations.contracts import IntegrationFailure, PlatformPaymentRequest
from app.integrations.models import (
    AdapterCustomizationRequest,
    PlatformAdapterDefault,
    TenantAdapterOverride,
)
from app.integrations.registry import REGISTRY, provider_options, resolve_registered
from app.notifications.models import OutboxMessage
from app.notifications.service import deliver_message_now
from app.organizations.configuration import (
    DEFAULT_LOGO_URL,
    communication_template_deliveries,
    configure_tenant,
    platform_configuration,
    render_communication_template,
    tenant_settings,
)
from app.organizations.entitlements import require_location_capacity, resolve_entitlements
from app.organizations.extraction import extraction_preflight
from app.organizations.jurisdiction import jurisdiction
from app.organizations.models import (
    Location,
    Organization,
    OrganizationDomainEvent,
    OrganizationDomainHost,
    OrganizationDomainRequest,
    OrganizationDomainVerification,
    PlatformAddonProduct,
    PlatformCommercialAccount,
    PlatformCommercialLedgerEntry,
    PlatformFeature,
    PlatformPlan,
    PlatformPlanCombination,
    PlatformPlanFeature,
    PlatformSubscription,
    PlatformTenantAddon,
)
from app.organizations.provisioning import (
    activate,
    migrate_all,
    provision,
    rollback_provisioned_organization,
)
from app.organizations.recipient_timezones import format_recipient_datetime, recipient_timezone
from app.organizations.schemas import (
    AcceptInvite,
    AccessAssignmentInput,
    AdapterDecision,
    AdapterDefaultInput,
    AdapterRequestInput,
    AppointmentWidgetAddonInput,
    BookingWidgetConfiguration,
    BookingWidgetDecisionInput,
    BookingWidgetOriginInput,
    CommercialRefundInput,
    CommunicationTemplateInput,
    DatabaseCutover,
    DomainRequestDecisionInput,
    DomainVerificationInput,
    InviteInput,
    Onboarding,
    OrgSettings,
    PlanCombinationInput,
    PlanEntitlementInput,
    PlatformAddonProductInput,
    PlatformDefaultsInput,
    PlatformFeatureInput,
    PlatformInviteInput,
    PlatformLocationInput,
    PlatformPasswordResetInput,
    PlatformPlanInput,
    PlatformSupportTicketInput,
    PlatformSupportTicketUpdate,
    PlatformUserStatusInput,
    Policy,
    ProductionActivationInput,
    PublicPaymentMethodInput,
    PublicPlatformSignup,
    RecoveryAction,
    RoutingConfiguration,
    StaffAccess,
    StaffPasswordReset,
    StaffSuspension,
    SubscriptionInput,
    TenantActivationInput,
    TenantInvitationResetAction,
    normalize_widget_origin,
)
from app.organizations.tenant_resolution import (
    normalize_hostname,
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
from app.rbac.bootstrap import (
    PLATFORM_SUPER_ADMIN_ROLE_ID,
    TENANT_SUPER_ADMIN_ROLE_ID,
    seed_tenant_super_admin,
)
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
from app.rbac.runtime import decide_platform, decide_tenant, platform_policy_context
from app.rbac.workflow import (
    authorize_runtime_action,
    complete_runtime_action,
    create_runtime_action_request,
    request_payload,
)

router = APIRouter(tags=["Organization administration"])


# Restrict schema migration execution to the bootstrap authority or the
# canonical Platform Super Admin role. Migrations are infrastructure actions
# and are intentionally outside the ordinary permission registry.
async def platform_migration_actor(
    actor: PlatformActor = Depends(platform_or_bootstrap),
) -> PlatformActor:
    """Authorize the control-plane endpoint that migrates onboarded tenants."""

    if not actor.is_bootstrap_operator and actor.role_id != PLATFORM_SUPER_ADMIN_ROLE_ID:
        raise HTTPException(403, "Platform Super Admin access is required")
    return actor

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


async def platform_tenant_invitation_reset_actor(
    request: Request,
    actor: PlatformActor = Depends(platform_or_bootstrap),
):
    """Authorize a Platform Admin to reset a tenant administrator invitation.

    The reset is a recovery operation and deliberately uses the existing
    password-recovery permission and runtime approval policy. Tenant schema
    access is selected by the organization resolved in the route handler.
    """

    return await permit_platform_or_bootstrap(
        "support.password_recovery.initiate_password_reset",
        workflow_handles_approval=True,
    )(request, actor)




def _widget_request_record(config: dict | None) -> dict:
    """Return the persisted purchase/domain approval state."""
    values = config or {}
    request = values.get("approval_request")
    return request if isinstance(request, dict) else {
        "status": "approved" if values.get("origin_verifications") or values.get("allowed_origins") else "not_requested",
        "origin": "",
        "requested_at": None,
        "approved_at": None,
        "approved_by": None,
        "rejection_reason": "",
        "request_type": "initial",
        "previous_origin": None,
    }


async def _commercial_summary(db, organization_id: str, legacy_plan: str = "") -> dict:
    """Return the plan/subscription that currently governs a tenant.

    ``Organization.plan`` predates the commercial subscription tables and is
    retained for compatibility.  Platform surfaces must prefer the current
    subscription (and its plan catalogue row) whenever one exists.
    """
    row = (
        await db.execute(
            select(PlatformCommercialAccount, PlatformSubscription, PlatformPlan)
            .outerjoin(
                PlatformSubscription,
                PlatformSubscription.organization_id == PlatformCommercialAccount.organization_id,
            )
            .outerjoin(PlatformPlan, PlatformPlan.id == PlatformSubscription.plan_id)
            .where(PlatformCommercialAccount.organization_id == organization_id)
        )
    ).first()
    account, subscription, plan = row if row else (None, None, None)
    plan_code = (plan.code if plan else None) or (account.plan_code if account else None) or legacy_plan
    metadata = dict(account.commercial_metadata or {}) if account else {}
    trial = metadata.get("self_onboarding") if isinstance(metadata.get("self_onboarding"), dict) else None
    return {
        "plan_code": plan_code or "",
        "plan_name": plan.name if plan else "",
        "subscription_status": (subscription.status if subscription else None) or (account.subscription_status if account else "not_configured"),
        "account_status": account.account_status if account else "not_configured",
        "self_onboarding": trial,
    }


async def _organization_list_payloads(db, rows: list[Organization]) -> list[dict]:
    """Serialize organization list rows without one query per organization.

    The list endpoints are loaded immediately after provisioning.  Resolving a
    commercial summary and entitlement in a separate session for every tenant
    made that refresh grow linearly with the tenant catalogue and could exceed
    the reverse-proxy timeout after the tenant had already been committed.
    Keep the response contract, but obtain the commercial and widget facts in
    three bounded control-plane queries.
    """
    if not rows:
        return []
    organization_ids = [row.id for row in rows]
    commercial_rows = (
        await db.execute(
            select(PlatformCommercialAccount, PlatformSubscription, PlatformPlan)
            .outerjoin(
                PlatformSubscription,
                PlatformSubscription.organization_id == PlatformCommercialAccount.organization_id,
            )
            .outerjoin(PlatformPlan, PlatformPlan.id == PlatformSubscription.plan_id)
            .where(PlatformCommercialAccount.organization_id.in_(organization_ids))
        )
    ).all()
    commercial_by_organization = {
        account.organization_id: (account, subscription, plan)
        for account, subscription, plan in commercial_rows
    }
    subscribed_widget_organizations = set(
        (
            await db.scalars(
                select(PlatformSubscription.organization_id)
                .join(PlatformPlan, PlatformPlan.id == PlatformSubscription.plan_id)
                .join(PlatformPlanFeature, PlatformPlanFeature.plan_id == PlatformPlan.id)
                .join(PlatformFeature, PlatformFeature.id == PlatformPlanFeature.feature_id)
                .where(
                    PlatformSubscription.organization_id.in_(organization_ids),
                    PlatformSubscription.status.in_(("trialing", "active", "past_due")),
                    PlatformPlan.active,
                    PlatformPlanFeature.enabled,
                    PlatformFeature.active,
                    PlatformFeature.key == "module.appointment_widget",
                )
            )
        ).all()
    )
    addon_widget_organizations = set(
        (
            await db.scalars(
                select(PlatformTenantAddon.organization_id)
                .join(PlatformFeature, PlatformFeature.id == PlatformTenantAddon.feature_id)
                .where(
                    PlatformTenantAddon.organization_id.in_(organization_ids),
                    PlatformTenantAddon.status == "active",
                    PlatformFeature.active,
                    PlatformFeature.key == "module.appointment_widget",
                )
            )
        ).all()
    )
    widget_entitled = subscribed_widget_organizations | addon_widget_organizations
    payloads = []
    for row in rows:
        account, subscription, plan = commercial_by_organization.get(row.id, (None, None, None))
        metadata = dict(account.commercial_metadata or {}) if account else {}
        commercial = None
        if account is not None:
            commercial = {
                "account_status": account.account_status,
                "plan_code": (plan.code if plan else None) or account.plan_code or row.plan,
                "plan_name": plan.name if plan else "",
                "subscription_status": (subscription.status if subscription else None) or account.subscription_status,
                "self_onboarding": metadata.get("self_onboarding") if isinstance(metadata.get("self_onboarding"), dict) else None,
            }
        payloads.append(
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
                "widget_entitled": row.id in widget_entitled,
                "last_error": row.last_error,
                "commercial": commercial if commercial and commercial["account_status"] != "not_configured" else None,
            }
        )
    return payloads


def _widget_origin_record(origin: str) -> dict:
    # Origin approval is intentionally a soft, platform-owned verification.
    # DNS/HTTP proof is not required for the widget entitlement; the approved
    # origin is bound to the widget when the platform operator accepts it.
    return {
        "origin": origin,
        "dns_name": "",
        "token": "",
        "verification_method": "admin",
        "verified_at": None,
        "verified_by": None,
    }



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



# Handle staff invitation url for this module.
def staff_invitation_url(raw_token: str, tenant_slug: str) -> str:
    from app.core.config import settings
    base = settings().tenant_admin_public_url_template.format(tenant_slug=tenant_slug).rstrip("/")
    return f"{base}/?invite={quote(raw_token, safe='')}"


def invitation_expiry(policy: dict | None) -> tuple[int, str]:
    """Return the configured invitation lifetime in seconds and display form."""

    hours = Policy(**(policy or {})).invitation_expiry_hours
    return hours * 3600, f"{hours} hour" if hours == 1 else f"{hours} hours"


# Handle invite for this module.
async def invite(
    db,
    body,
    actor,
    clinic_name="your clinic",
    *,
    delivery_actor=None,
    tenant_slug="",
    deliver_immediately=True,
):
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
    runtime = await tenant_settings(db)
    expires_in, expires_label = invitation_expiry(runtime.policy)
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
            "expires": now + expires_in,
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
    template = runtime.communication_templates["staff-invitation"]
    expires_at = format_recipient_datetime(record.expires, await recipient_timezone(db, record))
    email_template = next((content for channel, content in communication_template_deliveries(template) if channel == "email"), None)
    if email_template is None:
        raise HTTPException(422, "Staff invitation requires an active email template")
    subject, message_body = render_communication_template(
        email_template,
        {
            "recipient_name": record.name,
            "clinic_name": clinic_name,
            "role": compatibility_role.replace("_", " "),
            "tenant_slug": tenant_slug,
            "platform_name": "DHMIS Platform",
            "invitation_expires_at": expires_at,
            "invitation_expires_in": expires_label,
            "invitation_link": staff_invitation_url(raw, tenant_slug),
        },
    )
    message = OutboxMessage(
        kind="staff.invitation",
        payload={
            "destination": record.email,
            "subject": subject,
            "body": message_body,
            "channel": "email",
            "user_id": record.id,
        },
        idempotency_key=f"staff-invitation:{record.id}",
        created_by=actor,
        updated_by=actor,
    )
    if deliver_immediately:
        await deliver_message_now(db, delivery_actor or actor, message)
    else:
        db.add(message)
    audit(
        db,
        actor,
        "invite",
        "staff",
        record.id,
        assignments=[item.model_dump() for item in assignments],
    )
    return {"invite_id": record.id, "token": raw, "invitation_link": staff_invitation_url(raw, tenant_slug), "expires_in": expires_in}


# Handle onboarding for this module.
@router.post("/platform/migrations/tenants")
async def migrate_onboarded_tenants(
    actor: PlatformActor = Depends(platform_migration_actor),
):
    """Upgrade control, template, and every existing onboarded tenant schema."""

    results = await migrate_all()
    failed = [result for result in results if not result["migrated"]]
    async with control_session() as db:
        platform_audit(
            db,
            actor.user_id,
            "platform.migrations.tenants",
            details={
                "tenant_count": len(results),
                "failed_count": len(failed),
                "results": results,
            },
        )
    payload = {
        "success": not failed,
        "tenant_count": len(results),
        "migrated_count": len(results) - len(failed),
        "failed_count": len(failed),
        "results": results,
    }
    if failed:
        return JSONResponse(status_code=207, content=payload)
    return payload


# Return only enabled, active entitlements for a selected onboarding plan.
async def _onboarding_plan_entitlements(db, plan: PlatformPlan) -> set[str]:
    return set(
        (
            await db.scalars(
                select(PlatformFeature.key)
                .join(PlatformPlanFeature, PlatformPlanFeature.feature_id == PlatformFeature.id)
                .where(
                    PlatformPlanFeature.plan_id == plan.id,
                    PlatformPlanFeature.enabled,
                    PlatformFeature.active,
                )
            )
        ).all()
    )


async def _effective_onboarding_entitlements(
    db,
    body: Onboarding,
    plan: PlatformPlan,
) -> tuple[set[str], PlatformPlanCombination | None]:
    """Resolve the only feature bundle onboarding is permitted to provision.

    Plans are authored and preflight-validated in Billing -> Plans.  Onboarding
    consumes that commercial product; it does not create or freely edit a plan.
    """
    if plan.configuration_status != "validated":
        raise HTTPException(422, "The selected plan has not passed configuration preflight")
    entitled = await _onboarding_plan_entitlements(db, plan)
    if plan.configuration_mode == "fixed":
        if body.selected_combination_code:
            raise HTTPException(422, "This fixed plan does not offer selectable combinations")
        return entitled, None
    combination = await db.scalar(
        select(PlatformPlanCombination).where(
            PlatformPlanCombination.plan_id == plan.id,
            PlatformPlanCombination.code == body.selected_combination_code,
            PlatformPlanCombination.active,
        )
    )
    if combination is None:
        raise HTTPException(422, "Select a reviewed combination for this curated plan")
    selected = set(combination.feature_keys or [])
    if not selected.issubset(entitled):
        # This should be impossible after plan preflight.  Do not provision a
        # corrupted curated contract if catalogue data changes out of band.
        raise HTTPException(422, "The selected combination no longer matches the validated plan")
    return selected, combination


def _managed_domain_bundle(slug: str, patient_facing: bool) -> tuple[str | None, str]:
    return (f"{slug}.dhmis.test" if patient_facing else None, f"admin.{slug}.dhmis.test")


def _custom_backoffice_hostname(public_hostname: str) -> str:
    """Derive admin.customer-domain.com from www.customer-domain.com."""
    hostname = normalize_hostname(public_hostname)
    root = hostname[4:] if hostname.startswith("www.") else hostname
    return f"admin.{root}"


async def _create_domain_request(
    db,
    *,
    organization: Organization,
    mode: Literal["managed", "custom"],
    patient_facing: bool,
    custom_hostname: str | None,
    actor_id: str,
) -> OrganizationDomainRequest:
    """Persist the domain bundle and its initial verification state.

    A custom request never makes Platform Admin the owner-verifier. The tenant
    administrator receives instructions and completes an automated DNS/HTTP
    proof; platform staff can only monitor, resend, cancel, or suspend.
    """
    managed_public, managed_admin = _managed_domain_bundle(organization.slug, patient_facing)
    public_hostname = managed_public if mode == "managed" else custom_hostname
    backoffice_hostname = managed_admin if mode == "managed" else _custom_backoffice_hostname(str(custom_hostname))
    status = "active" if mode == "managed" else "pending_verification"
    request = OrganizationDomainRequest(
        organization_id=organization.id,
        mode=mode,
        status=status,
        public_hostname=public_hostname,
        backoffice_hostname=backoffice_hostname,
        canonical=mode == "managed",
        activation_at=datetime.now(UTC) if mode == "managed" else None,
        request_metadata={"patient_facing": patient_facing, "managed_backoffice": managed_admin},
        created_by=actor_id,
        updated_by=actor_id,
    )
    db.add(request)
    await db.flush()
    # A custom request has a derived Back Office host, but it cannot route until
    # ownership, DNS, routing and TLS have all become ready. The managed Back
    # Office hostname is a separate, platform-owned fallback. It is available
    # while customer verification is pending and becomes a redirect alias after
    # activation.
    hosts = [
        (public_hostname, "public", mode == "managed"),
        (backoffice_hostname, "back_office", mode == "managed"),
    ]
    if mode == "custom":
        hosts.append((managed_admin, "managed_back_office", True))
    for hostname, role, ready in hosts:
        if not hostname:
            continue
        db.add(OrganizationDomainHost(
            request_id=request.id,
            organization_id=organization.id,
            hostname=hostname,
            role=role,
            routing_status="active" if ready else "pending",
            tls_status="ready" if ready else "pending",
            canonical=mode == "managed" and role != "managed_back_office",
            created_by=actor_id,
            updated_by=actor_id,
        ))
    if mode == "custom":
        token = secrets.token_urlsafe(32)
        db.add(OrganizationDomainVerification(
            request_id=request.id,
            method="dns",
            token=token,
            dns_name=f"_dhmis-verify.{custom_hostname}",
            http_path=f"/.well-known/dhmis-domain-verification/{token}",
            ownership_status="pending",
            dns_status="pending",
            tls_status="pending",
            verification_metadata={"expected_value": token},
            created_by=actor_id,
            updated_by=actor_id,
        ))
    db.add(OrganizationDomainEvent(
        request_id=request.id,
        event_type="requested" if mode == "custom" else "managed_activated",
        details={"mode": mode, "public_hostname": public_hostname, "backoffice_hostname": backoffice_hostname},
        created_by=actor_id,
        updated_by=actor_id,
    ))
    return request


# Enforce plan-governed onboarding options independently of the browser UI.
def _validate_onboarding_plan_options(
    body: Onboarding,
    selected_plan: PlatformPlan | None,
    entitlements: set[str],
) -> None:
    patient_facing = bool({"experience.tenant_website", "module.patient_portal"} & entitlements)
    if getattr(body, "domain_mode", "managed") == "custom" and not patient_facing:
        raise HTTPException(
            422,
            "A custom domain is available only when the selected plan includes Tenant Website or Patient Portal.",
        )
    # Legacy API callers did send client-chosen booleans. Keep those explicit
    # validation errors for compatibility; the current Onboarding model has a
    # domain_mode and derives the values from a reviewed plan bundle instead.
    if not hasattr(body, "domain_mode"):
        checks = (
            ("front_office_enabled", "experience.tenant_website", "Tenant Website"),
            ("booking_enabled", "capability.appointment_booking", "Online Appointment Booking"),
            ("patient_portal_enabled", "module.patient_portal", "Patient Portal"),
        )
        for field, feature, label in checks:
            if getattr(body, field, False) and selected_plan is not None and feature not in entitlements:
                raise HTTPException(422, {"code": "PLAN_ENTITLEMENT_REQUIRED", "message": f"The selected plan does not include {label}.", "feature": feature})
    if not body.booking_widget_origin:
        return
    if selected_plan is None:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "PLAN_REQUIRED",
                "message": "Select a plan before requesting Appointment Widget approval.",
                "feature": "module.appointment_widget",
            },
        )
    if "module.appointment_widget" not in entitlements:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "PLAN_ENTITLEMENT_REQUIRED",
                "message": "The selected plan does not include Appointment Widget.",
                "feature": "module.appointment_widget",
            },
        )
    if not getattr(body, "booking_enabled", False) and (
        not hasattr(body, "domain_mode") or "capability.appointment_booking" not in entitlements
    ):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "APPOINTMENT_BOOKING_REQUIRED",
                "message": "Appointment Widget requires Online Appointment Booking to be enabled.",
                "feature": "capability.appointment_booking",
            },
        )


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
        selected_plan = await db.scalar(
            select(PlatformPlan).where(
                PlatformPlan.code == body.plan_code,
                PlatformPlan.active,
                PlatformPlan.configuration_status == "validated",
            )
        )
        if selected_plan is None:
            raise HTTPException(422, "Selected plan is unavailable")
        selected_entitlements, selected_combination = await _effective_onboarding_entitlements(
            db, body, selected_plan
        )
        _validate_onboarding_plan_options(body, selected_plan, selected_entitlements)
        effective_front_office = "experience.tenant_website" in selected_entitlements
        # Widget self-booking needs the scheduling capability.  A plan
        # including Widget has passed preflight only if it includes it.
        effective_booking = "capability.appointment_booking" in selected_entitlements
        effective_portal = "module.patient_portal" in selected_entitlements
        patient_facing = effective_front_office or effective_portal
        organizations = (await db.scalars(select(Organization))).all()
        assigned = {
            binding["hostname"]
            for organization in organizations
            for binding in organization.domains
        }
        if assigned.intersection(binding["hostname"] for binding in body.domains):
            raise HTTPException(409, "Custom domain is already assigned")

        # The provisioning request is retriable.  A proxy/client can lose the
        # response after all tenant work has committed; returning the already
        # active organization prevents a second location or invitation from
        # being created when the operator submits the same request again.
        existing = await db.get(Organization, str(body.organization_id)) if body.organization_id else None
        if existing is None and body.organization_id is None:
            # A browser reload loses the client-held request id.  Treat an
            # active tenant with the same normalized slug and name as the
            # completed request instead of provisioning a second copy.
            slug_match = await db.scalar(
                select(Organization).where(Organization.slug == body.slug)
            )
            if (
                slug_match is not None
                and slug_match.status == "active"
                and slug_match.name.strip().casefold() == body.name.strip().casefold()
            ):
                existing = slug_match
    if existing is not None and existing.status == "active":
        async with organization_session(existing) as db:
            location = await db.scalar(select(Location).order_by(Location.created_at))
        return {
            "organization_id": existing.id,
            "slug": existing.slug,
            "location_id": location.id if location else None,
            "invitation": None,
            "status": "active",
            "already_provisioned": True,
        }
    org = await provision(
        body.name,
        str(body.organization_id) if body.organization_id else None,
        body.slug,
        body.region,
    )
    try:
        async with organization_session(org) as db:
            runtime = await configure_tenant(
                db,
                visibility=body.visibility,
                branding=body.branding,
                policy=default_policy,
                actor_id=actor.user_id,
            )
            if body.booking_widget_origin:
                try:
                    widget_origin = normalize_widget_origin(body.booking_widget_origin)
                except ValueError as exc:
                    raise HTTPException(422, str(exc)) from exc
                runtime.booking_widget = {
                    **(runtime.booking_widget or {}),
                    "approval_request": {
                        "status": "pending",
                        "origin": widget_origin,
                        "requested_at": datetime.now(UTC).isoformat(),
                        "approved_at": None,
                        "approved_by": None,
                        "rejection_reason": "",
                    },
                    "origin_verifications": [_widget_origin_record(widget_origin)],
                    "allowed_origins": [],
                }
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
            pending_invitation = await db.scalar(
                select(StaffInvite).where(
                    StaffInvite.email == body.admin_email.lower(),
                    StaffInvite.status == "pending",
                    StaffInvite.used.is_(False),
                    StaffInvite.expires > int(time.time()),
                )
            )
            onboarding_role = await db.get(TenantRole, TENANT_SUPER_ADMIN_ROLE_ID)
            if onboarding_role is None:
                raise HTTPException(503, "Tenant setup roles are unavailable")
            invitation = (
                None
                if existing or pending_invitation
                else await invite(
                    db,
                    InviteInput(
                        name=body.admin_name,
                        email=body.admin_email,
                        # The first account is the tenant setup administrator.  It
                        # must receive the protected canonical role directly;
                        # assigning the legacy admin role here caused onboarding
                        # to create a second organization assignment later.
                        assignments=[AccessAssignmentInput(role=onboarding_role.name, scope="organization")],
                    ),
                    "platform",
                    org.name,
                    delivery_actor=delivery_actor,
                    tenant_slug=org.slug,
                    # Keep the invitation in the tenant transaction.  A mail
                    # provider is an external side effect, so it is delivered
                    # only after the tenant and control-plane commits below.
                    deliver_immediately=False,
                )
            )
            audit(db, "platform", "onboard", "organization", org.id)
        async with control_session() as db:
            row = await db.get(Organization, org.id)
            # Back Office is inherent to every tenant.  All patient-facing
            # surfaces are determined by the validated commercial plan (and a
            # reviewed combination where the plan offers one), never a client
            # checkbox submitted by onboarding.
            row.domains = body.domains
            row.front_office_enabled = effective_front_office
            row.booking_enabled = effective_booking
            row.patient_portal_enabled = effective_portal
            row.updated_by = actor.user_id
            commercial = await db.scalar(
                select(PlatformCommercialAccount).where(
                    PlatformCommercialAccount.organization_id == org.id
                )
            )
            if commercial is None:
                commercial = PlatformCommercialAccount(
                    organization_id=org.id,
                    account_status="active",
                    plan_code=row.plan,
                    created_by=actor.user_id,
                    updated_by=actor.user_id,
                )
                db.add(commercial)
            if body.plan_code:
                plan = await db.scalar(
                    select(PlatformPlan).where(
                        PlatformPlan.code == body.plan_code,
                        PlatformPlan.active,
                    )
                )
                if plan is None:
                    raise HTTPException(422, "Selected plan is unavailable")
                subscription = await db.scalar(
                    select(PlatformSubscription).where(
                        PlatformSubscription.organization_id == org.id
                    )
                )
                started_at = body.current_period_start or datetime.now(UTC)
                if subscription is None:
                    subscription = PlatformSubscription(
                        organization_id=org.id,
                        plan_id=plan.id,
                        created_by=actor.user_id,
                        updated_by=actor.user_id,
                    )
                    db.add(subscription)
                subscription.plan_id = plan.id
                subscription.status = body.subscription_status
                subscription.trial_ends_at = body.trial_ends_at
                subscription.current_period_start = started_at
                subscription.current_period_end = body.current_period_end or body.trial_ends_at
                subscription.external_reference = body.external_reference
                subscription.subscription_metadata = {
                    **(subscription.subscription_metadata or {}),
                    "source": "public_platform_signup" if actor.user_id == "self-onboarding" else "platform_admin",
                    "payment_status": "authorized" if body.external_reference else "not_applicable",
                    "selected_combination_code": selected_combination.code if selected_combination else None,
                }
                subscription.updated_by = actor.user_id
                row.plan = plan.code
                commercial.plan_code = plan.code
                commercial.subscription_status = body.subscription_status
                commercial.external_reference = body.external_reference
                commercial.updated_by = actor.user_id
                onboarding_ledger_reference = f"plan-onboarding:{org.id}:{plan.id}"
                if not await db.scalar(
                    select(PlatformCommercialLedgerEntry).where(
                        PlatformCommercialLedgerEntry.reference == onboarding_ledger_reference
                    )
                ):
                    db.add(
                        PlatformCommercialLedgerEntry(
                            organization_id=org.id,
                            kind="plan_assignment",
                            description=f"{plan.name} plan · {plan.interval}",
                            gross_amount_cents=plan.price_cents,
                            discount_cents=0,
                            net_amount_cents=plan.price_cents,
                            currency=plan.currency,
                            status="scheduled" if body.subscription_status == "trialing" else "open",
                            reference=onboarding_ledger_reference,
                            entry_metadata={"plan_id": plan.id, "plan_code": plan.code, "subscription_status": body.subscription_status},
                            created_by=actor.user_id,
                            updated_by=actor.user_id,
                        )
                    )
                platform_audit(
                    db,
                    actor.user_id,
                    "billing.subscription.create",
                    organization_id=org.id,
                    details={
                        "plan_code": plan.code,
                        "status": body.subscription_status,
                        "trial_ends_at": body.trial_ends_at.isoformat() if body.trial_ends_at else None,
                        "payment_reference": body.external_reference,
                    },
                )
            if body.trial_mode:
                if not body.trial_terms_accepted or not body.data_processing_acknowledged:
                    raise HTTPException(
                        422,
                        "Secure trial terms and the no-PHI acknowledgement are required",
                    )
                commercial.commercial_metadata = {
                    **(commercial.commercial_metadata or {}),
                    "self_onboarding": {
                        "mode": "secure_trial",
                        "phi_import_allowed": False,
                        "production_activation": "required",
                        "custom_domains": "assisted_activation",
                        "widgets": "assisted_activation",
                        "sso_and_integrations": "assisted_activation",
                        "trial_terms_accepted": True,
                        "data_processing_acknowledged": True,
                        "administrator_verification": "invite_acceptance",
                        "mfa_required": True,
                        "accepted_at": datetime.now(UTC).isoformat(),
                    },
                }
                platform_audit(
                    db,
                    actor.user_id,
                    "organization.secure-trial.started",
                    organization_id=org.id,
                    details={
                        "phi_import_allowed": False,
                        "production_activation": "required",
                        "custom_domains": "assisted_activation",
                        "widgets": "assisted_activation",
                    },
                )
                enqueue_platform_notification(
                    db,
                    kind="organization.secure-trial.started",
                    reference_id=str(org.id),
                    actor_id=actor.user_id,
                    payload={
                        "organization_id": org.id,
                        "organization_name": row.name,
                        "slug": row.slug,
                        "plan_code": commercial.plan_code or row.plan,
                        "subscription_status": commercial.subscription_status or "trialing",
                        "detail": f"{row.name} started a secure trial and requires production review",
                        "cta_label": "Review secure trial",
                        "target_url": f"/admin/billing-plans/tenants/{org.id}/",
                    },
                )
            if patient_facing:
                domain_request = await _create_domain_request(
                    db,
                    organization=row,
                    mode=body.domain_mode,
                    patient_facing=True,
                    custom_hostname=body.custom_domain_hostname,
                    actor_id=actor.user_id,
                )
                platform_audit(
                    db,
                    actor.user_id,
                    "organization.domain.request",
                    organization_id=org.id,
                    details={
                        "request_id": domain_request.id,
                        "mode": domain_request.mode,
                        "public_hostname": domain_request.public_hostname,
                        "backoffice_hostname": domain_request.backoffice_hostname,
                        "status": domain_request.status,
                    },
                )
                if domain_request.mode == "custom":
                    enqueue_platform_notification(
                        db,
                        kind="organization.domain.requested",
                        reference_id=domain_request.id,
                        actor_id=actor.user_id,
                        payload={
                            "organization_id": org.id,
                            "organization_name": row.name,
                            "request_id": domain_request.id,
                            "hostname": domain_request.public_hostname,
                            "detail": f"{row.name} must complete ownership verification for {domain_request.public_hostname}.",
                            "cta_label": "View domain request",
                            "target_url": "/admin/onboarding/domains/",
                        },
                    )
            if body.booking_widget_origin:
                platform_audit(
                    db,
                    actor.user_id,
                    "organization.booking-widget.request",
                    organization_id=org.id,
                    details={
                        "origin": widget_origin,
                        "plan_code": commercial.plan_code or row.plan,
                        "subscription_status": commercial.subscription_status or "not_configured",
                        "source": "onboarding",
                    },
                )
                enqueue_platform_notification(
                    db,
                    kind="booking-widget.requested",
                    reference_id=f"{org.id}:{hashlib.sha256(widget_origin.encode()).hexdigest()[:16]}",
                    actor_id=actor.user_id,
                    payload={
                        "organization_id": org.id,
                        "organization_name": row.name,
                        "slug": row.slug,
                        "origin": widget_origin,
                        "plan_code": commercial.plan_code or row.plan,
                        "plan_name": "",
                        "subscription_status": commercial.subscription_status or "not_configured",
                        "detail": f"{row.name} requested widget approval for {widget_origin} · {commercial.plan_code or row.plan or 'No plan'} · {commercial.subscription_status or 'No subscription'}",
                        "cta_label": "Review widget request",
                        "target_url": "/admin/onboarding/",
                    },
                )
            platform_audit(db, actor.user_id, "organization.provision", organization_id=org.id)
        await activate(org.id)
        result = {
            "organization_id": org.id,
            "slug": org.slug,
            "location_id": location.id,
            "invitation": invitation,
            "status": "active",
        }
    except Exception:
        if getattr(org, "_provision_created", False):
            try:
                await rollback_provisioned_organization(
                    org.schema_name,
                    org.id,
                    org.database_alias,
                )
            except Exception:
                # Preserve the original onboarding failure while retaining a
                # durable failure marker if cleanup cannot complete.
                async with control_session() as db:
                    failed_org = await db.get(Organization, org.id)
                    if failed_org is not None:
                        failed_org.status = "failed"
                        failed_org.last_error = "onboarding_rollback_failed"
        raise

    # The tenant is now active and all onboarding rows are committed.  Deliver
    # the staged invitation after commit so a provider failure cannot roll back
    # an otherwise valid tenant, and the outbox row remains available for retry.
    if invitation:
        try:
            async with organization_session(org) as db:
                message = await db.scalar(
                    select(OutboxMessage).where(
                        OutboxMessage.idempotency_key
                        == f"staff-invitation:{invitation['invite_id']}"
                    )
                )
                if message is not None and message.status in {"pending", "retry"}:
                    await deliver_message_now(db, delivery_actor, message)
        except Exception:
            # The dispatcher will retry the pending outbox message.  Do not
            # report onboarding as failed after the tenant has committed.
            pass
    return result


async def _domain_request_payload(db, request: OrganizationDomainRequest) -> dict:
    """Return a safe routing-workspace DTO without exposing hidden tokens."""
    hosts = (
        await db.scalars(
            select(OrganizationDomainHost)
            .where(OrganizationDomainHost.request_id == request.id)
            .order_by(OrganizationDomainHost.role, OrganizationDomainHost.hostname)
        )
    ).all()
    verification = await db.scalar(
        select(OrganizationDomainVerification).where(
            OrganizationDomainVerification.request_id == request.id
        )
    )
    payload = {
        "id": request.id,
        "mode": request.mode,
        "status": request.status,
        "public_hostname": request.public_hostname,
        "backoffice_hostname": request.backoffice_hostname,
        "canonical": request.canonical,
        "activation_at": request.activation_at,
        "suspension_at": request.suspension_at,
        "patient_facing": bool((request.request_metadata or {}).get("patient_facing")),
        "hosts": [
            {
                "hostname": host.hostname,
                "role": host.role,
                "routing_status": host.routing_status,
                "tls_status": host.tls_status,
                "canonical": host.canonical,
            }
            for host in hosts
        ],
    }
    if verification:
        payload["verification"] = {
            "method": verification.method,
            "dns_name": verification.dns_name,
            "dns_value": verification.token,
            "http_path": verification.http_path,
            "http_value": verification.token,
            "ownership_status": verification.ownership_status,
            "dns_status": verification.dns_status,
            "tls_status": verification.tls_status,
            "last_checked_at": verification.last_checked_at,
            "propagation_guidance": "DNS and TLS propagation can take up to 24 hours after your change.",
        }
    if request.mode == "custom":
        organization = await db.get(Organization, request.organization_id)
        regions = ["*"] if organization is None else ["*", organization.region]
        configured = await db.scalar(
            select(PlatformAdapterDefault)
            .where(
                PlatformAdapterDefault.capability == "domain_dns_provider",
                PlatformAdapterDefault.region.in_(regions),
                PlatformAdapterDefault.active,
            )
            .order_by(PlatformAdapterDefault.region.desc())
        )
        registration = (
            REGISTRY.get("domain_dns_provider", {}).get(configured.provider_name)
            if configured is not None
            else None
        )
        available = bool(
            configured is not None
            and registration is not None
            and not (configured.mode == "live" and registration.sandbox)
            and not (configured.mode == "sandbox" and not registration.sandbox)
            and (registration.sandbox or settings().allow_live_integrations)
        )
        payload["dns_automation"] = {
            "available": available,
            "provider": configured.provider_name if configured else None,
            "guidance": (
                "An authorised DNS provider is configured. Use automatic setup only when the provider has access to this domain's zone."
                if available
                else "Automatic DNS setup is unavailable until Platform Admin installs and authorises a DNS provider integration for the customer's zone."
            ),
        }
    return jsonable_encoder(payload)


async def _configured_domain_dns_provider(db, organization: Organization):
    """Resolve the explicitly approved DNS automation adapter for one tenant.

    The contract intentionally does not accept DNS credentials from the tenant
    request. Provider-specific authorisation and zone access belong to the
    installed adapter and its secure platform configuration.
    """
    configured = (
        await db.scalars(
            select(PlatformAdapterDefault)
            .where(
                PlatformAdapterDefault.capability == "domain_dns_provider",
                PlatformAdapterDefault.active,
                PlatformAdapterDefault.region.in_(["*", organization.region]),
            )
            .order_by(PlatformAdapterDefault.region.desc())
        )
    ).all()
    selected = next((row for row in configured if row.region == organization.region), None) or next(
        (row for row in configured if row.region == "*"), None
    )
    if selected is None:
        raise HTTPException(
            409,
            "No authorised automated DNS provider is configured for this tenant's region. Use DNS TXT or HTTPS-file verification instead.",
        )
    registration = REGISTRY.get("domain_dns_provider", {}).get(selected.provider_name)
    if registration is None:
        raise HTTPException(
            503,
            "The configured automated DNS provider is not installed. Use DNS TXT or HTTPS-file verification instead.",
        )
    if selected.mode == "live" and registration.sandbox:
        raise HTTPException(503, "The configured automated DNS provider is sandbox-only")
    if selected.mode == "sandbox" and not registration.sandbox:
        raise HTTPException(503, "The configured automated DNS provider has no sandbox adapter")
    try:
        return selected.provider_name, resolve_registered(
            "domain_dns_provider",
            selected.provider_name,
            organization_id=organization.id,
            region=organization.region,
            enforce_live=selected.mode != "sandbox",
        )
    except IntegrationFailure as error:
        raise HTTPException(503, f"Automated DNS provider is unavailable: {error}") from error


async def _resend_domain_verification_invitation(
    organization: Organization,
    request: OrganizationDomainRequest,
    actor: PlatformActor,
) -> bool:
    """Notify the tenant administrator to continue a pending domain request.

    Platform staff may remind the customer, but only a tenant administrator can
    view the proof and run the ownership check from the routing workspace.
    """
    if not request.public_hostname:
        return False
    async with organization_session(organization) as tenant_db:
        recipient = await tenant_db.scalar(
            select(StaffUser)
            .where(
                StaffUser.role_id == TENANT_SUPER_ADMIN_ROLE_ID,
                StaffUser.active,
                StaffUser.archived_at.is_(None),
            )
            .order_by(StaffUser.created_at)
        )
        if recipient is None:
            pending_invite = await tenant_db.scalar(
                select(StaffInvite)
                .where(StaffInvite.status == "pending", StaffInvite.used.is_(False))
                .order_by(StaffInvite.created_at)
            )
            if pending_invite is None:
                return False
            destination, recipient_name = pending_invite.email, pending_invite.name
        else:
            destination, recipient_name = recipient.email, recipient.name
        runtime = await tenant_settings(tenant_db)
        delivery_actor = Actor(
            actor.user_id,
            organization,
            actor.name,
            "platform",
            settings=runtime,
            adapter_names=await attach_effective_adapters(organization),
            assignment_scope="organization",
        )
        workspace = settings().tenant_admin_public_url_template.format(
            tenant_slug=organization.slug
        ).rstrip("/") + "/settings/practice"
        message = OutboxMessage(
            kind="organization.domain-verification",
            payload={
                "destination": destination,
                "subject": f"Action required: verify {request.public_hostname}",
                "body": (
                    f"Hello {recipient_name},\n\n"
                    f"DHMIS is waiting for your organization to verify ownership of "
                    f"{request.public_hostname}. Sign in to the Routing and surfaces "
                    f"workspace to copy the DNS TXT or HTTPS verification-file instruction, "
                    f"then run the verification check. DNS and certificate propagation can take up to 24 hours.\n\n"
                    f"Open routing workspace: {workspace}"
                ),
                "channel": "email",
                "user_id": recipient.id if recipient else pending_invite.id,
            },
            idempotency_key=f"domain-verification-resend:{request.id}:{secrets.token_hex(8)}",
            created_by=actor.user_id,
            updated_by=actor.user_id,
        )
        await deliver_message_now(tenant_db, delivery_actor, message)
        return True


async def _check_custom_domain_request(
    db,
    request: OrganizationDomainRequest,
    method: Literal["dns", "http"],
    actor_id: str,
) -> OrganizationDomainRequest:
    """Automate the tenant-owned DNS TXT or HTTP-file ownership check.

    The caller can request a check only. It cannot assert success.  Activation
    still requires ownership proof plus a reachable HTTPS endpoint, which is
    the minimum observable routing/TLS signal available to the application.
    """
    verification = await db.scalar(
        select(OrganizationDomainVerification).where(
            OrganizationDomainVerification.request_id == request.id
        )
    )
    if verification is None or not request.public_hostname:
        raise HTTPException(422, "This domain request has no customer-owned verification challenge")
    verification.method = method
    verification.last_checked_at = datetime.now(UTC)
    verification.updated_by = actor_id
    ownership_verified = False
    failure = ""
    if method == "http":
        try:
            url = f"https://{request.public_hostname}{verification.http_path}"
            async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
                response = await client.get(url)
            ownership_verified = response.status_code == 200 and response.text.strip() == verification.token
            if not ownership_verified:
                failure = "The verification file was not found with the expected content."
        except httpx.HTTPError:
            failure = "The verification file could not be reached over HTTPS yet."
    else:
        try:
            # DNS-over-HTTPS keeps the API container free of a shell resolver
            # dependency and works consistently in hosted environments.
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get("https://dns.google/resolve", params={"name": verification.dns_name, "type": "TXT"})
            response.raise_for_status()
            values = {str(item.get("data", "")).strip('"') for item in response.json().get("Answer") or []}
            ownership_verified = verification.token in values
            if not ownership_verified:
                failure = "The required TXT value is not visible yet."
        except Exception:
            failure = "The DNS verification service is unavailable or the required TXT value is not visible yet."
    verification.ownership_status = "verified" if ownership_verified else "pending"
    # HTTP-file ownership proof does not make a DNS-TXT assertion. Preserve
    # that distinction in the tenant and platform workspaces.
    verification.dns_status = (
        "not_required" if method == "http" and ownership_verified else
        "verified" if ownership_verified else "pending"
    )
    tls_ready = False
    if ownership_verified:
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
                response = await client.head(f"https://{request.public_hostname}")
            tls_ready = response.status_code < 500
        except httpx.HTTPError:
            tls_ready = False
    verification.tls_status = "ready" if tls_ready else "pending"
    request.updated_by = actor_id
    if ownership_verified and tls_ready:
        request.status = "active"
        request.canonical = True
        request.activation_at = datetime.now(UTC)
        hosts = (
            await db.scalars(select(OrganizationDomainHost).where(OrganizationDomainHost.request_id == request.id))
        ).all()
        for host in hosts:
            # The managed administrative hostname is a fallback/redirect
            # alias, never the canonical custom-domain application host.
            host.routing_status = "active"
            host.tls_status = "ready"
            host.canonical = host.role != "managed_back_office"
            host.updated_by = actor_id
        event_type = "activated"
        details = {"method": method}
    else:
        request.status = "pending_propagation" if ownership_verified else "pending_verification"
        event_type = "verification_pending"
        details = {"method": method, "reason": failure, "tls_ready": tls_ready}
    db.add(OrganizationDomainEvent(
        request_id=request.id,
        event_type=event_type,
        details=details,
        created_by=actor_id,
        updated_by=actor_id,
    ))
    return request


@router.get("/organization/routing/domain")
async def tenant_domain_routing_workspace(
    actor: Actor = Depends(permit("settings")),
):
    """Tenant-admin workspace for inspecting and completing domain setup."""
    async with control_session() as db:
        request = await db.scalar(
            select(OrganizationDomainRequest)
            .where(OrganizationDomainRequest.organization_id == actor.organization.id)
            .order_by(OrganizationDomainRequest.created_at.desc())
        )
        if request is None:
            return {"domain_request": None, "managed_backoffice_hostname": f"admin.{actor.organization.slug}.dhmis.test"}
        return {"domain_request": await _domain_request_payload(db, request)}


@router.post("/organization/routing/domain/{request_id}/verify")
async def tenant_verify_domain_routing(
    request_id: str,
    body: DomainVerificationInput,
    actor: Actor = Depends(permit("settings")),
):
    """Run the customer-owned verification check; this is never an admin override."""
    async with control_session() as db:
        request = await db.get(OrganizationDomainRequest, request_id)
        if request is None or request.organization_id != actor.organization.id:
            raise HTTPException(404, "Domain request not found")
        if request.mode != "custom" or request.status in {"cancelled", "suspended"}:
            raise HTTPException(422, "This domain request cannot be verified")
        await _check_custom_domain_request(db, request, body.method, actor.user_id)
        platform_audit(
            db,
            actor.user_id,
            "organization.domain.verification.check",
            organization_id=actor.organization.id,
            details={"request_id": request.id, "method": body.method, "status": request.status},
        )
        return {"domain_request": await _domain_request_payload(db, request)}


@router.post("/organization/routing/domain/{request_id}/dns-automation")
async def tenant_setup_domain_dns_automatically(
    request_id: str,
    actor: Actor = Depends(permit("settings")),
):
    """Ask a configured provider to place the existing ownership TXT record.

    This does not mark the request verified. The tenant still runs the normal
    verification check after DNS propagation, and the provider must decline
    any zone it is not authorised to manage.
    """
    async with control_session() as db:
        request = await db.get(OrganizationDomainRequest, request_id)
        if request is None or request.organization_id != actor.organization.id:
            raise HTTPException(404, "Domain request not found")
        if request.mode != "custom" or request.status in {"cancelled", "suspended", "active"}:
            raise HTTPException(422, "This domain request cannot use automatic DNS setup")
        verification = await db.scalar(
            select(OrganizationDomainVerification).where(
                OrganizationDomainVerification.request_id == request.id
            )
        )
        if verification is None:
            raise HTTPException(422, "This domain request has no DNS verification challenge")
        provider_name, provider = await _configured_domain_dns_provider(db, actor.organization)
        try:
            if not await provider.can_manage_zone(request.public_hostname or ""):
                raise HTTPException(
                    409,
                    "The configured DNS provider is not authorised for this domain's zone. Use DNS TXT or HTTPS-file verification instead.",
                )
            result = await provider.upsert_txt_record(
                hostname=verification.dns_name,
                value=verification.token,
                idempotency_key=f"domain-dns:{request.id}:{verification.token}",
            )
        except HTTPException:
            raise
        except IntegrationFailure as error:
            raise HTTPException(502, f"Automated DNS setup failed: {error}") from error
        except Exception:
            # Provider exceptions can contain vendor response bodies. Keep the
            # tenant response safe while retaining a minimal audit record.
            raise HTTPException(502, "Automated DNS setup could not be completed") from None
        verification.verification_metadata = {
            **(verification.verification_metadata or {}),
            "dns_automation": {
                "provider": provider_name,
                "requested_at": datetime.now(UTC).isoformat(),
                "result": {
                    key: value if isinstance(value, (str, int, float, bool, type(None))) else str(value)
                    for key, value in (result or {}).items()
                    if key in {"record_id", "zone_id", "status"}
                },
            },
        }
        verification.updated_by = actor.user_id
        db.add(OrganizationDomainEvent(
            request_id=request.id,
            event_type="dns_automation_requested",
            details={"provider": provider_name},
            created_by=actor.user_id,
            updated_by=actor.user_id,
        ))
        platform_audit(
            db,
            actor.user_id,
            "organization.domain.dns_automation.request",
            organization_id=actor.organization.id,
            details={"request_id": request.id, "provider": provider_name},
        )
        return {"domain_request": await _domain_request_payload(db, request)}


@router.get("/platform/domain-requests")
async def platform_domain_requests(
    status: str | None = Query(default=None, max_length=40),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=10, le=MAX_PAGE_SIZE),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("organizations.tenant_onboarding.read")),
):
    """Monitoring queue only; it intentionally provides no ownership approval."""
    async with control_session() as db:
        query = select(OrganizationDomainRequest, Organization).join(
            Organization, Organization.id == OrganizationDomainRequest.organization_id
        )
        if status:
            query = query.where(OrganizationDomainRequest.status == status)
        total = await db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
        rows = (await db.execute(query.order_by(OrganizationDomainRequest.created_at.desc()).offset((page - 1) * page_size).limit(page_size))).all()
        items = []
        for request, organization in rows:
            payload = await _domain_request_payload(db, request)
            payload.update({"organization_id": organization.id, "organization_name": organization.name, "slug": organization.slug})
            items.append(payload)
        platform_audit(db, actor.user_id, "organization.domain.monitor.read", details={"page": page, "page_size": page_size})
        return {"page": page, "page_size": page_size, "total": total, "items": items}


@router.post("/platform/domain-requests/{request_id}/{action}")
async def platform_domain_request_action(
    request_id: str,
    action: Literal["resend", "cancel", "suspend"],
    body: DomainRequestDecisionInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("organizations.tenant_onboarding.update")),
):
    """Platform-side lifecycle controls that cannot establish customer ownership."""
    async with control_session() as db:
        request = await db.get(OrganizationDomainRequest, request_id)
        if request is None:
            raise HTTPException(404, "Domain request not found")
        if action == "resend":
            organization = await db.get(Organization, request.organization_id)
            delivered = bool(organization and await _resend_domain_verification_invitation(organization, request, actor))
            db.add(OrganizationDomainEvent(
                request_id=request.id,
                event_type="verification_invitation_resent",
                details={"reason": body.reason, "delivery_queued": delivered},
                created_by=actor.user_id,
                updated_by=actor.user_id,
            ))
            if not delivered:
                raise HTTPException(409, "No active tenant administrator or pending administrator invitation is available")
        else:
            request.status = "cancelled" if action == "cancel" else "suspended"
            request.suspension_at = datetime.now(UTC)
            request.canonical = False
            request.updated_by = actor.user_id
            hosts = (await db.scalars(select(OrganizationDomainHost).where(OrganizationDomainHost.request_id == request.id))).all()
            for host in hosts:
                host.routing_status = "suspended"
                host.updated_by = actor.user_id
            db.add(OrganizationDomainEvent(request_id=request.id, event_type=action, details={"reason": body.reason}, created_by=actor.user_id, updated_by=actor.user_id))
        platform_audit(db, actor.user_id, f"organization.domain.{action}", organization_id=request.organization_id, details={"request_id": request.id, "reason": body.reason})
        return {"domain_request": await _domain_request_payload(db, request)}



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
        payloads = await _organization_list_payloads(db, rows)
        platform_audit(db, actor.user_id, "organization.list")
        return payloads


@router.get("/platform/organizations/booking-widget-requests")
async def platform_booking_widget_requests(
    status: str = Query(default="pending", pattern="^(all|pending|approved|rejected|not_requested)$"),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("organizations.organization_tenant_record.read")),
):
    """List tenant widget purchase/domain requests for the onboarding workspace."""
    del actor
    async with control_session() as control_db:
        organizations = (await control_db.scalars(select(Organization).order_by(Organization.name))).all()
        commercial = {
            organization.id: await _commercial_summary(control_db, organization.id, organization.plan)
            for organization in organizations
        }
    items = []
    for organization in organizations:
        async with organization_session(organization) as tenant_db:
            runtime = await tenant_settings(tenant_db)
            request = _widget_request_record(runtime.booking_widget)
        if status != "all" and request.get("status") != status:
            continue
        if request.get("status") == "not_requested":
            continue
        items.append({
            "organization_id": organization.id,
            "organization_name": organization.name,
            "slug": organization.slug,
            # Keep the legacy field for older clients, but expose the
            # subscription-backed values that govern the tenant today.
            "plan": commercial[organization.id]["plan_code"] or organization.plan,
            "plan_code": commercial[organization.id]["plan_code"] or organization.plan,
            "plan_name": commercial[organization.id]["plan_name"],
            "subscription_status": commercial[organization.id]["subscription_status"],
            "account_status": commercial[organization.id]["account_status"],
            "status": request.get("status"),
            "origin": request.get("origin", ""),
            "requested_at": request.get("requested_at"),
            "approved_at": request.get("approved_at"),
            "approved_by": request.get("approved_by"),
            "rejection_reason": request.get("rejection_reason", ""),
            "request_type": request.get("request_type", "initial"),
            "previous_origin": request.get("previous_origin"),
        })
    return {"items": items}


@router.post("/platform/organizations/{identifier}/booking-widget-request/decision")
async def decide_booking_widget_request(
    identifier: str,
    body: BookingWidgetDecisionInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("organizations.tenant_onboarding.provision")),
):
    """Approve or reject a purchased widget/domain request."""
    async with control_session() as control_db:
        organization = await control_db.get(Organization, identifier)
    if organization is None:
        raise HTTPException(404, "Organization not found")
    async with organization_session(organization) as db:
        runtime = await tenant_settings(db)
        current = runtime.booking_widget or {}
        request = _widget_request_record(current)
        if request.get("status") not in {"pending", "rejected"}:
            raise HTTPException(409, "There is no pending widget request for this tenant")
        next_status = body.status
        next_request = {
            **request,
            "status": next_status,
            "approved_at": datetime.now(UTC).isoformat() if next_status == "approved" else None,
            "approved_by": actor.user_id if next_status == "approved" else None,
            "rejection_reason": body.reason.strip() if next_status == "rejected" else "",
        }
        runtime.booking_widget = {**current, "approval_request": next_request}
        if next_status == "approved":
            approved_origin = request.get("origin", "")
            records = list(current.get("origin_verifications") or [])
            approved_record = next((item for item in records if item.get("origin") == approved_origin), None)
            if approved_record is None:
                approved_record = {
                    "origin": approved_origin,
                    "dns_name": "",
                    "token": "",
                    "verification_method": "admin",
                    "verified_at": next_request["approved_at"],
                    "verified_by": actor.user_id,
                }
                records.append(approved_record)
            else:
                approved_record.update(
                    verification_method="admin",
                    verified_at=next_request["approved_at"],
                    verified_by=actor.user_id,
                )
            runtime.booking_widget["origin_verifications"] = records
            existing_allowed = list(current.get("allowed_origins") or [])
            runtime.booking_widget["allowed_origins"] = (
                list(dict.fromkeys([*existing_allowed, approved_origin]))
                if request.get("request_type") == "additional"
                else [approved_origin]
            )
        elif next_status == "rejected":
            runtime.booking_widget["allowed_origins"] = (
                list(current.get("allowed_origins") or [])
                if request.get("request_type") == "additional"
                else []
            )
        await configure_tenant(db, actor_id=actor.user_id, booking_widget=runtime.booking_widget)
        audit(
            db,
            actor.user_id,
            f"booking-widget.request.{next_status}",
            "organization",
            organization.id,
            origin=request.get("origin", ""),
            previous_origin=request.get("previous_origin"),
            request_type=request.get("request_type", "initial"),
        )
    async with control_session() as control_db:
        platform_audit(
            control_db,
            actor.user_id,
            f"organization.booking-widget.{next_status}",
            organization_id=organization.id,
            details={
                "origin": request.get("origin", ""),
                "previous_origin": request.get("previous_origin"),
                "request_type": request.get("request_type", "initial"),
                "reason": body.reason,
            },
        )
    return {"organization_id": organization.id, "status": next_status, "origin": request.get("origin", "")}


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


@router.post("/platform/organizations/{identifier}/production-activation")
async def activate_secure_trial_for_production(
    identifier: str,
    body: ProductionActivationInput,
    actor: PlatformActor = Depends(
        permit_platform_or_bootstrap(
            "organizations.tenant_onboarding.activate",
            workflow_handles_approval=True,
        )
    ),
):
    """Convert a self-service secure trial into a reviewed production tenant."""

    async with control_session() as db:
        organization = await db.get(Organization, identifier)
        if organization is None:
            raise HTTPException(404, "Organization not found")
        account = await db.scalar(
            select(PlatformCommercialAccount).where(
                PlatformCommercialAccount.organization_id == identifier
            )
        )
        if account is None:
            raise HTTPException(409, "The organization has no commercial account")
        metadata = dict(account.commercial_metadata or {})
        trial = dict(metadata.get("self_onboarding") or {})
        if trial.get("mode") != "secure_trial":
            raise HTTPException(409, "This organization was not created through secure self-onboarding")
        if trial.get("production_activation") == "approved":
            return {
                "organization_id": identifier,
                "status": "already_active",
                "changed": False,
            }
        now = datetime.now(UTC)
        trial.update(
            {
                "production_activation": "approved",
                "phi_import_allowed": body.allow_phi_import,
                "custom_domains": "enabled" if body.allow_custom_domains else "assisted_activation",
                "widgets": "enabled" if body.allow_widgets else "assisted_activation",
                "sso_and_integrations": "enabled" if body.allow_sso_and_integrations else "assisted_activation",
                "approved_at": now.isoformat(),
                "approved_by": actor.user_id,
            }
        )
        account.commercial_metadata = {**metadata, "self_onboarding": trial}
        account.account_status = "active"
        account.subscription_status = "active"
        account.updated_by = actor.user_id
        subscription = await db.scalar(
            select(PlatformSubscription).where(
                PlatformSubscription.organization_id == identifier
            )
        )
        if subscription is not None:
            subscription.status = "active"
            subscription.updated_by = actor.user_id
        platform_audit(
            db,
            actor.user_id,
            "organization.secure-trial.production-activation",
            organization_id=identifier,
            reason=body.reason,
            details={
                "phi_import_allowed": body.allow_phi_import,
                "custom_domains": body.allow_custom_domains,
                "widgets": body.allow_widgets,
                "sso_and_integrations": body.allow_sso_and_integrations,
            },
        )
    return {
        "organization_id": identifier,
        "status": "active",
        "changed": True,
        "production_activation": trial,
    }


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
        payloads = await _organization_list_payloads(db, rows)
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
            "items": payloads,
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
            applicable = [row for row in defaults if row.capability == capability]
            selected = next((row for row in applicable if row.region == "*"), None) or next(iter(applicable), None)
            registration = registrations.get(selected.provider_name) if selected else None
            mode = selected.mode if selected else "auto"
            sandbox_only = bool(
                registration
                and (mode == "sandbox" or (mode == "auto" and registration.sandbox))
            )
            if selected is None:
                state = "unconfigured"
                ready = False
            elif not selected.active:
                state = "disabled"
                ready = False
            elif registration is None:
                state = "unavailable"
                ready = False
            elif mode == "live" and registration.sandbox:
                state = "invalid-mode"
                ready = False
            elif mode == "sandbox" and not registration.sandbox:
                state = "invalid-mode"
                ready = False
            elif mode == "live" and not settings().allow_live_integrations:
                state = "live-disabled"
                ready = False
            else:
                state = "sandbox-only" if sandbox_only else "ready"
                ready = True
            result.append(
                {
                    "capability": capability,
                    "registered_providers": sorted(registrations),
                    "configured": bool(selected),
                    "provider_name": selected.provider_name if selected else "",
                    "active": bool(selected and selected.active),
                    "mode": mode,
                    "ready": ready,
                    "sandbox_only": sandbox_only,
                    "state": state if registrations else "unavailable",
                    "regional_defaults": [
                        {
                            "region": row.region,
                            "provider_name": row.provider_name,
                            "mode": row.mode,
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
        "public_available": plan.public_available,
        "configuration_mode": plan.configuration_mode,
        "configuration_status": plan.configuration_status,
        "configuration_notes": plan.configuration_notes or {},
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
    combinations = (
        await db.scalars(
            select(PlatformPlanCombination)
            .where(PlatformPlanCombination.plan_id == plan.id)
            .order_by(PlatformPlanCombination.name)
        )
    ).all()
    payload["combinations"] = [
        {
            "id": combination.id,
            "code": combination.code,
            "name": combination.name,
            "feature_keys": combination.feature_keys or [],
            "price_cents": combination.price_cents,
            "currency": combination.currency,
            "active": combination.active,
        }
        for combination in combinations
    ]
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


def _preflight_plan_configuration(body: PlatformPlanInput) -> dict:
    """Reject a plan that cannot be provisioned before it reaches the catalogue."""

    enabled = {item.key for item in (body.entitlements or []) if item.enabled}
    if "module.appointment_widget" in enabled and "capability.appointment_booking" not in enabled:
        raise HTTPException(
            422,
            {
                "code": "PLAN_WIDGET_BOOKING_REQUIRED",
                "message": "Appointment Widget requires Online Appointment Booking in the same plan bundle.",
            },
        )
    if body.configuration_mode == "fixed" and body.combinations:
        raise HTTPException(422, "A fixed plan cannot define selectable combinations")
    if body.configuration_mode == "selectable":
        if body.public_available:
            raise HTTPException(422, "Selectable curated plans cannot be public")
        if not body.combinations:
            raise HTTPException(422, "A selectable curated plan requires at least one reviewed combination")
        codes = [combination.code for combination in body.combinations]
        if len(codes) != len(set(codes)):
            raise HTTPException(422, "Plan combination codes must be unique")
        for combination in body.combinations:
            requested = set(combination.feature_keys)
            if not requested.issubset(enabled):
                raise HTTPException(
                    422,
                    {
                        "code": "PLAN_COMBINATION_FEATURE_INVALID",
                        "message": f"Combination {combination.name} includes a feature not enabled on the plan.",
                    },
                )
            if "module.appointment_widget" in requested and "capability.appointment_booking" not in requested:
                raise HTTPException(
                    422,
                    {
                        "code": "PLAN_COMBINATION_WIDGET_BOOKING_REQUIRED",
                        "message": f"Combination {combination.name} includes Appointment Widget without Online Appointment Booking.",
                    },
                )
    return {
        "validated_at": datetime.now(UTC).isoformat(),
        "configuration_mode": body.configuration_mode,
        "public_available": body.public_available,
        "enabled_feature_keys": sorted(enabled),
    }


async def _sync_plan_combinations(db, plan: PlatformPlan, combinations: list[PlanCombinationInput], actor_id: str) -> None:
    """Replace curated combinations atomically after plan preflight has passed."""

    await db.execute(delete(PlatformPlanCombination).where(PlatformPlanCombination.plan_id == plan.id))
    for combination in combinations:
        db.add(
            PlatformPlanCombination(
                plan_id=plan.id,
                code=combination.code,
                name=combination.name,
                feature_keys=combination.feature_keys,
                price_cents=combination.price_cents,
                currency=combination.currency,
                active=combination.active,
                created_by=actor_id,
                updated_by=actor_id,
            )
        )


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
        plans = (
            await db.scalars(
                select(PlatformPlan).where(
                    PlatformPlan.active,
                    PlatformPlan.public_available,
                    PlatformPlan.configuration_status == "validated",
                )
            )
        ).all()
        plans = sorted(plans, key=lambda plan: (plan.price_cents == 0, plan.price_cents, plan.name))
        return [await platform_plan_payload_with_entitlements(db, plan) for plan in plans]


async def _authorize_public_signup_payment(
    *, plan: PlatformPlan, payment_method_token: str, idempotency_key: str, region: str
):
    """Use the installed sandbox gateway to authorize a method without charging it."""

    gateway = resolve_registered(
        "payment_gateway",
        "sandbox",
        organization_id="platform-signup",
        region=region,
        enforce_live=False,
    )
    try:
        return await gateway.authorize_platform(
            PlatformPaymentRequest(
                idempotency_key=idempotency_key,
                amount_cents=max(plan.price_cents, 1),
                currency=plan.currency,
                payment_method_token=payment_method_token,
            )
        )
    except IntegrationFailure as error:
        raise HTTPException(502, str(error)) from error
    except ValueError as error:
        raise HTTPException(422, str(error)) from error


@router.post("/public/platform/payment-methods/authorize")
async def authorize_public_platform_payment(body: PublicPaymentMethodInput):
    """Return a deterministic sandbox success for a trial payment method."""

    async with control_session() as db:
        plan = await db.scalar(
            select(PlatformPlan).where(
                PlatformPlan.code == body.plan_code,
                PlatformPlan.active,
                PlatformPlan.configuration_status == "validated",
            )
        )
        if plan is None:
            raise HTTPException(422, "Selected plan is unavailable")
        if plan.price_cents <= 0:
            raise HTTPException(422, "This plan requires a sales-assisted subscription")
    result = await _authorize_public_signup_payment(
        plan=plan,
        payment_method_token=body.payment_method_token,
        idempotency_key=f"payment-method:{uuid4()}",
        region=body.region,
    )
    return {
        "status": "success",
        "sandbox": result.sandbox,
        "payment_status": result.status,
        "reference": result.reference,
        "message": "Payment method accepted by the sandbox gateway. No trial charge was made.",
    }


@router.post("/public/platform/onboarding", status_code=201)
async def public_platform_onboarding(body: PublicPlatformSignup):
    """Start a secure, isolated trial from Platform Home.

    Public self-onboarding never provisions production integrations. Custom
    domains, appointment widgets, imports, SSO, and other reviewed capabilities
    remain Platform Admin assisted actions after the tenant has been created.
    """

    if not body.trial_terms_accepted or not body.data_processing_acknowledged:
        raise HTTPException(
            422,
            "Accept the secure trial terms and confirm that no PHI will be imported before production activation",
        )
    if body.organization_id:
        raise HTTPException(422, "Public self-onboarding cannot target an existing organization")
    if body.custom_hostname or body.booking_widget_origin:
        raise HTTPException(
            422,
            "Custom domains and appointment widgets require assisted production activation",
        )

    async with control_session() as db:
        plan = await db.scalar(
            select(PlatformPlan).where(
                PlatformPlan.code == body.plan_code,
                PlatformPlan.active,
                PlatformPlan.public_available,
                PlatformPlan.configuration_status == "validated",
            )
        )
        if plan is None:
            raise HTTPException(422, "Selected plan is unavailable")
        if plan.price_cents <= 0:
            raise HTTPException(422, "This plan requires a sales-assisted subscription")
        if plan.trial_days <= 0:
            raise HTTPException(422, "This plan is not available for secure self-onboarding")

    organization_id = uuid4()
    payment = await _authorize_public_signup_payment(
        plan=plan,
        payment_method_token=body.payment_method_token,
        idempotency_key=f"signup:{organization_id}",
        region=body.region,
    )
    now = datetime.now(UTC)
    trial_ends_at = now + timedelta(days=plan.trial_days)
    subscription_status = "trialing" if plan.trial_days else "active"
    onboarding_body = Onboarding(
        organization_id=organization_id,
        name=body.name,
        slug=body.slug,
        region=body.region,
        location_name=body.location_name,
        location_address=body.location_address,
        location_phone=body.location_phone,
        location_timezone=body.location_timezone,
        admin_name=body.admin_name,
        admin_email=body.admin_email,
        front_office_enabled=body.front_office_enabled,
        booking_enabled=body.booking_enabled,
        patient_portal_enabled=body.patient_portal_enabled,
        booking_widget_origin=None,
        trial_mode=True,
        trial_terms_accepted=body.trial_terms_accepted,
        data_processing_acknowledged=body.data_processing_acknowledged,
        plan_code=plan.code,
        subscription_status=subscription_status,
        trial_ends_at=trial_ends_at if plan.trial_days else None,
        current_period_start=now,
        current_period_end=trial_ends_at if plan.trial_days else None,
        external_reference=payment.reference,
        custom_domain_hostname=None,
        custom_domain_surfaces=[],
    )
    self_onboarding_actor = PlatformActor(
        "self-onboarding",
        body.admin_name,
        "self-onboarding",
        "",
        is_bootstrap_operator=True,
    )
    result = await onboarding(onboarding_body, self_onboarding_actor)
    host_template = settings().tenant_public_url_template
    managed_url = host_template.format(tenant_slug=result["slug"])
    return {
        **result,
        "plan_code": plan.code,
        "plan_name": plan.name,
        "subscription_status": subscription_status,
        "trial_ends_at": trial_ends_at.isoformat() if plan.trial_days else None,
        "payment": {
            "status": payment.status,
            "sandbox": payment.sandbox,
            "reference": payment.reference,
        },
        "managed_url": managed_url,
        "secure_trial": {
            "phi_import_allowed": False,
            "production_activation_required": True,
            "custom_domains": "assisted_activation",
            "widgets": "assisted_activation",
            "sso_and_integrations": "assisted_activation",
            "administrator_verification_required": True,
            "mfa_setup_required": True,
        },
        "custom_domain": None,
        "widget": {
            "status": "assisted_activation_required",
            "origin": None,
        },
    }


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
        preflight = _preflight_plan_configuration(body)
        plan = PlatformPlan(
            **body.model_dump(exclude={"entitlements", "combinations"}),
            configuration_status="validated",
            configuration_notes=preflight,
            created_by=actor.user_id,
            updated_by=actor.user_id,
        )
        db.add(plan)
        await db.flush()
        await sync_plan_entitlements(db, plan, body.entitlements, actor.user_id)
        await _sync_plan_combinations(db, plan, body.combinations, actor.user_id)
        await db.flush()
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
        preflight = _preflight_plan_configuration(body)
        for key, value in body.model_dump(exclude={"entitlements", "combinations"}).items():
            setattr(plan, key, value)
        plan.configuration_status = "validated"
        plan.configuration_notes = preflight
        plan.updated_by = actor.user_id
        await sync_plan_entitlements(db, plan, body.entitlements, actor.user_id)
        await _sync_plan_combinations(db, plan, body.combinations, actor.user_id)
        await db.flush()
        platform_audit(db, actor.user_id, "billing.plan.update", details={"plan_id": plan_id, "plan_code": plan.code})
        return await platform_plan_payload_with_entitlements(db, plan)


def _addon_product_payload(product: PlatformAddonProduct, feature: PlatformFeature) -> dict:
    return {
        "id": product.id,
        "feature_key": feature.key,
        "code": product.code,
        "name": product.name,
        "description": product.description,
        "quantity": product.quantity,
        "price_cents": product.price_cents,
        "currency": product.currency,
        "interval": product.interval,
        "active": product.active,
    }


@router.get("/platform/billing/addon-products")
async def platform_addon_products(
    feature_key: str | None = Query(default=None),
    include_inactive: bool = Query(default=False),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.plan_assignment.read")),
):
    async with control_session() as db:
        query = select(PlatformAddonProduct, PlatformFeature).join(
            PlatformFeature, PlatformFeature.id == PlatformAddonProduct.feature_id
        )
        if feature_key:
            query = query.where(PlatformFeature.key == feature_key)
        if not include_inactive:
            query = query.where(PlatformAddonProduct.active)
        rows = (await db.execute(query.order_by(PlatformAddonProduct.name))).all()
        platform_audit(db, actor.user_id, "billing.addon-products.read")
        return [_addon_product_payload(product, feature) for product, feature in rows]


@router.post("/platform/billing/addon-products", status_code=201)
async def create_platform_addon_product(
    body: PlatformAddonProductInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.plan_assignment.create")),
):
    async with control_session() as db:
        if await db.scalar(select(PlatformAddonProduct).where(PlatformAddonProduct.code == body.code)):
            raise HTTPException(409, "An add-on product with that code already exists")
        feature = await db.scalar(select(PlatformFeature).where(PlatformFeature.key == body.feature_key, PlatformFeature.active))
        if feature is None:
            raise HTTPException(422, "The selected add-on feature is unavailable")
        product = PlatformAddonProduct(
            feature_id=feature.id,
            code=body.code,
            name=body.name,
            description=body.description,
            quantity=body.quantity,
            price_cents=body.price_cents,
            currency=body.currency,
            interval=body.interval,
            active=body.active,
            created_by=actor.user_id,
            updated_by=actor.user_id,
        )
        db.add(product)
        await db.flush()
        platform_audit(db, actor.user_id, "billing.addon-product.create", details={"code": product.code, "feature_key": feature.key})
        return _addon_product_payload(product, feature)


@router.put("/platform/billing/addon-products/{product_id}")
async def update_platform_addon_product(
    product_id: str,
    body: PlatformAddonProductInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.plan_assignment.update")),
):
    async with control_session() as db:
        product = await db.get(PlatformAddonProduct, product_id)
        if product is None:
            raise HTTPException(404, "Add-on product not found")
        duplicate = await db.scalar(select(PlatformAddonProduct).where(PlatformAddonProduct.code == body.code, PlatformAddonProduct.id != product_id))
        if duplicate:
            raise HTTPException(409, "An add-on product with that code already exists")
        feature = await db.scalar(select(PlatformFeature).where(PlatformFeature.key == body.feature_key, PlatformFeature.active))
        if feature is None:
            raise HTTPException(422, "The selected add-on feature is unavailable")
        product.feature_id = feature.id
        for key, value in body.model_dump(exclude={"feature_key"}).items():
            setattr(product, key, value)
        product.updated_by = actor.user_id
        await db.flush()
        platform_audit(db, actor.user_id, "billing.addon-product.update", details={"code": product.code, "feature_key": feature.key})
        return _addon_product_payload(product, feature)


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
            addon_rows = (
                await db.execute(
                    select(PlatformTenantAddon, PlatformFeature)
                    .join(PlatformFeature, PlatformFeature.id == PlatformTenantAddon.feature_id)
                    .where(
                        PlatformTenantAddon.organization_id == organization.id,
                        PlatformTenantAddon.status == "active",
                    )
                )
            ).all()
            items.append({
                "organization_id": organization.id,
                "organization_name": organization.name,
                "slug": organization.slug,
                # The widget add-on is commercial entitlement only. Routing
                # remains an explicit Tenant management decision.
                "booking_enabled": organization.booking_enabled,
                "account_status": account.account_status,
                "legacy_plan_code": account.plan_code,
                "subscription_status": subscription.status if subscription else account.subscription_status,
                "self_onboarding": (account.commercial_metadata or {}).get("self_onboarding"),
                "addons": [
                    {
                        "id": addon.id,
                        "feature_key": feature.key,
                        "feature_name": feature.name,
                        "quantity": addon.quantity,
                        "unit_price_cents": addon.unit_price_cents,
                        "discount_basis_points": addon.discount_basis_points,
                        "currency": addon.currency,
                        "status": addon.status,
                    }
                    for addon, feature in addon_rows
                ],
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


@router.put("/platform/organizations/{identifier}/addons/appointment-widget")
async def assign_appointment_widget_addon(
    identifier: str,
    body: AppointmentWidgetAddonInput,
    actor: PlatformActor = Depends(
        permit_platform_or_bootstrap("commercial.subscription_record.update")
    ),
):
    """Assign a separately billed widget entitlement and always raise a ledger entry."""

    async with control_session() as db:
        organization = await db.get(Organization, identifier)
        if organization is None:
            raise HTTPException(404, "Organization not found")
        organization.updated_by = actor.user_id
        row = await db.execute(
            select(PlatformAddonProduct, PlatformFeature)
            .join(PlatformFeature, PlatformFeature.id == PlatformAddonProduct.feature_id)
            .where(
                PlatformAddonProduct.code == body.product_code,
                PlatformAddonProduct.active,
                PlatformFeature.key == "module.appointment_widget",
                PlatformFeature.active,
            )
        )
        product, feature = row.one_or_none() or (None, None)
        if product is None or feature is None:
            raise HTTPException(422, "Select an active Appointment Widget pricing product")
        addon = await db.scalar(
            select(PlatformTenantAddon).where(
                PlatformTenantAddon.organization_id == identifier,
                PlatformTenantAddon.feature_id == feature.id,
            )
        )
        if addon is None:
            addon = PlatformTenantAddon(
                organization_id=identifier,
                feature_id=feature.id,
                created_by=actor.user_id,
                updated_by=actor.user_id,
            )
            db.add(addon)
        addon.status = "active"
        addon.product_id = product.id
        addon.quantity = product.quantity
        addon.unit_price_cents = product.price_cents
        addon.discount_basis_points = body.discount_basis_points
        addon.currency = product.currency
        addon.addon_metadata = {
            **(addon.addon_metadata or {}),
            "product_code": product.code,
            "allowed_origins": product.quantity,
            "interval": product.interval,
            "reason": body.reason,
        }
        addon.updated_by = actor.user_id

        gross = product.price_cents
        discount = gross * body.discount_basis_points // 10000
        ledger = PlatformCommercialLedgerEntry(
            organization_id=identifier,
            kind="appointment_widget_addon",
            description=product.name,
            gross_amount_cents=gross,
            discount_cents=discount,
            net_amount_cents=gross - discount,
            currency=product.currency,
            status="discounted" if gross == discount else "open",
            reference=f"widget-addon:{identifier}:{uuid4()}",
            entry_metadata={
                "feature_key": feature.key,
                "product_id": product.id,
                "product_code": product.code,
                "quantity": product.quantity,
                "interval": product.interval,
                "discount_basis_points": body.discount_basis_points,
                "reason": body.reason,
            },
            created_by=actor.user_id,
            updated_by=actor.user_id,
        )
        db.add(ledger)
        await db.flush()
        platform_audit(
            db,
            actor.user_id,
            "billing.addon.appointment-widget.assign",
            organization_id=identifier,
            reason=body.reason,
            details={
                "addon_id": addon.id,
                "ledger_entry_id": ledger.id,
                "quantity": product.quantity,
                "gross_amount_cents": gross,
                "discount_cents": discount,
                "net_amount_cents": gross - discount,
            },
        )
        return {
            "addon_id": addon.id,
            "feature_key": feature.key,
            "product": _addon_product_payload(product, feature),
            "allowed_origins": product.quantity,
            "booking_enabled": organization.booking_enabled,
            "activation_requirement": (
                None
                if organization.booking_enabled
                else "Enable Online Appointment Booking in Tenant routing before the widget can be activated."
            ),
            "ledger_entry": {
                "id": ledger.id,
                "gross_amount_cents": gross,
                "discount_cents": discount,
                "net_amount_cents": gross - discount,
                "currency": product.currency,
                "status": ledger.status,
            },
        }


@router.get("/platform/organizations/{identifier}/billing/ledger")
async def platform_organization_billing_ledger(
    identifier: str,
    months: int = Query(default=12, ge=1, le=60),
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.subscription_record.read")),
):
    """Return the DHMIS SaaS commercial ledger, never clinical patient invoices."""
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

        commercial_entries = (
            await db.scalars(
                select(PlatformCommercialLedgerEntry)
                .where(PlatformCommercialLedgerEntry.organization_id == identifier)
                .order_by(PlatformCommercialLedgerEntry.created_at.desc())
            )
        ).all()

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
    month_entry_counts = [0] * len(month_keys)
    for entry in commercial_entries:
        created_at = entry.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        key = (created_at.year, created_at.month)
        month_index = month_lookup.get(key)
        if month_index is None:
            continue
        if entry.status != "scheduled":
            month_totals[month_index] += int(entry.net_amount_cents)
        month_entry_counts[month_index] += 1

    return {
        "months": [
            {
                "month": f"{year:04d}-{month:02d}",
                "amount_cents": month_totals[index],
                "invoice_count": month_entry_counts[index],
            }
            for index, (year, month) in enumerate(month_keys)
        ],
        "invoices": [
            {
                "id": entry.id,
                "created_at": entry.created_at,
                "amount_cents": entry.net_amount_cents,
                "paid_cents": entry.net_amount_cents if entry.status == "paid" else 0,
                "status": entry.status,
                "description": entry.description,
                "gross_amount_cents": entry.gross_amount_cents,
                "discount_cents": entry.discount_cents,
                "currency": entry.currency,
                "reference": entry.reference,
                "reversal_of_entry_id": entry.reversal_of_entry_id,
            }
            for entry in commercial_entries
        ],
        "commercial_entries": [
            {
                "id": entry.id,
                "created_at": entry.created_at,
                "kind": entry.kind,
                "description": entry.description,
                "gross_amount_cents": entry.gross_amount_cents,
                "discount_cents": entry.discount_cents,
                "net_amount_cents": entry.net_amount_cents,
                "currency": entry.currency,
                "status": entry.status,
                "reference": entry.reference,
                "reversal_of_entry_id": entry.reversal_of_entry_id,
            }
            for entry in commercial_entries
        ],
    }


async def _revoke_commercial_access(
    db,
    *,
    organization: Organization,
    account: PlatformCommercialAccount,
    actor_id: str,
    reason: str,
) -> None:
    """Suspend tenant application access without ever deleting accounting data."""
    organization.status = "suspended"
    organization.updated_by = actor_id
    account.account_status = "suspended"
    account.subscription_status = "canceled"
    account.commercial_metadata = {
        **(account.commercial_metadata or {}),
        "access_revoked_at": datetime.now(UTC).isoformat(),
        "access_revocation_reason": reason,
    }
    account.updated_by = actor_id
    requests = (
        await db.scalars(
            select(OrganizationDomainRequest).where(
                OrganizationDomainRequest.organization_id == organization.id,
                OrganizationDomainRequest.status.in_(("active", "pending_verification", "pending_propagation")),
            )
        )
    ).all()
    for request in requests:
        request.status = "suspended"
        request.suspension_at = datetime.now(UTC)
        request.canonical = False
        request.updated_by = actor_id
        hosts = (await db.scalars(select(OrganizationDomainHost).where(OrganizationDomainHost.request_id == request.id))).all()
        for host in hosts:
            host.routing_status = "suspended"
            host.updated_by = actor_id
        db.add(OrganizationDomainEvent(
            request_id=request.id,
            event_type="commercial_access_revoked",
            details={"reason": reason},
            created_by=actor_id,
            updated_by=actor_id,
        ))


@router.post("/platform/organizations/{identifier}/refunds", status_code=201)
async def refund_platform_commercial_entry(
    identifier: str,
    body: CommercialRefundInput,
    actor: PlatformActor = Depends(permit_platform_or_bootstrap("commercial.subscription_record.update", workflow_handles_approval=True)),
):
    """Append an immutable refund adjustment and revoke the approved scope."""
    async with control_session() as db:
        organization = await db.get(Organization, identifier)
        account = await db.scalar(select(PlatformCommercialAccount).where(PlatformCommercialAccount.organization_id == identifier))
        if organization is None or account is None:
            raise HTTPException(404, "Organization commercial account not found")
        prior = await db.scalar(
            select(PlatformCommercialLedgerEntry).where(
                PlatformCommercialLedgerEntry.organization_id == identifier,
                PlatformCommercialLedgerEntry.id == body.ledger_entry_id,
            )
        )
        if prior is None or prior.net_amount_cents <= 0:
            raise HTTPException(422, "Select a positive commercial charge to refund")
        duplicate = await db.scalar(
            select(PlatformCommercialLedgerEntry).where(
                PlatformCommercialLedgerEntry.reference == f"refund:{body.idempotency_key}"
            )
        )
        if duplicate:
            return {"ledger_entry": jsonable_encoder({"id": duplicate.id, "status": duplicate.status, "net_amount_cents": duplicate.net_amount_cents}), "idempotent": True}
        previously_refunded = await db.scalar(
            select(func.coalesce(func.sum(PlatformCommercialLedgerEntry.net_amount_cents), 0)).where(
                PlatformCommercialLedgerEntry.reversal_of_entry_id == prior.id
            )
        ) or 0
        refundable = prior.net_amount_cents + int(previously_refunded)
        if body.amount_cents > refundable:
            raise HTTPException(422, f"Refund exceeds remaining refundable amount ({refundable} cents)")
        refund = PlatformCommercialLedgerEntry(
            organization_id=identifier,
            kind="refund",
            description=f"Refund: {prior.description}",
            gross_amount_cents=-body.amount_cents,
            discount_cents=0,
            net_amount_cents=-body.amount_cents,
            currency=prior.currency,
            status="refunded",
            reference=f"refund:{body.idempotency_key}",
            reversal_of_entry_id=prior.id,
            entry_metadata={
                "reason": body.reason,
                "internal_note": body.internal_note,
                "revoke_scope": body.revoke_scope,
                "original_reference": prior.reference,
            },
            created_by=actor.user_id,
            updated_by=actor.user_id,
        )
        db.add(refund)
        if body.revoke_scope == "tenant":
            await _revoke_commercial_access(db, organization=organization, account=account, actor_id=actor.user_id, reason=body.reason)
            subscription = await db.scalar(select(PlatformSubscription).where(PlatformSubscription.organization_id == identifier))
            if subscription:
                subscription.status = "canceled"
                subscription.cancel_at_period_end = False
                subscription.updated_by = actor.user_id
        else:
            feature_key = str((prior.entry_metadata or {}).get("feature_key") or "")
            addon = await db.scalar(
                select(PlatformTenantAddon)
                .join(PlatformFeature, PlatformFeature.id == PlatformTenantAddon.feature_id)
                .where(PlatformTenantAddon.organization_id == identifier, PlatformFeature.key == feature_key)
            )
            if addon:
                addon.status = "canceled"
                addon.updated_by = actor.user_id
        await db.flush()
        platform_audit(db, actor.user_id, "billing.commercial.refund", organization_id=identifier, details={"refund_entry_id": refund.id, "reversal_of_entry_id": prior.id, "amount_cents": body.amount_cents, "scope": body.revoke_scope})
        return {"ledger_entry": jsonable_encoder({"id": refund.id, "status": refund.status, "net_amount_cents": refund.net_amount_cents, "reversal_of_entry_id": prior.id}), "idempotent": False}


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
        if body.status != "canceled" and plan.configuration_status != "validated":
            raise HTTPException(422, "The selected plan has not passed configuration preflight")
        account = await db.scalar(select(PlatformCommercialAccount).where(PlatformCommercialAccount.organization_id == identifier))
        if account is None:
            account = PlatformCommercialAccount(organization_id=identifier, created_by=actor.user_id, updated_by=actor.user_id)
            db.add(account)
        subscription = await db.scalar(select(PlatformSubscription).where(PlatformSubscription.organization_id == identifier))
        previous_plan_id = subscription.plan_id if subscription else None
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
        if previous_plan_id != plan.id:
            db.add(
                PlatformCommercialLedgerEntry(
                    organization_id=identifier,
                    kind="plan_assignment",
                    description=f"{plan.name} plan · {plan.interval}",
                    gross_amount_cents=plan.price_cents,
                    discount_cents=0,
                    net_amount_cents=plan.price_cents,
                    currency=plan.currency,
                    status="scheduled" if body.status == "trialing" else "open",
                    reference=f"plan-assignment:{identifier}:{uuid4()}",
                    entry_metadata={"plan_id": plan.id, "plan_code": plan.code, "subscription_status": body.status},
                    created_by=actor.user_id,
                    updated_by=actor.user_id,
                )
            )
        if body.status == "canceled" and not body.cancel_at_period_end:
            await _revoke_commercial_access(
                db,
                organization=organization,
                account=account,
                actor_id=actor.user_id,
                reason="Subscription cancelled",
            )
            db.add(
                PlatformCommercialLedgerEntry(
                    organization_id=identifier,
                    kind="subscription_cancellation",
                    description=f"Subscription cancelled: {plan.name}",
                    gross_amount_cents=0,
                    discount_cents=0,
                    net_amount_cents=0,
                    currency=plan.currency,
                    status="canceled",
                    reference=f"subscription-cancellation:{identifier}:{uuid4()}",
                    entry_metadata={"plan_id": plan.id, "plan_code": plan.code},
                    created_by=actor.user_id,
                    updated_by=actor.user_id,
                )
            )
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


# Retrieve platform password policy while applying the existing permission gate.
@router.get("/platform/settings/password-policy")
async def get_platform_password_policy(
    actor: PlatformActor = Depends(
        permit_platform_or_bootstrap("security.password_policy.read")
    ),
):
    async with control_session() as db:
        row = await platform_configuration(db)
        platform_audit(db, actor.user_id, "platform-password-policy.read")
        return PasswordPolicy(**row.password_policy).model_dump()


@router.put("/platform/settings/password-policy")
async def set_platform_password_policy(
    body: PasswordPolicy,
    actor: PlatformActor = Depends(
        permit_platform_or_bootstrap("security.password_policy.update")
    ),
):
    async with control_session() as db:
        row = await platform_configuration(db)
        row.password_policy = body.model_dump()
        row.updated_by = actor.user_id
        platform_audit(db, actor.user_id, "platform-password-policy.configure")
        return row.password_policy


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
        row.communication_templates = {**row.communication_templates, key: body.as_storage()}
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
            target_url = payload.get("target_url")
            # Older password-reset/invitation outbox rows predate the explicit
            # notification target. Recover the one-time path from the stored
            # message body so historical bell entries remain actionable.
            if not target_url:
                body_text = str(payload.get("body") or "")
                match = re.search(r"(?:https?://[^\s\"<>]+)?/admin/\?(reset|invite)=([^\s\"<>]+)", body_text)
                if match:
                    action, token = match.groups()
                    target_url = f"/admin/?{action}={quote(token.rstrip('.,);]'), safe='')}"
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
                "target_url": target_url,
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
        expires_in, expires_label = invitation_expiry(
            (await platform_configuration(db)).default_policy
        )
        row = PlatformInvite(
            name=body.name,
            email=body.email.lower(),
            role=role.id,
            token_hash=digest(raw),
            expires=int(time.time()) + expires_in,
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
                "invitation_expires_in": expires_label,
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
        expires_in, expires_label = invitation_expiry(
            (await platform_configuration(db)).default_policy
        )
        replacement = PlatformInvite(
            name=invitation.name,
            email=invitation.email,
            role=invitation.role,
            token_hash=digest(raw),
            expires=int(time.time()) + expires_in,
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
                "invitation_expires_in": expires_label,
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
            row.mode = body.mode
            row.active = body.active
            row.updated_by = actor.user_id
        platform_audit(
            db,
            actor.user_id,
            "adapter-default.configure",
            details={
                "region": body.region,
                "capability": body.capability,
                "provider_name": body.provider_name,
                "mode": body.mode,
                "active": body.active,
            },
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
            raise HTTPException(403, {"message": "Permission denied", "required_permissions": [permission_key]})
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
        # Plan-owned patient-facing experiences are not mutable routing
        # checkboxes. They change only through a validated commercial plan.
        # Booking is intentionally different: after a Widget purchase a tenant
        # operator must explicitly enable it in this workspace.
        if body.front_office_enabled != row.front_office_enabled or body.patient_portal_enabled != row.patient_portal_enabled:
            raise HTTPException(422, "Tenant Website and Patient Portal are controlled by the assigned plan")
        if body.domains != row.domains:
            raise HTTPException(422, "Use the domain routing lifecycle to request or change a custom domain")
        if body.booking_enabled and not row.booking_enabled:
            widget_feature = await db.scalar(
                select(PlatformTenantAddon.id)
                .join(PlatformFeature, PlatformFeature.id == PlatformTenantAddon.feature_id)
                .where(
                    PlatformTenantAddon.organization_id == identifier,
                    PlatformTenantAddon.status == "active",
                    PlatformFeature.key == "module.appointment_widget",
                )
            )
            plan_booking = await db.scalar(
                select(PlatformPlanFeature.id)
                .join(PlatformSubscription, PlatformSubscription.plan_id == PlatformPlanFeature.plan_id)
                .join(PlatformFeature, PlatformFeature.id == PlatformPlanFeature.feature_id)
                .where(
                    PlatformSubscription.organization_id == identifier,
                    PlatformSubscription.status.in_(("trialing", "active", "past_due")),
                    PlatformPlanFeature.enabled,
                    PlatformFeature.key == "capability.appointment_booking",
                )
            )
            if not widget_feature and not plan_booking:
                raise HTTPException(422, "Online Appointment Booking requires a booking-capable plan or active Appointment Widget purchase")
        row.slug = body.slug
        row.booking_enabled = body.booking_enabled
        row.updated_by = actor.user_id
        platform_audit(db, actor.user_id, "organization.routing", organization_id=row.id, details={"booking_enabled": row.booking_enabled})
        return {"slug": row.slug, "booking_enabled": row.booking_enabled, "front_office_enabled": row.front_office_enabled, "patient_portal_enabled": row.patient_portal_enabled, "domains": row.domains}


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
            raise HTTPException(403, {"message": "Permission denied", "required_permissions": [permission_key]})
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
                    tenant_slug=organization.slug,
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


# Handle tenant administrator invitation reset for this module.
@router.post("/platform/organizations/{identifier}/tenantInviteReset")
async def reset_tenant_administrator_invitation(
    identifier: str,
    body: TenantInvitationResetAction,
    actor: PlatformActor = Depends(platform_tenant_invitation_reset_actor),
):
    """Replace only the latest expired, unused organization-administrator invite.

    Platform Admin may initiate the recovery and receive its audit result, but
    never receives the replacement's bearer-token invitation URL. The email is
    rendered and delivered from the selected tenant schema.
    """

    async with control_session() as db:
        organization = await db.get(Organization, identifier)
    if organization is None:
        raise HTTPException(404, "Organization not found")

    permission_key = "support.password_recovery.initiate_password_reset"
    staff_email = body.staff_email.lower()
    runtime_payload = {
        "organization_id": identifier,
        "staff_email": staff_email,
        "action": "invitation_reset",
        "reason": body.reason,
    }
    approval = None
    async with control_session() as control_db:
        decision = await decide_platform(control_db, actor.user_id, permission_key)
        if not decision.allowed or decision.needs_step_up:
            raise HTTPException(403, {"message": "Permission denied", "required_permissions": [permission_key]})
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
                    "organization.admin-invitation-reset.approval-requested",
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
            invitation = await db.scalar(
                select(StaffInvite)
                .where(StaffInvite.email == staff_email)
                .order_by(StaffInvite.created_at.desc(), StaffInvite.id.desc())
                .with_for_update()
            )
            if invitation is None:
                raise HTTPException(404, "Expired unused organization administrator invitation not found")

            assignments = await invite_assignments(db, invitation)
            if not any(item.scope == "organization" for item in assignments):
                raise HTTPException(404, "Expired unused organization administrator invitation not found")

            now = int(time.time())
            if invitation.used or invitation.expires > now:
                raise HTTPException(409, "Only expired unused organization administrator invitations can be reset")
            # An invitation can reach its timestamp before a list request marks
            # its compatibility status as expired. Record that transition before
            # preserving it as the predecessor of the replacement.
            invitation.status = "expired"
            invitation.used = True
            invitation.updated_by = actor.user_id
            for item in assignments:
                item.status = "expired"
                item.updated_by = actor.user_id

            raw = secrets.token_urlsafe(32)
            runtime = await tenant_settings(db)
            expires_in, expires_label = invitation_expiry(runtime.policy)
            replacement = await add(
                db,
                StaffInvite,
                {
                    "name": invitation.name,
                    "email": invitation.email,
                    "role": invitation.role,
                    "is_provider": invitation.is_provider,
                    "location_ids": invitation.location_ids,
                    "token_hash": digest(raw),
                    "expires": now + expires_in,
                    "status": "pending",
                    "resend_count": invitation.resend_count + 1,
                    "supersedes_id": invitation.id,
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
                    for item in assignments
                ]
            )
            template = runtime.communication_templates["staff-invitation"]
            expires_at = format_recipient_datetime(replacement.expires, await recipient_timezone(db, replacement))
            email_template = next((content for channel, content in communication_template_deliveries(template) if channel == "email"), None)
            if email_template is None:
                raise HTTPException(422, "Staff invitation requires an active email template")
            subject, message_body = render_communication_template(
                email_template,
                {
                    "recipient_name": replacement.name,
                    "clinic_name": organization.name,
                    "role": replacement.role.replace("_", " "),
                    "tenant_slug": organization.slug,
                    "platform_name": "DHMIS Platform",
                    "invitation_expires_at": expires_at,
                    "invitation_expires_in": expires_label,
                    "invitation_link": staff_invitation_url(raw, organization.slug),
                },
            )
            delivery_actor = Actor(
                actor.user_id,
                organization,
                actor.name,
                "platform",
                settings=runtime,
                adapter_names=await attach_effective_adapters(organization),
                assignment_scope="organization",
            )
            await deliver_message_now(
                db,
                delivery_actor,
                OutboxMessage(
                    kind="staff.invitation",
                    payload={
                        "destination": replacement.email,
                        "subject": subject,
                        "body": message_body,
                        "channel": "email",
                        "user_id": replacement.id,
                    },
                    idempotency_key=f"staff-invitation:{replacement.id}",
                    created_by=actor.user_id,
                    updated_by=actor.user_id,
                ),
            )
            audit(
                db,
                actor.user_id,
                "platform.invite.reset",
                "staff",
                replacement.id,
                supersedes_id=invitation.id,
                reason=body.reason,
            )

        if approval:
            await complete_runtime_action(
                approval,
                {"resource": "staff_invitation", "resource_id": replacement.id},
            )
        platform_audit(
            control_db,
            actor.user_id,
            "organization.admin-invitation-reset",
            organization_id=identifier,
            reason=body.reason,
            details={
                "staff_email": staff_email,
                "invite_id": replacement.id,
                "approval_request_id": approval.id if approval else None,
            },
        )
    return {"status": "completed", "action": "invitation_reset", "invite_id": replacement.id, "expires_in": expires_in}


# Handle accept invite for this module.
@router.post("/auth/invites/accept")
async def accept_invite(body: AcceptInvite):
    if not await throttle("invite:" + digest(body.token)):
        raise HTTPException(429, "Try again later")
    org = await organization_from_login(body.organization_id, body.tenant_slug)
    async with organization_session(org) as db:
        policy = PasswordPolicy(**(await tenant_settings(db)).policy.get("password_policy", {}))
        password_error = validate_password(body.password, policy)
        if password_error:
            raise HTTPException(422, password_error)
        invitation = await db.scalar(
            select(StaffInvite).where(StaffInvite.token_hash == digest(body.token)).with_for_update()
        )
        if invitation is None or invitation.used:
            raise HTTPException(401, "Invalid invitation")
        if invitation.expires < int(time.time()):
            raise HTTPException(401, "Expired invitation link. Kindly contact your Admin for support")
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
                "password_changed_at": datetime.now(UTC),
            },
            "invitation",
        )
        primary_role = await db.scalar(
            select(TenantRole).where(
                TenantRole.name == pending_assignments[0].role,
                TenantRole.status == "published",
            )
        )
        if primary_role is not None:
            user.role = primary_role.name
            user.role_id = primary_role.id
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
        canonical_roles = []
        for item in pending_assignments:
            role = await db.scalar(
                select(TenantRole).where(
                    TenantRole.name == item.role,
                    TenantRole.status == "published",
                )
            )
            if role is None:
                raise HTTPException(422, "The invited role is no longer available")
            canonical_roles.append(
                TenantRoleAssignment(
                    user_id=user.id,
                    role_id=role.id,
                    level="Organization" if item.scope == "organization" else "Location",
                    location_id=item.location_id,
                    created_by=user.id,
                    updated_by=user.id,
                )
            )
        db.add_all(canonical_roles)
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
    return await invite(
        db,
        body,
        actor.user_id,
        actor.organization.name,
        delivery_actor=actor,
        tenant_slug=actor.organization.slug,
    )


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


async def canonical_staff_assignments(db, user_id: str) -> list[dict]:
    """Return published RBAC assignments for a staff member for display."""
    rows = (
        await db.execute(
            select(
                TenantRoleAssignment.id,
                TenantRoleAssignment.role_id,
                TenantRoleAssignment.level,
                TenantRoleAssignment.location_id,
                TenantRole.name,
            )
            .join(TenantRole, TenantRole.id == TenantRoleAssignment.role_id)
            .where(
                TenantRoleAssignment.user_id == user_id,
                TenantRole.status == "published",
            )
            .order_by(
                TenantRoleAssignment.level,
                TenantRoleAssignment.location_id,
                TenantRoleAssignment.id,
            )
        )
    ).all()
    return [
        {
            "id": assignment_id,
            "role_id": role_id,
            "scope": level.lower(),
            "location_id": location_id,
            "role": role_name,
        }
        for assignment_id, role_id, level, location_id, role_name in rows
    ]


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
            display_assignments = await canonical_staff_assignments(db, row.id)
            if not display_assignments:
                display_assignments = [
                    {
                        "id": item.id,
                        "scope": item.scope,
                        "location_id": item.location_id,
                        "role": item.role,
                    }
                    for item in assignments
                ]
            primary_display = next(
                (
                    item
                    for item in display_assignments
                    if item.get("role_id") == row.role_id
                ),
                next(
                    (
                        item
                        for item in display_assignments
                        if item.get("role") == "Tenant Super Admin"
                    ),
                    display_assignments[0] if display_assignments else None,
                ),
            )
            items.append(
                {
                    "id": row.id,
                    "name": row.name,
                    "email": row.email,
                    "role": primary_display["role"] if primary_display else row.role,
                    "is_provider": row.is_provider,
                    "location_ids": row.location_ids,
                    "assignments": display_assignments,
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
    runtime = await tenant_settings(db)
    expires_in, expires_label = invitation_expiry(runtime.policy)
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
            "expires": int(time.time()) + expires_in,
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
    template = runtime.communication_templates["staff-invitation"]
    expires_at = format_recipient_datetime(replacement.expires, await recipient_timezone(db, replacement))
    email_template = next((content for channel, content in communication_template_deliveries(template) if channel == "email"), None)
    if email_template is None:
        raise HTTPException(422, "Staff invitation requires an active email template")
    subject, message_body = render_communication_template(
        email_template,
        {
            "recipient_name": replacement.name,
            "clinic_name": actor.organization.name,
            "role": replacement.role.replace("_", " "),
            "tenant_slug": actor.organization.slug,
            "platform_name": "DHMIS Platform",
            "invitation_expires_at": expires_at,
            "invitation_expires_in": expires_label,
            "invitation_link": staff_invitation_url(raw, actor.organization.slug),
        },
    )
    await deliver_message_now(db, actor, OutboxMessage(
            kind="staff.invitation",
            payload={
                "destination": replacement.email,
                "subject": subject,
                "body": message_body,
                "channel": "email",
                "user_id": replacement.id,
            },
            idempotency_key=f"staff-invitation:{replacement.id}",
            created_by=actor.user_id,
            updated_by=actor.user_id,
        ))
    audit(db, actor.user_id, "invite.resend", "staff", replacement.id, supersedes_id=prior.id)
    return {"invite_id": replacement.id, "token": raw, "invitation_link": staff_invitation_url(raw, actor.organization.slug), "expires_in": expires_in}


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
        tenant_slug=actor.organization.slug,
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


async def _discount_permission_allowed(request: Request, db, actor: Actor, permission_key: str) -> bool:
    """Evaluate a granular discount permission while preserving the settings route."""
    decision = await decide_tenant(
        db,
        actor.user_id,
        permission_key,
        selected_location_id=actor.selected_location_id,
        current_ip=request.client.host if request.client else None,
    )
    return decision.allowed and not decision.needs_step_up and not decision.needs_approval


async def _password_policy_permission_allowed(
    request: Request, db, actor: Actor, permission_key: str
) -> bool:
    """Evaluate granular password-policy access without widening settings access."""
    decision = await decide_tenant(
        db,
        actor.user_id,
        permission_key,
        selected_location_id=actor.selected_location_id,
        current_ip=request.client.host if request.client else None,
    )
    return decision.allowed and not decision.needs_step_up and not decision.needs_approval


async def _require_discount_permissions(
    request: Request,
    db,
    actor: Actor,
    permission_keys: set[str],
) -> None:
    """Reject discount policy changes unless every required action is granted."""
    missing = [
        key
        for key in sorted(permission_keys)
        if not await _discount_permission_allowed(request, db, actor, key)
    ]
    if missing:
        raise HTTPException(403, {"message": "Discount policy permission required", "required_permissions": missing})


async def _verified_custom_domain_origin(organization_id: str) -> str | None:
    """Suggest the primary custom host only when it is not the portal host.

    A Patient Portal uses the tenant's primary hostname as an application
    route.  That hostname is never a Widget origin and must not consume the
    separately priced external-origin allowance.  Widget-only tenants may use
    their verified custom hostname as their embed origin.
    """
    async with control_session() as control_db:
        organization = await control_db.get(Organization, organization_id)
        request = await control_db.scalar(
            select(OrganizationDomainRequest)
            .where(
                OrganizationDomainRequest.organization_id == organization_id,
                OrganizationDomainRequest.mode == "custom",
                OrganizationDomainRequest.status == "active",
            )
            .order_by(OrganizationDomainRequest.activation_at.desc(), OrganizationDomainRequest.created_at.desc())
        )
    if organization is None or organization.patient_portal_enabled:
        return None
    if request is None or not request.public_hostname:
        return None
    return f"https://{normalize_hostname(request.public_hostname)}"


async def _primary_patient_origins(organization: Organization) -> set[str]:
    """Return portal hosts reserved for application routing, never Widgets."""
    if not organization.patient_portal_enabled:
        return set()
    async with control_session() as db:
        request = await db.scalar(
            select(OrganizationDomainRequest)
            .where(OrganizationDomainRequest.organization_id == organization.id)
            .order_by(OrganizationDomainRequest.created_at.desc())
        )
    hostname = request.public_hostname if request else f"{organization.slug}.dhmis.test"
    return {f"https://{normalize_hostname(hostname)}"} if hostname else set()


# Retrieve get settings for the current request or workflow.
@router.get("/organization/settings")
async def get_settings(request: Request, db=Depends(db_session), actor=Depends(permit("settings"))):
    row = await tenant_settings(db)
    entitlements = await resolve_entitlements(actor.organization.id)
    widget_entitlement = entitlements.get("module.appointment_widget")
    origin_limit = entitlements.get("limit.appointment_widget_origins") or {}
    policy = Policy(**row.policy).model_dump()
    if not await _discount_permission_allowed(request, db, actor, "billing.discount.read"):
        policy["discounts"] = []
    if not await _password_policy_permission_allowed(
        request, db, actor, "security.password_policy.read"
    ):
        # Keep the existing settings DTO shape for clients that render the
        # settings form, while withholding the tenant's configured policy.
        policy["password_policy"] = PasswordPolicy().model_dump()
    widget_settings = {
        "mode": "button",
        "accent_color": "#356b5d",
        "text_color": "#14231c",
        "background_color": "#f3f6f4",
        "surface_color": "#ffffff",
        "border_color": "#d8e3de",
        "font_family": "inherit",
        "font_url": "",
        "button_label": "Book an appointment",
        "title": "Book an appointment",
        "description": "Choose a time that works for you.",
        "success_message": "Your appointment request has been received.",
        "button_width": "auto",
        "button_height": 48,
        "button_radius": 8,
        "button_font_size": 16,
        "button_font_weight": "700",
        "panel_width": 680,
        "panel_radius": 14,
        "panel_padding": 20,
        "default_location_id": "",
        "allowed_location_ids": [],
        "allowed_service_ids": [],
        "allowed_provider_ids": [],
        "allowed_origins": [],
        **(row.booking_widget or {}),
    }

    widget_settings["origin_verifications"] = [
        _public_origin_verification(item) for item in (row.booking_widget or {}).get("origin_verifications") or []
    ]
    widget_settings["approval_request"] = _widget_request_record(row.booking_widget)
    widget_settings["entitled"] = bool(widget_entitlement and widget_entitlement.get("enabled"))
    widget_settings["allowed_origin_limit"] = (
        20 if origin_limit.get("unlimited") else int(origin_limit.get("value") or 1)
    )
    widget_settings["suggested_origin"] = await _verified_custom_domain_origin(actor.organization.id)
    return {
        "visibility": row.visibility,
        "branding": row.branding,
        "logo_url": row.logo_url or DEFAULT_LOGO_URL,
        "policy": policy,
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
        "booking_widget": widget_settings,
    }


@router.get("/organization/booking-widget/embed")
async def booking_widget_embed(request: Request, db=Depends(db_session), actor=Depends(permit("settings"))):
    """Return a copyable, origin-independent embed snippet for the saved mode.

    The script is served by the API origin rather than the tenant-web app. This
    lets tenants embed it in an independently hosted website while the API
    continues to enforce entitlement and verified-origin checks.
    """
    runtime = await tenant_settings(db)
    config = runtime.booking_widget or {}
    approval = _widget_request_record(config)
    organization_id = actor.organization.id
    mode = config.get("mode", "button")
    api_origin = str(request.base_url).rstrip("/")
    script_url = f"{api_origin}/widgets/appointments.js"
    api_base = f"{api_origin}/v1/widgets/appointments"
    script_attrs = f'data-api-base="{api_base}" data-organization-id="{organization_id}"'
    if mode == "div":
        snippet = (
            '<div id="dhmis-booking-widget"></div>\n'
            f'<script src="{script_url}" {script_attrs} '
            'data-target="#dhmis-booking-widget" data-mode="div"></script>'
        )
    elif mode == "iframe":
        snippet = f'<script src="{script_url}" {script_attrs} data-mode="iframe"></script>'
    else:
        snippet = f'<script src="{script_url}" {script_attrs} data-mode="button"></script>'
    return {
        "mode": mode,
        "organization_id": organization_id,
        "script_url": script_url,
        "api_base": api_base,
        "snippet": snippet if approval.get("status") == "approved" else "",
        "approval_status": approval.get("status"),
        "updated_at": runtime.updated_at.isoformat() if runtime.updated_at else None,
    }


def _public_origin_verification(item: dict) -> dict:
    method = item.get("verification_method", "dns")
    return {
        "origin": item.get("origin", ""),
        "dns_name": item.get("dns_name", ""),
        "record_type": "ADMIN" if method == "admin" else ("HTTP" if method == "http" else "TXT"),
        "record_value": "" if method == "admin" else (item.get("token", "") if method == "http" else (f"dhmis-widget={item.get('token', '')}" if item.get("token") else "")),
        "verification_url": item.get("verification_url"),
        "verified_at": item.get("verified_at"),
        "verified_by": item.get("verified_by"),
    }


@router.get("/organization/booking-widget/origins")
async def list_booking_widget_origins(db=Depends(db_session), actor=Depends(permit("settings"))):
    config = (await tenant_settings(db)).booking_widget or {}
    return {"items": [_public_origin_verification(item) for item in config.get("origin_verifications") or []]}


@router.post("/organization/booking-widget/request", status_code=201)
async def request_booking_widget(
    body: BookingWidgetOriginInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    """Request widget activation and origin approval after purchasing the add-on."""
    entitlements = await resolve_entitlements(actor.organization.id)
    entitlement = entitlements.get("module.appointment_widget")
    if not entitlement or not entitlement.get("enabled"):
        raise HTTPException(402, "Purchase or enable the appointment widget add-on before requesting approval")
    if not actor.organization.booking_enabled:
        raise HTTPException(
            409,
            "Enable Online Appointment Booking in Tenant routing before requesting widget approval",
        )
    try:
        origin = normalize_widget_origin(body.origin)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if origin in await _primary_patient_origins(actor.organization):
        raise HTTPException(
            422,
            "The Patient Portal primary hostname is an application route, not an Appointment Widget origin. Submit an external website origin instead.",
        )
    runtime = await tenant_settings(db)
    current = runtime.booking_widget or {}
    approval = _widget_request_record(current)
    current_origin = approval.get("origin", "")
    current_status = approval.get("status")
    prior_approved_origin = approval.get("previous_origin") or (current_origin if current_status == "approved" else "")
    if current_status == "approved" and origin == current_origin:
        return {"status": "approved", "origin": current_origin}
    if current_status == "pending":
        if origin == approval.get("origin"):
            return {
                "status": "pending",
                "origin": approval.get("origin", ""),
                "requested_at": approval.get("requested_at"),
            }
        raise HTTPException(409, "A widget domain request is already awaiting platform approval")
    origin_limit_entitlement = entitlements.get("limit.appointment_widget_origins") or {}
    origin_limit = 20 if origin_limit_entitlement.get("unlimited") else int(origin_limit_entitlement.get("value") or 1)
    approved_origins = list(dict.fromkeys(current.get("allowed_origins") or []))
    is_additional = current_status == "approved" and origin not in approved_origins and len(approved_origins) < origin_limit
    if current_status == "approved" and origin not in approved_origins and len(approved_origins) >= origin_limit and origin_limit > 1:
        raise HTTPException(
            409,
            f"This widget allows {origin_limit} approved website origin(s). Purchase another origin allowance before adding one.",
        )
    is_domain_change = (
        current_status == "approved" and origin not in approved_origins and not is_additional
    ) or (current_status == "rejected" and approval.get("request_type") == "domain_change")
    request_type = "additional" if is_additional else ("domain_change" if is_domain_change else "initial")
    now = datetime.now(UTC).isoformat()
    records = list(current.get("origin_verifications") or [])
    record = next((item for item in records if item.get("origin") == origin), None)
    if record is None:
        record = _widget_origin_record(origin)
        records.append(record)
    booking_widget = {
        **current,
        "approval_request": {
            "status": "pending",
            "origin": origin,
            "requested_at": now,
            "approved_at": None,
            "approved_by": None,
            "rejection_reason": "",
            "request_type": request_type,
            "previous_origin": prior_approved_origin if is_domain_change else None,
        },
        # Keep the previous origin as history, but remove every allowed origin
        # while the replacement is being reviewed. This immediately disables
        # the existing embed until the platform approves the new origin.
        "origin_verifications": records,
        "allowed_origins": approved_origins if is_additional else [],
    }
    await configure_tenant(db, actor_id=actor.user_id, booking_widget=booking_widget)
    audit_action = "booking-widget.domain-change.request" if is_domain_change else "booking-widget.request"
    audit(
        db,
        actor.user_id,
        audit_action,
        "organization",
        actor.organization.id,
        origin=origin,
        previous_origin=prior_approved_origin if is_domain_change else None,
        request_type=request_type,
    )
    # The notification uses the same database transaction as the tenant
    # settings update. A failed request therefore cannot leave a stale task
    # in the platform bell.
    commercial = await _commercial_summary(db, actor.organization.id, actor.organization.plan)
    platform_audit(
        db,
        actor.user_id,
        "organization.booking-widget.domain-change.request" if is_domain_change else "organization.booking-widget.request",
        organization_id=actor.organization.id,
        details={
            "origin": origin,
            "previous_origin": prior_approved_origin if is_domain_change else None,
            "request_type": request_type,
            "plan_code": commercial["plan_code"],
            "plan_name": commercial["plan_name"],
            "subscription_status": commercial["subscription_status"],
        },
    )
    enqueue_platform_notification(
        db,
        kind="booking-widget.requested",
        reference_id=f"{actor.organization.id}:{now}",
        actor_id=actor.user_id,
        payload={
            "organization_id": actor.organization.id,
            "organization_name": actor.organization.name,
            "slug": actor.organization.slug,
            "origin": origin,
            "plan_code": commercial["plan_code"],
            "plan_name": commercial["plan_name"],
            "subscription_status": commercial["subscription_status"],
            "detail": (
                f"{actor.organization.name} requested a widget domain change from {prior_approved_origin} to {origin}; "
                "the existing widget is disabled until approval"
                if is_domain_change
                else f"{actor.organization.name} requested widget approval for {origin}"
            ) + f" · {commercial['plan_name'] or commercial['plan_code'] or 'No plan'} · {commercial['subscription_status'] or 'No subscription'}",
            "cta_label": "Review widget request",
            "target_url": "/admin/onboarding/",
        },
    )
    return {
        "status": "pending",
        "origin": origin,
        "requested_at": now,
        "request_type": request_type,
        "previous_origin": prior_approved_origin if is_domain_change else None,
    }


@router.post("/organization/booking-widget/origins", status_code=201)
async def request_booking_widget_origin(
    body: BookingWidgetOriginInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    try:
        origin = normalize_widget_origin(body.origin)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    runtime = await tenant_settings(db)
    approval = _widget_request_record(runtime.booking_widget)
    if approval.get("status") != "approved":
        raise HTTPException(409, "The appointment widget must be approved before adding website origins")
    approved_origin = approval.get("origin", "")
    if origin != approved_origin:
        raise HTTPException(409, "This widget is locked to its approved website origin")
    record = next(
        (item for item in (runtime.booking_widget or {}).get("origin_verifications") or [] if item.get("origin") == approved_origin),
        None,
    )
    if record is None:
        raise HTTPException(409, "The approved widget origin is missing")
    return _public_origin_verification(record) | {"status": "approved" if record.get("verified_at") else "pending"}


@router.post("/organization/booking-widget/origins/verify")
async def verify_booking_widget_origin(
    body: BookingWidgetOriginInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    try:
        origin = normalize_widget_origin(body.origin)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    runtime = await tenant_settings(db)
    if _widget_request_record(runtime.booking_widget).get("status") != "approved":
        raise HTTPException(409, "The appointment widget must be approved before verifying website origins")
    records = list((runtime.booking_widget or {}).get("origin_verifications") or [])
    record = next((item for item in records if item.get("origin") == origin), None)
    if not record:
        raise HTTPException(404, "Widget origin has not been registered")
    if not record.get("verified_at"):
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
                if record.get("verification_method") == "http":
                    response = await client.get(record["verification_url"])
                    response.raise_for_status()
                    found = response.text.strip() == record["token"]
                else:
                    response = await client.get("https://dns.google/resolve", params={"name": record["dns_name"], "type": "TXT"})
                    response.raise_for_status()
                    answers = response.json().get("Answer") or []
                    expected = f'"dhmis-widget={record["token"]}"'
                    found = any(expected in str(answer.get("data", "")) for answer in answers)
            if not found:
                if record.get("verification_method") == "http":
                    raise HTTPException(409, {"message": "The HTTP verification token was not found", "verification_url": record["verification_url"], "record_value": record["token"]})
                raise HTTPException(409, {"message": "DNS TXT record was not found", "dns_name": record["dns_name"], "record_value": f"dhmis-widget={record['token']}"})
        except HTTPException:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise HTTPException(502, "DNS verification service is unavailable") from exc
        record["verified_at"] = datetime.now(UTC).isoformat()
        record["verified_by"] = actor.user_id
    booking_widget = {**(runtime.booking_widget or {}), "origin_verifications": records, "allowed_origins": [item["origin"] for item in records if item.get("verified_at")]}
    await configure_tenant(db, actor_id=actor.user_id, booking_widget=booking_widget)
    audit(db, actor.user_id, "booking-widget.origin.verify", "organization", actor.organization.id, origin=origin)
    return _public_origin_verification(record) | {"status": "verified"}


@router.delete("/organization/booking-widget/origins")
async def remove_booking_widget_origin(
    body: BookingWidgetOriginInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    try:
        origin = normalize_widget_origin(body.origin)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    runtime = await tenant_settings(db)
    approval = _widget_request_record(runtime.booking_widget)
    if approval.get("status") == "approved" and origin == approval.get("origin"):
        raise HTTPException(409, "The approved widget origin is locked and cannot be removed")
    records = [item for item in (runtime.booking_widget or {}).get("origin_verifications") or [] if item.get("origin") != origin]
    booking_widget = {**(runtime.booking_widget or {}), "origin_verifications": records, "allowed_origins": [item["origin"] for item in records if item.get("verified_at")]}
    await configure_tenant(db, actor_id=actor.user_id, booking_widget=booking_widget)
    audit(db, actor.user_id, "booking-widget.origin.remove", "organization", actor.organization.id, origin=origin)
    return {"status": "removed", "origin": origin}


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
async def set_settings(request: Request, body: OrgSettings, db=Depends(db_session), actor=Depends(permit("settings"))):
    current = await tenant_settings(db)
    current_discounts = {
        item.get("id"): item
        for item in (current.policy or {}).get("discounts", [])
        if item.get("id")
    }
    can_read_discounts = await _discount_permission_allowed(request, db, actor, "billing.discount.read")
    requested_discounts = {item.id: item.model_dump() for item in body.policy.discounts}
    # A user who cannot read discounts receives an empty projection from GET
    # settings. Preserve the stored definitions when they save an unrelated
    # practice setting instead of interpreting that projection as deletion.
    if current_discounts and not can_read_discounts and not requested_discounts:
        requested_discounts = current_discounts
    required_discount_permissions: set[str] = set()
    for identifier, item in requested_discounts.items():
        if identifier not in current_discounts:
            required_discount_permissions.add("billing.discount.create")
        elif item != current_discounts[identifier]:
            required_discount_permissions.add("billing.discount.update")
    if set(current_discounts) - set(requested_discounts):
        required_discount_permissions.add("billing.discount.archive")
    if required_discount_permissions:
        await _require_discount_permissions(request, db, actor, required_discount_permissions)
    current_password_policy = PasswordPolicy(
        **(current.policy or {}).get("password_policy", {})
    ).model_dump()
    requested_password_policy = body.policy.password_policy.model_dump()
    can_read_password_policy = await _password_policy_permission_allowed(
        request, db, actor, "security.password_policy.read"
    )
    if can_read_password_policy:
        if requested_password_policy != current_password_policy and not await _password_policy_permission_allowed(
            request, db, actor, "security.password_policy.update"
        ):
            raise HTTPException(
                403,
                {
                    "message": "Password policy update permission required",
                    "required_permissions": ["security.password_policy.update"],
                },
            )
    else:
        # Users who cannot read password policy must not be able to overwrite
        # it through the broader organization-settings payload.
        body.policy.password_policy = PasswordPolicy(**current_password_policy)
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
    if body.booking_widget:
        current_widget = current.booking_widget or {}
        current_approval_request = current_widget.get("approval_request")
        widget_status = _widget_request_record(current_widget).get("status")
        requested_widget = body.booking_widget.model_dump()
        if widget_status != "approved":
            changed_widget_keys = [
                key for key, value in requested_widget.items()
                if value != current_widget.get(key, BookingWidgetConfiguration().model_dump().get(key))
                and key not in {"allowed_origins", "origin_verifications"}
            ]
            if changed_widget_keys:
                raise HTTPException(409, "The appointment widget must be approved before its styling can be changed")
        verification_records = list(current_widget.get("origin_verifications") or [])
        verified_origins = [
            str(item.get("origin"))
            for item in verification_records
            if isinstance(item, dict) and item.get("origin") and item.get("verified_at")
        ]
        requested_origins = [normalize_widget_origin(value) for value in body.booking_widget.allowed_origins]
        if verification_records:
            # Origin access is granted only by the DNS verification workflow;
            # saving the broader settings form cannot bypass that control.
            requested_origins = verified_origins
        body.booking_widget.allowed_origins = list(dict.fromkeys(requested_origins))
        origin_limit_entitlement = (await resolve_entitlements(actor.organization.id)).get(
            "limit.appointment_widget_origins"
        ) or {}
        origin_limit = 20 if origin_limit_entitlement.get("unlimited") else int(origin_limit_entitlement.get("value") or 1)
        if len(body.booking_widget.allowed_origins) > origin_limit:
            raise HTTPException(
                422,
                f"This widget subscription allows {origin_limit} approved website origin(s).",
            )
        body.booking_widget.origin_verifications = verification_records
    payload = body.model_dump()
    if body.booking_widget and current_approval_request is not None:
        # Approval is owned by the platform workflow, so tenant settings saves
        # must carry it forward rather than allowing a form DTO to clear it.
        payload["booking_widget"]["approval_request"] = current_approval_request
        if _widget_request_record(current_widget).get("status") == "approved":
            # The approved origin is part of the entitlement grant. Styling
            # saves may change presentation fields, but cannot widen, replace,
            # or remove the origin bound to this widget.
            payload["booking_widget"]["origin_verifications"] = list(current_widget.get("origin_verifications") or [])
            payload["booking_widget"]["allowed_origins"] = list(current_widget.get("allowed_origins") or [])
    if current_discounts and not can_read_discounts and not body.policy.discounts:
        payload["policy"]["discounts"] = list(current_discounts.values())
    await configure_tenant(db, actor_id=actor.user_id, **payload)
    audit(db, actor.user_id, "configure", "organization", actor.organization.id)
    return payload


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
        key: body.as_storage(),
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
    sample_expiry = format_recipient_datetime(datetime(2026, 10, 10, 10, tzinfo=UTC),
        await recipient_timezone(db, user),
    )
    _, sample_expiry_label = invitation_expiry(runtime.policy)
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
        "invitation_expires_at": sample_expiry,
        "invitation_expires_in": sample_expiry_label,
        "invitation_link": "https://example.invalid/invitation",
        "reset_link": "https://example.invalid/password-reset",
    }
    # Test delivery only uses channels for which the signed-in staff member
    # has a stored destination. Staff records currently carry email, not a
    # phone/WhatsApp address, so email is deliberately the available target.
    from app.organizations.configuration import communication_template_deliveries

    queued = 0
    token = secrets.token_hex(12)
    for channel, channel_template in communication_template_deliveries(template):
        if channel != "email" or not user.email:
            continue
        subject, message_body = render_communication_template(channel_template, replacements)
        db.add(OutboxMessage(
            kind="communication-template.test",
            payload={
                "destination": user.email,
                "subject": "[Test] " + subject,
                "body": message_body,
                "channel": channel,
                "user_id": user.id,
            },
            idempotency_key=f"template-test:{key}:{channel}:{token}",
            created_by=actor.user_id,
            updated_by=actor.user_id,
        ))
        queued += 1
    if not queued:
        raise HTTPException(422, "No configured template channel has a destination for this user")
    audit(db, actor.user_id, "template.test", "communication_templates", key)
    return {"status": "queued", "deliveries": queued}


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
    # Keep the canonical RBAC assignment projection in step with the legacy
    # access rows used by older request paths.  Access queries and effective
    # permission evaluation read the canonical role IDs, while the legacy
    # rows remain the compatibility source for session location selection.
    await db.execute(delete(TenantRoleAssignment).where(TenantRoleAssignment.user_id == user.id))
    primary_role_id = None
    for item in requested:
        role = await db.scalar(
            select(TenantRole).where(
                TenantRole.name == item.role,
                TenantRole.status == "published",
            )
        )
        if role is None:
            raise HTTPException(422, "Unknown role")
        primary_role_id = primary_role_id or role.id
        db.add(
            TenantRoleAssignment(
                user_id=user.id,
                role_id=role.id,
                level="Organization" if item.scope == "organization" else "Location",
                location_id=item.location_id,
                created_by=actor.user_id,
                updated_by=actor.user_id,
            )
        )
    user.role = requested[0].role
    user.role_id = primary_role_id
    user.active = body.active
    if body.is_provider is not None:
        user.is_provider = body.is_provider
    user.location_ids = [item.location_id for item in requested if item.location_id]
    user.token_version += 1
    user.updated_by = actor.user_id
    audit(db, actor.user_id, "access.update", "staff", identifier, changes=changes)
    return {"updated": True, "changes": changes}
