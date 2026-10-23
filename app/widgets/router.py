"""Public appointment-widget endpoints.

The widget is intentionally independent from tenant-web.  It receives an
organization id, validates the tenant's booking surface and subscription
entitlement, then returns only the tenant-scoped data needed by the widget.
"""

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select

from app.cms.routes.public import PublicBooking, availability, public_booking
from app.core.database import control_session, organization_session
from app.identity.models import StaffUser
from app.identity.service import role_names_with_module
from app.organizations.configuration import tenant_settings
from app.organizations.entitlements import resolve_entitlements
from app.organizations.models import Location, PlatformCommercialAccount
from app.organizations.tenant_resolution import resolve_organization
from app.billing.models import Service

router = APIRouter(prefix="/widgets/appointments", tags=["Appointment widget"])

WIDGET_FEATURE = "module.appointment_widget"


def _verified_origins(config: dict | None) -> set[str]:
    """Return origins approved by the platform or completed through legacy verification."""

    values = config or {}
    verified = values.get("origin_verifications") or []
    result = set()
    for item in verified:
        if isinstance(item, dict) and item.get("origin") and item.get("verified_at"):
            result.add(str(item["origin"]))
    # Preserve development compatibility for configurations created before
    # verification was introduced. New origins are added only through the
    # verification endpoints.
    if not verified:
        result.update(str(origin) for origin in values.get("allowed_origins") or [])
    return result


async def widget_context(organization_id: str, request: Request):
    """Resolve booking, entitlement, account, and origin access for a request."""
    resolution = await resolve_organization(organization_id=organization_id, surface="booking")
    organization = resolution.organization
    async with control_session() as db:
        account = await db.scalar(
            select(PlatformCommercialAccount).where(PlatformCommercialAccount.organization_id == organization.id)
        )
    if account and account.account_status not in {"active", "trialing"}:
        raise HTTPException(
            status_code=402,
            detail={"code": "ACCOUNT_INACTIVE", "message": "The tenant account is not active for appointment booking."},
        )
    entitlements = await resolve_entitlements(organization.id)
    entitlement = entitlements.get(WIDGET_FEATURE)
    if not entitlement or not entitlement.get("enabled"):
        raise HTTPException(
            status_code=402,
            detail={
                "code": "APPOINTMENT_WIDGET_NOT_ENTITLED",
                "message": "The appointment widget is not included in the tenant subscription.",
                "feature": WIDGET_FEATURE,
            },
        )
    async with organization_session(organization) as db:
        runtime = await tenant_settings(db)
        config = runtime.booking_widget or {}
    approval = config.get("approval_request") or {}
    # Configurations created before the approval workflow remain compatible
    # when they already contain a verified origin. New requests must be
    # explicitly approved by a platform operator before the widget can run.
    approval_status = approval.get("status")
    if approval_status not in {"approved", None} and not config.get("origin_verifications") and not config.get("allowed_origins"):
        raise HTTPException(
            status_code=403,
            detail={"code": "APPOINTMENT_WIDGET_PENDING_APPROVAL", "message": "The appointment widget is awaiting platform approval."},
        )
    if approval_status == "pending":
        raise HTTPException(
            status_code=403,
            detail={"code": "APPOINTMENT_WIDGET_PENDING_APPROVAL", "message": "The appointment widget is awaiting platform approval."},
        )
    if approval_status == "rejected":
        raise HTTPException(
            status_code=403,
            detail={"code": "APPOINTMENT_WIDGET_REJECTED", "message": "The appointment widget request was rejected by the platform."},
        )
    origin = request.headers.get("origin", "").strip()
    parent_origin = request.query_params.get("parent_origin", "").strip()
    verified_origins = _verified_origins(config)
    if origin and origin not in verified_origins and parent_origin not in verified_origins:
        raise HTTPException(
            status_code=403,
            detail={"code": "WIDGET_ORIGIN_NOT_VERIFIED", "message": "This website is not verified for the appointment widget."},
        )
    return organization, runtime, config, entitlement


@router.get("/config")
async def widget_config(
    request: Request,
    organization_id: str = Query(min_length=36, max_length=36),
):
    """Return the tenant-scoped configuration consumed by the standalone script."""
    organization, runtime, config, entitlement = await widget_context(organization_id, request)
    async with organization_session(organization) as db:
        locations = (await db.scalars(select(Location).where(Location.active).order_by(Location.name))).all()
        providers = (
            await db.scalars(
                select(StaffUser).where(
                    StaffUser.active,
                    StaffUser.is_provider,
                    StaffUser.archived_at.is_(None),
                    (StaffUser.suspended_until.is_(None) | (StaffUser.suspended_until <= datetime.now(UTC))),
                    StaffUser.role.in_(await role_names_with_module(db, "clinical")),
                )
            )
        ).all()
        services = (await db.scalars(select(Service).order_by(Service.name))).all()
    location_ids = set(config.get("allowed_location_ids") or [])
    provider_ids = set(config.get("allowed_provider_ids") or [])
    service_ids = set(config.get("allowed_service_ids") or [])
    api_origin = str(request.base_url).rstrip("/")
    widget_mode = config.get("mode", "button")
    widget_target = ' data-target="#dhmis-booking-widget"' if widget_mode == "div" else ""
    widget_mount = '<div id="dhmis-booking-widget"></div>\n' if widget_mode == "div" else ""
    return {
        "organization_id": organization.id,
        "tenant": {"slug": organization.slug, "name": organization.name},
        "entitlement": {"key": WIDGET_FEATURE, "public_label": entitlement.get("public_label", "")},
        "mode": config.get("mode", "button"),
        "branding": {
            **runtime.branding,
            "--sage": config.get("accent_color", "#356b5d"),
            "--widget-text": config.get("text_color", "#14231c"),
            "--widget-background": config.get("background_color", "#f3f6f4"),
            "--widget-surface": config.get("surface_color", "#ffffff"),
            "--widget-border": config.get("border_color", "#d8e3de"),
        },
        "text": {
            "button_label": config.get("button_label", "Book an appointment"),
            "title": config.get("title", "Book an appointment"),
            "description": config.get("description", "Choose a time that works for you."),
            "success_message": config.get("success_message", "Your appointment request has been received."),
        },
        "font": {"family": config.get("font_family", "inherit"), "url": config.get("font_url", "")},
        "design": {
            "button_width": config.get("button_width", "auto"),
            "button_height": config.get("button_height", 48),
            "button_radius": config.get("button_radius", 8),
            "button_font_size": config.get("button_font_size", 16),
            "button_font_weight": config.get("button_font_weight", "700"),
            "panel_width": config.get("panel_width", 680),
            "panel_radius": config.get("panel_radius", 14),
            "panel_padding": config.get("panel_padding", 20),
        },
        "embed": {
            "script_path": f"{api_origin}/widgets/appointments.js",
            "organization_id": organization.id,
            "script": f'{widget_mount}<script src="{api_origin}/widgets/appointments.js" data-api-base="{api_origin}/v1/widgets/appointments" data-organization-id="{organization.id}" data-mode="{widget_mode}"{widget_target}></script>',
        },
        "logo_url": runtime.logo_url,
        "default_location_id": config.get("default_location_id", ""),
        "locations": [
            {"id": row.id, "name": row.name, "address": row.address, "timezone": row.timezone, "chairs": row.chairs}
            for row in locations
            if not location_ids or row.id in location_ids
        ],
        "providers": [
            {"id": row.id, "name": row.name, "location_ids": row.location_ids}
            for row in providers
            if not provider_ids or row.id in provider_ids
        ],
        "services": [
            {"id": row.id, "name": row.name, "fee_cents": row.fee_cents}
            for row in services
            if not service_ids or row.id in service_ids
        ],
    }


@router.get("/availability")
async def widget_availability(
    request: Request,
    organization_id: str = Query(min_length=36, max_length=36),
    location_id: str = Query(min_length=1),
    provider_id: str = Query(min_length=1),
    day: str = Query(min_length=10, max_length=10),
):
    """Return available appointment slots for the selected widget filters."""
    await widget_context(organization_id, request)
    from datetime import date

    return await availability(organization_id, location_id, provider_id, date.fromisoformat(day))


@router.post("/appointments", status_code=201)
async def widget_appointment(
    request: Request,
    organization_id: str = Query(min_length=36, max_length=36),
    body: PublicBooking = ...,
):
    """Create a public appointment after applying widget access controls."""
    await widget_context(organization_id, request)
    return await public_booking(organization_id, body, request)
