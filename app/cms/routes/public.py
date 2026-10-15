"""Public storefront and booking routes."""

from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import select

from app.billing.models import Service
from app.cms.models import CmsMediaAsset
from app.cms.services import (
    default_content,
    public_content,
    published_revision,
)
from app.core.audit import audit
from app.core.database import organization_session
from app.core.rate_limit import get_fo_throttle_args
from app.core.repository import add
from app.identity.models import StaffUser
from app.identity.router import throttle
from app.identity.service import Actor, role_names_with_module
from app.integrations.configuration import attach_effective_adapters
from app.integrations.contracts import IntegrationFailure
from app.integrations.registry import resolve_registered
from app.organizations.configuration import tenant_settings
from app.organizations.models import Location
from app.organizations.tenant_resolution import resolve_organization
from app.patients.models import Patient
from app.scheduling.models import Appointment
from app.scheduling.schemas import Booking
from app.scheduling.service import book

router = APIRouter()

# Handle public organization for this module.
async def public_organization(identifier: str, surface: str):
    return (
        await resolve_organization(organization_id=identifier, surface=surface)
    ).organization


# Handle storefront for this module.
@router.get("/public/organizations/{organization_id}")
async def storefront(organization_id: str, location_id: str | None = Query(default=None)):
    organization = await public_organization(organization_id, "public")
    return await storefront_data(organization, location_id=location_id)


# Handle storefront data for this module.
async def storefront_data(
    organization,
    override_content: dict | None = None,
    preview_revision: str = "",
    location_id: str | None = None,
):
    adapter_names = await attach_effective_adapters(organization)
    map_provider = None
    map_provider_name = adapter_names.get("map_provider")
    if map_provider_name:
        try:
            map_provider = resolve_registered(
                "map_provider",
                map_provider_name,
                organization_id=organization.id,
                region=organization.region,
                enforce_live=False,
            )
        except IntegrationFailure:
            map_provider = None
    async with organization_session(organization) as db:
        settings = await tenant_settings(db)
        revision = (
            None
            if override_content is not None
            else await published_revision(db, location_id=location_id)
        )
        content = override_content or (revision.content if revision else await default_content(db, organization))
        catalog_services = {
            row.id: row
            for row in (await db.scalars(select(Service))).all()
        }
        # Handle catalog service for for this module.
        def catalog_service_for(item: dict):
            return catalog_services.get(item.get("catalog_service_id") or item.get("id"))
        site_service_rows = []
        for row in sorted(content.get("services", []), key=lambda item: item.get("order", 0)):
            service = catalog_service_for(row)
            if not row.get("visible", True) or service is None:
                continue
            site_service_rows.append(
                {
                    **row,
                    "id": service.id,
                    "catalog_service_id": service.id,
                    "title": service.name,
                    "description": service.description[:90],
                    "fee_mode": "free" if service.fee_cents == 0 else "from",
                    "fee_cents": service.fee_cents,
                }
            )
        public_site_content = dict(content)
        public_site_content["services"] = site_service_rows
        locations = (await db.scalars(select(Location).where(Location.active).order_by(Location.name))).all()
        # Clinical roles are not enough to make an account patient-facing.
        # Administrators and support users can be assigned to a location while
        # remaining excluded from booking and the public care team.
        clinical_roles = set(await role_names_with_module(db, "clinical"))
        provider_query = select(StaffUser).where(
            StaffUser.active,
            StaffUser.is_provider,
            StaffUser.archived_at.is_(None),
            (StaffUser.suspended_until.is_(None) | (StaffUser.suspended_until <= datetime.now(UTC))),
            StaffUser.role.in_(clinical_roles),
        )
        providers = (await db.scalars(provider_query)).all()
    content_locations = {
        item.get("location_id"): item for item in content.get("locations", [])
    }
    return {
        "organization_id": organization.id,
        "slug": organization.slug,
        "name": organization.name,
        "branding": settings.branding,
        "logo_url": settings.logo_url,
        "content": public_content(public_site_content),
        "cms_revision_id": preview_revision or (revision.id if revision else None),
        "cms_source": "preview" if preview_revision else "published" if revision else "provisioned-default",
        "booking_widget": settings.booking_widget,
        "map_provider": map_provider_name,
        "services": [
            {
                "id": row["id"],
                "code": catalog_services[row["catalog_service_id"]].code,
                "name": row["title"],
                "fee_cents": row["fee_cents"],
                "fee_mode": row["fee_mode"],
                "description": row["description"],
                "icon": row.get("icon", "tooth"),
            }
            for row in site_service_rows
        ],
        "locations": [
            {
                "id": row.id,
                "name": content_locations.get(row.id, {}).get("name") or row.name,
                "address": content_locations.get(row.id, {}).get("address") or row.address,
                "phone": content_locations.get(row.id, {}).get("phone") or row.phone,
                "email": content_locations.get(row.id, {}).get("email", ""),
                "timezone": content_locations.get(row.id, {}).get("timezone") or row.timezone,
                "hours": content_locations.get(row.id, {}).get("hours", {}),
                "closure_note": content_locations.get(row.id, {}).get("closure_note", ""),
                "latitude": row.latitude,
                "longitude": row.longitude,
                "osm_place_id": row.osm_place_id,
                "chairs": row.chairs,
                "opening_hour": row.opening_hour,
                "closing_hour": row.closing_hour,
                "map": (
                    map_provider.location_links(
                        row.latitude,
                        row.longitude,
                        row.address,
                    )
                    if map_provider is not None
                    and row.latitude is not None
                    and row.longitude is not None
                    else {}
                ),
            }
            for row in locations
        ],
        "providers": [{"id": row.id, "name": row.name, "location_ids": row.location_ids} for row in providers],
    }


# Handle availability for this module.
@router.get("/public/organizations/{organization_id}/availability")
async def availability(
    organization_id: str,
    location_id: str,
    provider_id: str,
    day: date = Query(),
):
    organization = await public_organization(organization_id, "booking")
    async with organization_session(organization) as db:
        settings = await tenant_settings(db)
        location = await db.get(Location, location_id)
        provider = await db.get(StaffUser, provider_id)
        if (
            location is None
            or provider is None
            or not provider.active
            or not provider.is_provider
            or provider.archived_at is not None
            or (provider.suspended_until and provider.suspended_until > datetime.now(UTC))
        ):
            raise HTTPException(404, "Location or provider not found")
        zone = ZoneInfo(location.timezone)
        start = datetime.combine(day, time(location.opening_hour), tzinfo=zone)
        end = datetime.combine(day, time(location.closing_hour), tzinfo=zone)
        appointments = (
            await db.scalars(
                select(Appointment).where(
                    Appointment.provider_id == provider.id,
                    Appointment.status != "cancelled",
                    Appointment.starts_at < end,
                    Appointment.ends_at > start,
                )
            )
        ).all()
        slots = []
        cursor = start
        policy = {**settings.policy, **location.policy}
        buffer = timedelta(minutes=policy.get("buffer_minutes", 0))
        while cursor + timedelta(minutes=30) <= end:
            slot_end = cursor + timedelta(minutes=30)
            if cursor > datetime.now(zone) and not any(
                item.starts_at < slot_end + buffer and item.ends_at > cursor - buffer
                for item in appointments
            ):
                slots.append({"starts_at": cursor.isoformat(), "ends_at": slot_end.isoformat()})
            cursor += timedelta(minutes=30)
    return slots


# Defines the public booking model, contract, or value object.
class PublicBooking(BaseModel):
    first_name: str = Field(min_length=1, max_length=80)
    last_name: str = Field(min_length=1, max_length=80)
    birth_date: date
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    phone: str = Field(default="", max_length=40)
    location_id: str
    provider_id: str
    chair: str = Field(min_length=1, max_length=40)
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    procedure: str = Field(min_length=1, max_length=180)


# Handle public booking for this module.
@router.post("/public/organizations/{organization_id}/appointments", status_code=201)
async def public_booking(organization_id: str, body: PublicBooking, request: Request):
    address = request.client.host if request.client else "unknown"
    limits = get_fo_throttle_args()
    if not await throttle(
        f"public-booking:{address}:{organization_id}", limits.limit, limits.seconds
    ):
        raise HTTPException(429, "Too many booking attempts")
    organization = await public_organization(organization_id, "booking")
    adapter_names = await attach_effective_adapters(organization)
    async with organization_session(organization) as db:
        settings = await tenant_settings(db)
        actor = Actor(
            "public-booking",
            organization,
            "Public booking",
            "public",
            settings=settings,
            adapter_names=adapter_names,
        )
        patient = await db.scalar(
            select(Patient).where(
                Patient.email == body.email.lower(), Patient.birth_date == body.birth_date
            )
        )
        if patient is None:
            patient = await add(
                db,
                Patient,
                {
                    "first_name": body.first_name,
                    "last_name": body.last_name,
                    "birth_date": body.birth_date,
                    "email": body.email.lower(),
                    "phone": body.phone,
                    "location_id": body.location_id,
                },
                actor.user_id,
            )
            #send a welcome email to the newly added patient.
        appointment = await book(
            db,
            actor,
            Booking(
                patient_id=patient.id,
                location_id=body.location_id,
                provider_id=body.provider_id,
                chair=body.chair,
                starts_at=body.starts_at,
                ends_at=body.ends_at,
                procedure=body.procedure,
            ),
        )
        ## send the appointment email to the patients, either new or existing patients.
        audit(db, actor.user_id, "public.book", "appointments", appointment.id, patient_id=patient.id)
        return {"appointment_id": appointment.id, "status": appointment.status}


# Handle storefront by slug for this module.
@router.get("/public/tenants/{tenant_slug}")
async def storefront_by_slug(tenant_slug: str, location_id: str | None = Query(default=None)):
    resolution = await resolve_organization(slug=tenant_slug, surface="public")
    return await storefront_data(resolution.organization, location_id=location_id)


# Handle published media for this module.
@router.get("/public/tenants/{tenant_slug}/media/{asset_key}")
async def published_media(
    tenant_slug: str,
    asset_key: str,
    location_id: str | None = Query(default=None),
):
    resolution = await resolve_organization(slug=tenant_slug, surface="public")
    async with organization_session(resolution.organization) as db:
        revision = await published_revision(db, location_id=location_id)
        if revision is None:
            raise HTTPException(404, "CMS media not found")
        asset = await db.scalar(
            select(CmsMediaAsset).where(
                CmsMediaAsset.revision_id == revision.id,
                CmsMediaAsset.asset_key == asset_key,
                CmsMediaAsset.visible,
            )
        )
        if asset is None or not asset.content:
            raise HTTPException(404, "CMS media not found")
        return Response(content=asset.content, media_type=asset.mime_type)


# Handle booking context for this module.
@router.get("/booking/tenants/{tenant_slug}")
async def booking_context(tenant_slug: str):
    resolution = await resolve_organization(slug=tenant_slug, surface="booking")
    return await storefront_data(resolution.organization)


# Handle availability by slug for this module.
@router.get("/booking/tenants/{tenant_slug}/availability")
async def availability_by_slug(
    tenant_slug: str,
    location_id: str,
    provider_id: str,
    day: date = Query(),
):
    resolution = await resolve_organization(slug=tenant_slug, surface="booking")
    return await availability(
        resolution.organization.id,
        location_id,
        provider_id,
        day,
    )


# Handle booking by slug for this module.
@router.post("/booking/tenants/{tenant_slug}/appointments", status_code=201)
async def booking_by_slug(
    tenant_slug: str, body: PublicBooking, request: Request
):
    resolution = await resolve_organization(slug=tenant_slug, surface="booking")
    return await public_booking(resolution.organization.id, body, request)

__all__ = ["public_organization", "storefront", "storefront_data", "availability", "PublicBooking", "public_booking", "storefront_by_slug", "published_media", "booking_context", "availability_by_slug", "booking_by_slug", "router"]
