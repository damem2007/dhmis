from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from app.billing.models import Service
from app.core.database import organization_session
from app.identity.models import StaffUser
from app.identity.service import role_names_with_module
from app.organizations.configuration import tenant_settings
from app.organizations.models import Location
from app.organizations.tenant_resolution import resolve_organization, safe_metadata

router = APIRouter(prefix="/tenants", tags=["Tenant resolution"])


@router.get("/resolve")
async def resolve_tenant(
    slug: str | None = Query(default=None),
    hostname: str | None = Query(default=None),
    organization_id: str | None = Query(default=None),
    surface: str | None = Query(default=None, pattern="^(back-office|public|portal|booking)$"),
):
    return await safe_metadata(
        await resolve_organization(
            slug=slug,
            hostname=hostname,
            organization_id=organization_id,
            surface=surface,
        )
    )


@router.get("/{slug}/widget-config")
async def booking_widget_config(slug: str):
    """Return a tenant-bound public booking manifest without accepting an organization id."""

    resolution = await resolve_organization(slug=slug, surface="booking")
    organization = resolution.organization
    async with organization_session(organization) as db:
        runtime = await tenant_settings(db)
        config = runtime.booking_widget
        locations = (await db.scalars(select(Location).order_by(Location.name))).all()
        providers = (
            await db.scalars(
                select(StaffUser).where(
                    StaffUser.active,
                    StaffUser.role.in_(await role_names_with_module(db, "clinical")),
                )
            )
        ).all()
        services = (await db.scalars(select(Service).order_by(Service.name))).all()
    location_ids = set(config.get("allowed_location_ids", []))
    service_ids = set(config.get("allowed_service_ids", []))
    provider_ids = set(config.get("allowed_provider_ids", []))
    if config.get("default_location_id") and not any(
        row.id == config["default_location_id"] for row in locations
    ):
        raise HTTPException(409, "Booking widget default location is no longer available")
    return {
        "tenant": {"slug": organization.slug, "name": organization.name},
        "branding": {**runtime.branding, "--sage": config.get("accent_color", "#356b5d")},
        "allowed_origins": config.get("allowed_origins", []),
        "default_location_id": config.get("default_location_id", ""),
        "locations": [
            {
                "id": row.id,
                "name": row.name,
                "address": row.address,
                "latitude": row.latitude,
                "longitude": row.longitude,
                "osm_place_id": row.osm_place_id,
                "timezone": row.timezone,
                "chairs": row.chairs,
            }
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
