import re
from dataclasses import dataclass

from fastapi import HTTPException, Request
from sqlalchemy import select

from app.core.database import control_session, organization_session
from app.organizations.configuration import tenant_settings
from app.organizations.models import Organization

RESERVED_SLUGS = {"admin", "api", "health", "portal", "public", "v1"}
SURFACE_FEATURE = {
    "public": "front_office_enabled",
    "portal": "patient_portal_enabled",
    "booking": "booking_enabled",
}


def normalize_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not 3 <= len(slug) <= 80 or slug in RESERVED_SLUGS:
        raise ValueError("Slug must be 3–80 characters and cannot be a reserved platform route")
    return slug


def normalize_hostname(value: str) -> str:
    hostname = value.strip().lower().split(":", 1)[0].rstrip(".")
    if not hostname or not re.fullmatch(r"[a-z0-9.-]+", hostname):
        raise ValueError("Invalid hostname")
    return hostname


@dataclass
class TenantResolution:
    organization: Organization
    source: str
    surface: str | None = None
    domain: str | None = None


def ensure_surface(organization: Organization, surface: str | None):
    feature = SURFACE_FEATURE.get(surface or "")
    if feature and not getattr(organization, feature):
        raise HTTPException(404, "Clinic surface is not enabled")


async def resolve_organization(
    *,
    slug: str | None = None,
    hostname: str | None = None,
    organization_id: str | None = None,
    surface: str | None = None,
) -> TenantResolution:
    if sum(value is not None for value in (slug, hostname, organization_id)) != 1:
        raise HTTPException(422, "Provide exactly one tenant routing key")
    async with control_session() as db:
        if organization_id:
            organization = await db.get(Organization, organization_id)
            resolution = TenantResolution(organization, "organization-id") if organization else None
        elif slug:
            try:
                normalized = normalize_slug(slug)
            except ValueError:
                raise HTTPException(404, "Clinic not found") from None
            organization = await db.scalar(select(Organization).where(Organization.slug == normalized))
            resolution = TenantResolution(organization, "platform-slug") if organization else None
        else:
            try:
                normalized_host = normalize_hostname(hostname or "")
            except ValueError:
                raise HTTPException(404, "Clinic not found") from None
            organizations = (
                await db.scalars(select(Organization).where(Organization.status == "active"))
            ).all()
            resolution = None
            for candidate in organizations:
                for binding in candidate.domains:
                    if normalize_hostname(str(binding.get("hostname", ""))) == normalized_host:
                        resolution = TenantResolution(
                            candidate,
                            "custom-domain",
                            str(binding.get("surface") or "public"),
                            normalized_host,
                        )
                        break
                if resolution:
                    break
    if resolution is None or resolution.organization.status != "active":
        raise HTTPException(404, "Clinic not found")
    if surface and resolution.surface and surface != resolution.surface:
        raise HTTPException(404, "Clinic surface is not enabled on this domain")
    requested_surface = surface or resolution.surface
    ensure_surface(resolution.organization, requested_surface)
    resolution.surface = requested_surface
    return resolution


async def organization_from_login(
    organization_id: str | None, tenant_slug: str | None
) -> Organization:
    if tenant_slug:
        resolved = await resolve_organization(slug=tenant_slug)
        if organization_id and organization_id != resolved.organization.id:
            raise HTTPException(401, "Tenant context mismatch")
        return resolved.organization
    if organization_id:
        return (await resolve_organization(organization_id=organization_id)).organization
    raise HTTPException(422, "Tenant context is required")


async def validate_request_tenant(request: Request, organization: Organization):
    slug = request.headers.get("X-DHMIS-Tenant", "").strip()
    if slug and slug != organization.slug:
        raise HTTPException(403, "Tenant context mismatch")


async def safe_metadata(resolution: TenantResolution):
    organization = resolution.organization
    async with organization_session(organization) as db:
        settings = await tenant_settings(db)
    return {
        "organization_id": organization.id,
        "slug": organization.slug,
        "name": organization.name,
        "source": resolution.source,
        "domain": resolution.domain,
        "surface": resolution.surface,
        "features": {
            "front_office": organization.front_office_enabled,
            "booking": organization.booking_enabled,
            "patient_portal": organization.patient_portal_enabled,
        },
        "branding": settings.branding,
    }
