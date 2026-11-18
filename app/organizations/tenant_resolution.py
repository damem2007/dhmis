import re
from dataclasses import dataclass

from fastapi import HTTPException, Request
from sqlalchemy import select

from app.core.database import control_session, organization_session
from app.organizations.configuration import tenant_settings
from app.organizations.jurisdiction import jurisdiction
from app.organizations.models import Organization, OrganizationDomainHost, OrganizationDomainRequest

RESERVED_SLUGS = {"admin", "api", "health", "portal", "public", "v1"}
SURFACE_FEATURE = {
    "public": "front_office_enabled",
    "portal": "patient_portal_enabled",
    "booking": "booking_enabled",
}
PLATFORM_HOST_SUFFIX = ".dhmis.test"
PLATFORM_HOST_LABELS = {"admin", "api", "platform", "www"}


# Handle normalize slug for this module.
def normalize_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not 3 <= len(slug) <= 80 or slug in RESERVED_SLUGS:
        raise ValueError("Slug must be 3–80 characters and cannot be a reserved platform route")
    return slug


# Handle normalize hostname for this module.
def normalize_hostname(value: str) -> str:
    hostname = value.strip().lower().split(":", 1)[0].rstrip(".")
    if not hostname or not re.fullmatch(r"[a-z0-9.-]+", hostname):
        raise ValueError("Invalid hostname")
    return hostname


def platform_hostname_slug(hostname: str) -> tuple[str, str | None] | None:
    """Resolve the tenant key implied by the platform's wildcard hostnames."""

    normalized = normalize_hostname(hostname)
    if not normalized.endswith(PLATFORM_HOST_SUFFIX):
        return None
    prefix = normalized[: -len(PLATFORM_HOST_SUFFIX)]
    labels = prefix.split(".") if prefix else []
    if len(labels) == 1 and labels[0] not in PLATFORM_HOST_LABELS:
        return labels[0], None
    if len(labels) == 2 and labels[0] == "admin" and labels[1] not in PLATFORM_HOST_LABELS:
        return labels[1], "back-office"
    return None


# Defines the tenant resolution model, contract, or value object.
@dataclass
class TenantResolution:
    organization: Organization
    source: str
    surface: str | None = None
    domain: str | None = None
    redirect_to: str | None = None


# Validate or enforce ensure surface before the operation continues.
def ensure_surface(organization: Organization, surface: str | None):
    feature = SURFACE_FEATURE.get(surface or "")
    if feature and not getattr(organization, feature):
        raise HTTPException(404, "Clinic surface is not enabled")


# Retrieve resolve organization for the current request or workflow.
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
            resolution = None
            # Domain hosts are the authoritative routing lifecycle.  A custom
            # hostname is deliberately invisible until its request is active;
            # this prevents a tenant-owned hostname from serving an app before
            # ownership, DNS, routing and TLS checks have succeeded.
            host_row = (
                await db.execute(
                    select(OrganizationDomainHost, OrganizationDomainRequest, Organization)
                    .join(OrganizationDomainRequest, OrganizationDomainRequest.id == OrganizationDomainHost.request_id)
                    .join(Organization, Organization.id == OrganizationDomainHost.organization_id)
                    .where(
                        OrganizationDomainHost.hostname == normalized_host,
                        OrganizationDomainHost.routing_status == "active",
                        OrganizationDomainHost.tls_status == "ready",
                        OrganizationDomainRequest.status == "active",
                        Organization.status == "active",
                    )
                )
            ).one_or_none()
            if host_row:
                host, domain_request, candidate = host_row
                if host.role == "managed_back_office":
                    # A custom domain is authoritative once active. Keep the
                    # managed administrative hostname as an explicit lifecycle
                    # record so it redirects rather than resolving as public.
                    resolution = TenantResolution(
                        candidate,
                        "managed-alias-redirect",
                        "back-office",
                        normalized_host,
                        f"https://{domain_request.backoffice_hostname}",
                    )
                else:
                    resolution = TenantResolution(
                        candidate,
                        "domain-lifecycle",
                        "back-office" if host.role == "back_office" else "public",
                        normalized_host,
                    )
            # Compatibility lookup for rows created before the lifecycle
            # tables.  New custom-domain requests never use this path.
            if resolution is None:
                organizations = (
                    await db.scalars(select(Organization).where(Organization.status == "active"))
                ).all()
                for candidate in organizations:
                    for binding in candidate.domains:
                        if normalize_hostname(str(binding.get("hostname", ""))) == normalized_host:
                            resolution = TenantResolution(
                                candidate,
                                "legacy-custom-domain",
                                str(binding.get("surface") or "public"),
                                normalized_host,
                            )
                            break
                    if resolution:
                        break
            if resolution is None:
                inferred = platform_hostname_slug(normalized_host)
                if inferred:
                    inferred_slug, inferred_surface = inferred
                    organization = await db.scalar(
                        select(Organization).where(Organization.slug == inferred_slug)
                    )
                    if organization:
                        latest_request = await db.scalar(
                            select(OrganizationDomainRequest)
                            .where(OrganizationDomainRequest.organization_id == organization.id)
                            .order_by(OrganizationDomainRequest.created_at.desc())
                        )
                        if latest_request is not None and latest_request.mode == "custom":
                            if latest_request.status == "active":
                                target = latest_request.backoffice_hostname if inferred_surface == "back-office" else latest_request.public_hostname
                                if target:
                                    resolution = TenantResolution(
                                        organization,
                                        "managed-alias-redirect",
                                        inferred_surface,
                                        normalized_host,
                                        f"https://{target}",
                                    )
                            # While the customer-owned request remains pending,
                            # only managed Back Office stays available.
                            elif inferred_surface is None:
                                organization = None
                    if organization and resolution is None:
                        resolution = TenantResolution(
                            organization,
                            "platform-hostname",
                            inferred_surface,
                            normalized_host,
                        )
    if resolution is None or resolution.organization.status != "active":
        if resolution is not None:
            raise HTTPException(404, f"Clinic is not active ({resolution.organization.status})")
        raise HTTPException(404, "Clinic not found")
    # Public tenant hostname is shared by Tenant Website and the /portal
    # extension.  It is not a distinct DNS host for Patient Portal.
    if surface and resolution.surface and surface != resolution.surface and not (
        resolution.surface == "public" and surface in {"portal", "booking"}
    ):
        raise HTTPException(404, "Clinic surface is not enabled on this domain")
    requested_surface = surface or resolution.surface
    ensure_surface(resolution.organization, requested_surface)
    resolution.surface = requested_surface
    return resolution


# Handle organization from login for this module.
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


# Validate or enforce validate request tenant before the operation continues.
async def validate_request_tenant(request: Request, organization: Organization):
    slug = request.headers.get("X-DHMIS-Tenant", "").strip()
    if slug and slug != organization.slug:
        raise HTTPException(403, "Tenant context mismatch")


# Handle safe metadata for this module.
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
        "redirect_to": resolution.redirect_to,
        "region": organization.region,
        "currency": jurisdiction(organization.region).currency,
        "features": {
            "front_office": organization.front_office_enabled,
            "booking": organization.booking_enabled,
            "patient_portal": organization.patient_portal_enabled,
        },
        "branding": settings.branding,
        "logo_url": settings.logo_url,
    }
