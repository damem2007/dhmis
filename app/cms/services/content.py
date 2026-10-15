"""CMS content defaults, validation, and public serialization."""

from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import select

from app.billing.defaults import ensure_default_services
from app.billing.models import Service
from app.cms.models import CmsMediaAsset, CmsRevision
from app.cms.schemas import CmsContentInput
from app.identity.models import StaffUser
from app.identity.service import role_names_with_module
from app.organizations.configuration import tenant_settings
from app.organizations.models import Location

DEFAULT_SERVICE_ICONS = {
    "CHECKUP-CLEAN": "checkup",
    "FILLINGS": "filling",
    "EMERGENCY": "emergency",
    "WHITENING": "whitening",
    "CHILDREN-DENTISTRY": "kids",
    "CONSULTATION": "consult",
}


# Handle revision payload for this module.
def revision_payload(row: CmsRevision) -> dict:
    return {
        "id": row.id,
        "revision_number": row.revision_number,
        "status": row.status,
        "base_revision_id": row.base_revision_id,
        "content": row.content,
        "applicability": row.applicability,
        "validation": row.validation,
        "policy_versions": row.policy_versions,
        "published_at": row.published_at,
        "published_by": row.published_by,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }

# Handle default content for this module.
async def default_content(db, organization) -> dict:
    # CMS defaults are derived from the same tenant-owned catalogue used by
    # billing and clinical workflows. This also backfills older empty tenant
    # schemas before their first site-editor visit.
    await ensure_default_services(db)
    settings = await tenant_settings(db)
    services = (await db.scalars(select(Service).order_by(Service.name))).all()
    locations = (await db.scalars(select(Location).order_by(Location.name))).all()
    dentists = (
        await db.scalars(
            select(StaffUser)
            .where(
                StaffUser.active,
                StaffUser.is_provider,
                StaffUser.archived_at.is_(None),
                (StaffUser.suspended_until.is_(None) | (StaffUser.suspended_until <= datetime.now(UTC))),
                StaffUser.role.in_(await role_names_with_module(db, "clinical")),
            )
            .order_by(StaffUser.name)
        )
    ).all()
    legacy = settings.public_content
    return CmsContentInput(
        headline=legacy.get("headline") or organization.name,
        introduction=legacy.get("introduction", ""),
        contact_email=legacy.get("contact_email", ""),
        contact_phone=legacy.get("contact_phone", ""),
        address=legacy.get("address", ""),
        brand={"primary": settings.branding.get("--sage", "#356b5d")},
        services=[
            {
                "id": item.id,
                "catalog_service_id": item.id,
                "title": item.name,
                "icon": DEFAULT_SERVICE_ICONS.get(item.code, "tooth"),
                "description": item.description[:90],
                "fee_mode": "free" if item.fee_cents == 0 else "from",
                "fee_cents": item.fee_cents,
                "visible": True,
                "order": index,
            }
            for index, item in enumerate(services)
        ],
        dentists=[
            {
                "id": item.id,
                "name": item.name,
                "role": item.role.replace("-", " ").title(),
                "visible": True,
                "order": index,
            }
            for index, item in enumerate(dentists)
        ],
        locations=[
            {
                "location_id": item.id,
                "name": item.name,
                "address": legacy.get("address", ""),
                "phone": legacy.get("contact_phone", ""),
                "email": legacy.get("contact_email", ""),
                "timezone": item.timezone,
                "hours": {
                    "monday": f"{item.opening_hour:02d}:00–{item.closing_hour:02d}:00"
                },
                "visible": True,
            }
            for item in locations
        ],
        location_rotation_enabled=False,
    ).model_dump(mode="json")


# Handle consent valid for this module.
def consent_valid(consent: dict) -> bool:
    return bool(
        consent.get("confirmed")
        and consent.get("confirmed_by", "").strip()
        and consent.get("confirmed_at", "").strip()
        and consent.get("source", "").strip()
    )


async def sync_catalog_services(db, content: dict) -> dict:
    """Normalize site services from the tenant's billing catalogue.

    Services & fees owns the service identity and billable fields. The CMS may
    curate presentation (icon, visibility, and order), but it cannot create a
    second service record with different pricing or descriptive data.
    """
    catalogue = {
        item.id: item
        for item in (await db.scalars(select(Service).order_by(Service.name))).all()
    }
    normalized = []
    seen: set[str] = set()
    for item in content.get("services", []):
        service_id = item.get("catalog_service_id") or item.get("id")
        service = catalogue.get(service_id)
        if service is None:
            raise HTTPException(
                422,
                "Every website service must be created in Services & fees before it can be published.",
            )
        if service.id in seen:
            raise HTTPException(422, "A service can only appear once on the website.")
        seen.add(service.id)
        normalized.append(
            {
                **item,
                "id": service.id,
                "catalog_service_id": service.id,
                "title": service.name,
                "description": service.description[:90],
                "fee_mode": "free" if service.fee_cents == 0 else "from",
                "fee_cents": service.fee_cents,
            }
        )
    result = dict(content)
    result["services"] = normalized
    return result


# Handle preflight for this module.
async def preflight(db, revision: CmsRevision, organization) -> dict:
    blockers: list[dict] = []
    content = CmsContentInput.model_validate(revision.content)
    catalogue = {
        item.id
        for item in (await db.scalars(select(Service))).all()
    }
    seen_services: set[str] = set()
    for item in content.services:
        service_id = item.catalog_service_id or item.id
        if service_id not in catalogue:
            blockers.append({"code": "service.catalog.unknown", "service_id": service_id})
        elif service_id in seen_services:
            blockers.append({"code": "service.catalog.duplicate", "service_id": service_id})
        seen_services.add(service_id)
    locations = (await db.scalars(select(Location))).all()
    valid_location_ids = {item.id for item in locations}
    applicability = revision.applicability
    requested = set(applicability.get("location_ids", []))
    for identifier in sorted(requested - valid_location_ids):
        blockers.append({"code": "scope.location.unknown", "location_id": identifier})
    for item in content.locations:
        if item.location_id not in valid_location_ids:
            blockers.append({"code": "content.location.unknown", "location_id": item.location_id})
    assets = {item.key: item for item in content.media}
    stored_assets = {
        item.asset_key: item
        for item in (
            await db.scalars(
                select(CmsMediaAsset).where(CmsMediaAsset.revision_id == revision.id)
            )
        ).all()
    }
    for asset in content.media:
        if not asset.visible:
            continue
        stored = stored_assets.get(asset.key)
        has_remote_file = asset.file_url.startswith(("https://", "http://"))
        if not ((stored and stored.content) or has_remote_file):
            blockers.append({"code": "media.file.required", "asset_key": asset.key})
        if len(asset.alt_text.strip()) < 8:
            blockers.append({"code": "media.alt.required", "asset_key": asset.key})
        if not consent_valid(asset.consent.model_dump()):
            blockers.append({"code": "media.consent.required", "asset_key": asset.key})
    providers = {
        item.id
        for item in (
            await db.scalars(
                select(StaffUser).where(
                    StaffUser.active,
                    StaffUser.is_provider,
                    StaffUser.archived_at.is_(None),
                    (StaffUser.suspended_until.is_(None) | (StaffUser.suspended_until <= datetime.now(UTC))),
                )
            )
        ).all()
    }
    for dentist in content.dentists:
        if dentist.photo_key and dentist.photo_key not in assets:
            blockers.append({"code": "dentist.photo.unknown", "dentist_id": dentist.id})
        if dentist.bookable_online and dentist.id not in providers:
            blockers.append({"code": "dentist.booking.unsupported", "dentist_id": dentist.id})
    if content.testimonials_enabled:
        if not content.regulator_declaration:
            blockers.append({"code": "testimonials.regulator_declaration.required"})
        for item in content.testimonials:
            if item.visible and not consent_valid(item.consent.model_dump()):
                blockers.append({"code": "testimonial.consent.required", "testimonial_id": item.id})
    settings = await tenant_settings(db)
    policy_versions = {
        "jurisdiction": f"{organization.region}:1",
        "tenant_settings_updated_at": settings.updated_at.isoformat(),
    }
    return {
        "valid": not blockers,
        "blocker_count": len(blockers),
        "blockers": blockers,
        "policy_versions": policy_versions,
        "scope": applicability,
    }

# Handle public content for this module.
def public_content(content: dict) -> dict:
    safe = CmsContentInput.model_validate(content).model_dump(mode="json")
    for asset in safe["media"]:
        asset.pop("consent", None)
    for item in safe["testimonials"]:
        item.pop("consent", None)
    safe.pop("regulator_declaration", None)
    return safe
