from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import delete, func, select, text

from app.billing.models import Service
from app.cms.models import CmsMediaAsset, CmsPublicationPointer, CmsRevision
from app.cms.schemas import CmsContentInput
from app.identity.models import StaffUser
from app.identity.service import role_names_with_module
from app.organizations.configuration import tenant_settings
from app.organizations.models import Location


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


async def lock_publication_state(db):
    """Serialize revision numbers and publication keys within the current tenant."""
    await db.execute(
        text(
            "SELECT pg_advisory_xact_lock("
            "hashtext(current_schema()), hashtext('cms-publication-state'))"
        )
    )


async def default_content(db, organization) -> dict:
    settings = await tenant_settings(db)
    services = (await db.scalars(select(Service).order_by(Service.name))).all()
    locations = (await db.scalars(select(Location).order_by(Location.name))).all()
    dentists = (
        await db.scalars(
            select(StaffUser)
            .where(StaffUser.active, StaffUser.role.in_(await role_names_with_module(db, "clinical")))
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
                "title": item.name,
                "description": item.description[:90],
                "fee_mode": "from",
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
    ).model_dump(mode="json")


async def ensure_draft(db, organization, actor_id: str) -> CmsRevision:
    await lock_publication_state(db)
    draft = await db.scalar(
        select(CmsRevision)
        .where(CmsRevision.status == "draft")
        .order_by(CmsRevision.revision_number.desc())
        .limit(1)
    )
    if draft:
        return draft
    published = await db.scalar(
        select(CmsRevision)
        .where(CmsRevision.status == "published")
        .order_by(CmsRevision.revision_number.desc())
        .limit(1)
    )
    number = (await db.scalar(select(func.max(CmsRevision.revision_number))) or 0) + 1
    draft = CmsRevision(
        revision_number=number,
        status="draft",
        base_revision_id=published.id if published else None,
        content=published.content if published else await default_content(db, organization),
        applicability=published.applicability if published else {"scope": "organization", "location_ids": []},
        created_by=actor_id,
        updated_by=actor_id,
    )
    db.add(draft)
    await db.flush()
    await sync_media(
        db,
        draft,
        actor_id,
        source_revision_id=published.id if published else None,
    )
    return draft


async def sync_media(
    db,
    revision: CmsRevision,
    actor_id: str,
    source_revision_id: str | None = None,
):
    existing = {
        item.asset_key: item
        for item in (
            await db.scalars(
                select(CmsMediaAsset).where(
                    CmsMediaAsset.revision_id == (source_revision_id or revision.id)
                )
            )
        ).all()
    }
    await db.execute(delete(CmsMediaAsset).where(CmsMediaAsset.revision_id == revision.id))
    db.add_all(
        [
            CmsMediaAsset(
                revision_id=revision.id,
                asset_key=item["key"],
                kind=item["kind"],
                file_name=item.get("file_name", ""),
                file_url=item.get("file_url", ""),
                mime_type=item.get("mime_type", ""),
                alt_text=item.get("alt_text", ""),
                consent=item.get("consent", {}),
                visible=item.get("visible", True),
                content=existing[item["key"]].content if item["key"] in existing else None,
                content_sha256=(
                    existing[item["key"]].content_sha256 if item["key"] in existing else ""
                ),
                size_bytes=existing[item["key"]].size_bytes if item["key"] in existing else 0,
                created_by=actor_id,
                updated_by=actor_id,
            )
            for item in revision.content.get("media", [])
        ]
    )
    await db.flush()


def consent_valid(consent: dict) -> bool:
    return bool(
        consent.get("confirmed")
        and consent.get("confirmed_by", "").strip()
        and consent.get("confirmed_at", "").strip()
        and consent.get("source", "").strip()
    )


async def preflight(db, revision: CmsRevision, organization) -> dict:
    blockers: list[dict] = []
    content = CmsContentInput.model_validate(revision.content)
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
    providers = {item.id for item in (await db.scalars(select(StaffUser).where(StaffUser.active))).all()}
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


async def published_revision(db, location_id: str | None = None) -> CmsRevision | None:
    pointer = None
    if location_id:
        pointer = await db.scalar(
            select(CmsPublicationPointer).where(
                CmsPublicationPointer.scope_key == f"location:{location_id}"
            )
        )
    if pointer is None:
        pointer = await db.scalar(
            select(CmsPublicationPointer).where(CmsPublicationPointer.scope_key == "organization")
        )
    return await db.get(CmsRevision, pointer.revision_id) if pointer else None


def public_content(content: dict) -> dict:
    safe = CmsContentInput.model_validate(content).model_dump(mode="json")
    for asset in safe["media"]:
        asset.pop("consent", None)
    for item in safe["testimonials"]:
        item.pop("consent", None)
    safe.pop("regulator_declaration", None)
    return safe


def assert_current(revision: CmsRevision, expected: str | None):
    if expected:
        try:
            supplied = datetime.fromisoformat(expected.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(422, "Invalid draft timestamp") from None
        if supplied != revision.updated_at:
            raise HTTPException(409, "Draft changed; reload before saving or publishing")


async def activate_publication(db, revision: CmsRevision, actor_id: str, publication_key: str):
    now = datetime.now(UTC)
    targets = (
        [("organization", None)]
        if revision.applicability.get("scope") == "organization"
        else [
            (f"location:{identifier}", identifier)
            for identifier in revision.applicability.get("location_ids", [])
        ]
    )
    for scope_key, location_id in targets:
        pointer = await db.scalar(
            select(CmsPublicationPointer)
            .where(CmsPublicationPointer.scope_key == scope_key)
            .with_for_update()
        )
        if pointer is None:
            db.add(
                CmsPublicationPointer(
                    scope_key=scope_key,
                    location_id=location_id,
                    revision_id=revision.id,
                    activated_at=now,
                    created_by=actor_id,
                    updated_by=actor_id,
                )
            )
        else:
            pointer.revision_id = revision.id
            pointer.activated_at = now
            pointer.updated_by = actor_id
    revision.status = "published"
    revision.published_at = now
    revision.published_by = actor_id
    revision.publication_key = publication_key
    revision.updated_by = actor_id
    await db.flush()
