"""CMS draft and publication lifecycle persistence helpers."""

from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import delete, func, select, text

from app.cms.models import CmsMediaAsset, CmsPublicationPointer, CmsRevision
from app.cms.services.content import default_content


async def lock_publication_state(db):
    """Serialize revision numbers and publication keys within the current tenant."""
    await db.execute(
        text(
            "SELECT pg_advisory_xact_lock("
            "hashtext(current_schema()), hashtext('cms-publication-state'))"
        )
    )

# Validate or enforce ensure draft before the operation continues.
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


# Update sync media while preserving existing validation and audit behavior.
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


# Handle published revision for this module.
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

# Validate or enforce assert current before the operation continues.
def assert_current(revision: CmsRevision, expected: str | None):
    if expected:
        try:
            supplied = datetime.fromisoformat(expected.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(422, "Invalid draft timestamp") from None
        if supplied != revision.updated_at:
            raise HTTPException(409, "Draft changed; reload before saving or publishing")


# Handle activate publication for this module.
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
