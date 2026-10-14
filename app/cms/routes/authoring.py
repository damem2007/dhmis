"""CMS authoring, preview, and publication routes."""

import base64
import binascii
import hashlib
import time as epoch_time
from datetime import UTC, datetime

import jwt
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.cms.models import CmsMediaAsset, CmsRevision
from app.cms.schemas import CmsContentInput, DraftInput, MediaUploadInput, PublishInput
from app.cms.services import (
    activate_publication,
    assert_current,
    ensure_draft,
    lock_publication_state,
    preflight,
    revision_payload,
    sync_catalog_services,
    sync_media,
)
from app.core.audit import audit
from app.core.config import settings as application_settings
from app.core.database import control_session, organization_session
from app.identity.service import Actor, db_session, permit
from app.organizations.configuration import configure_tenant, tenant_settings
from app.rbac.dependencies import permit_tenant
from app.rbac.models import TenantApprovalPolicy, TenantChangeDecision, TenantChangeRequest
from app.rbac.runtime import decide_tenant, tenant_policy_context
from app.rbac.workflow import (
    authorize_runtime_action,
    complete_runtime_action,
    create_runtime_action_request,
    request_payload,
)

from .public import storefront_data

router = APIRouter()


# Defines the content input model, contract, or value object.
class ContentInput(BaseModel):
    headline: str = Field(min_length=2, max_length=180)
    introduction: str = Field(min_length=2, max_length=2000)
    contact_email: str = Field(default="", max_length=254)
    contact_phone: str = Field(default="", max_length=40)
    logo_url: str = Field(default="", max_length=500)


# Handle cms for this module.
@router.get("/cms")
async def cms(db=Depends(db_session), actor=Depends(permit("settings"))):
    return (await tenant_settings(db)).public_content


# Update update cms while preserving existing validation and audit behavior.
@router.put("/cms")
async def update_cms(
    body: ContentInput, db=Depends(db_session), actor=Depends(permit("settings"))
):
    await configure_tenant(db, public_content=body.model_dump(), actor_id=actor.user_id)
    audit(db, actor.user_id, "configure", "cms", actor.organization.id)
    return body.model_dump()


# Handle revisions for this module.
@router.get("/cms/revisions")
async def revisions(db=Depends(db_session), actor=Depends(permit("settings"))):
    rows = (
        await db.scalars(
            select(CmsRevision).order_by(CmsRevision.revision_number.desc()).limit(100)
        )
    ).all()
    return [revision_payload(row) for row in rows]


# Handle draft for this module.
@router.get("/cms/revisions/draft")
async def draft(db=Depends(db_session), actor=Depends(permit("settings"))):
    row = await ensure_draft(db, actor.organization, actor.user_id)
    audit(db, actor.user_id, "draft.read", "cms_revision", row.id)
    return revision_payload(row)


# Update save draft while preserving existing validation and audit behavior.
@router.put("/cms/revisions/{identifier}")
async def save_draft(
    identifier: str,
    body: DraftInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    row = await db.scalar(
        select(CmsRevision).where(CmsRevision.id == identifier).with_for_update()
    )
    if row is None:
        raise HTTPException(404, "CMS revision not found")
    if row.status != "draft":
        raise HTTPException(409, "Published revisions are immutable")
    assert_current(row, body.expected_updated_at)
    row.content = await sync_catalog_services(
        db, body.content.model_dump(mode="json")
    )
    row.applicability = body.applicability.model_dump(mode="json")
    row.validation = {}
    row.updated_at = datetime.now(UTC)
    row.updated_by = actor.user_id
    await sync_media(db, row, actor.user_id)
    audit(
        db,
        actor.user_id,
        "draft.save",
        "cms_revision",
        row.id,
        scope=row.applicability,
    )
    return revision_payload(row)


# Handle upload media for this module.
@router.post("/cms/revisions/{identifier}/media")
async def upload_media(
    identifier: str,
    body: MediaUploadInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    row = await db.scalar(
        select(CmsRevision).where(CmsRevision.id == identifier).with_for_update()
    )
    if row is None:
        raise HTTPException(404, "CMS revision not found")
    if row.status != "draft":
        raise HTTPException(409, "Published revisions are immutable")
    assert_current(row, body.expected_updated_at)
    try:
        content = base64.b64decode(body.content_base64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(422, "Photo content is not valid base64") from None
    if not content or len(content) > 5 * 1024 * 1024:
        raise HTTPException(422, "Photo must be between 1 byte and 5 MB")
    media = [item for item in row.content.get("media", []) if item.get("key") != body.key]
    media.append(
        {
            "key": body.key,
            "kind": body.kind,
            "file_name": body.file_name,
            "file_url": f"/v1/public/tenants/{actor.organization.slug}/media/{body.key}",
            "mime_type": body.mime_type,
            "alt_text": body.alt_text,
            "consent": body.consent.model_dump(mode="json"),
            "visible": body.visible,
        }
    )
    candidate = {**row.content, "media": media}
    row.content = CmsContentInput.model_validate(candidate).model_dump(mode="json")
    row.validation = {}
    row.updated_at = datetime.now(UTC)
    row.updated_by = actor.user_id
    await sync_media(db, row, actor.user_id)
    asset = await db.scalar(
        select(CmsMediaAsset).where(
            CmsMediaAsset.revision_id == row.id,
            CmsMediaAsset.asset_key == body.key,
        )
    )
    asset.content = content
    asset.content_sha256 = hashlib.sha256(content).hexdigest()
    asset.size_bytes = len(content)
    asset.updated_by = actor.user_id
    audit(
        db,
        actor.user_id,
        "media.upload",
        "cms_revision",
        row.id,
        asset_key=body.key,
        mime_type=body.mime_type,
        size_bytes=len(content),
    )
    await db.flush()
    return revision_payload(row)


# Handle draft media for this module.
@router.get("/cms/revisions/{identifier}/media/{asset_key}")
async def draft_media(
    identifier: str,
    asset_key: str,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    asset = await db.scalar(
        select(CmsMediaAsset).where(
            CmsMediaAsset.revision_id == identifier,
            CmsMediaAsset.asset_key == asset_key,
            CmsMediaAsset.visible,
        )
    )
    if asset is None or not asset.content:
        raise HTTPException(404, "CMS media not found")
    return Response(content=asset.content, media_type=asset.mime_type)


# Handle publication preflight for this module.
@router.post("/cms/revisions/{identifier}/preflight")
async def publication_preflight(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    row = await db.get(CmsRevision, identifier)
    if row is None:
        raise HTTPException(404, "CMS revision not found")
    if row.status != "draft":
        raise HTTPException(409, "Published revisions are immutable")
    result = await preflight(db, row, actor.organization)
    row.validation = result
    row.policy_versions = result["policy_versions"]
    row.updated_at = datetime.now(UTC)
    row.updated_by = actor.user_id
    audit(
        db,
        actor.user_id,
        "publish.preflight",
        "cms_revision",
        row.id,
        valid=result["valid"],
        blockers=result["blockers"],
    )
    await db.flush()
    return {**result, "revision_updated_at": row.updated_at}


# Handle preview token for this module.
@router.post("/cms/revisions/{identifier}/preview-token")
async def preview_token(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    row = await db.get(CmsRevision, identifier)
    if row is None:
        raise HTTPException(404, "CMS revision not found")
    now = int(epoch_time.time())
    token = jwt.encode(
        {
            "sub": actor.user_id,
            "org": actor.organization.id,
            "revision": row.id,
            "aud": "dhmis-cms-preview",
            "iss": "dhmis",
            "iat": now,
            "exp": now + 600,
        },
        application_settings().jwt_secret.get_secret_value(),
        algorithm="HS256",
    )
    audit(db, actor.user_id, "preview.issue", "cms_revision", row.id)
    return {"token": token, "expires_in": 600, "path": f"/v1/cms/preview/{token}"}


# Handle publish for this module.
@router.post("/cms/revisions/{identifier}/publish")
async def publish(
    identifier: str,
    body: PublishInput,
    db=Depends(db_session),
    actor: Actor = Depends(
        permit_tenant("cms.cms_publication.publish", workflow_handles_approval=True)
    ),
):
    await lock_publication_state(db)
    existing = await db.scalar(
        select(CmsRevision).where(CmsRevision.publication_key == body.idempotency_key)
    )
    if existing:
        if existing.id != identifier:
            raise HTTPException(409, "Publication key belongs to another revision")
        return revision_payload(existing)
    row = await db.scalar(
        select(CmsRevision).where(CmsRevision.id == identifier).with_for_update()
    )
    if row is None:
        raise HTTPException(404, "CMS revision not found")
    if row.status != "draft":
        raise HTTPException(409, "Only a draft can be published")
    assert_current(row, body.expected_updated_at)
    if body.confirmed_scope != row.applicability.get("scope") or sorted(
        body.confirmed_location_ids
    ) != sorted(row.applicability.get("location_ids", [])):
        raise HTTPException(409, "Publication scope confirmation is stale")
    result = await preflight(db, row, actor.organization)
    if not result["valid"]:
        row.validation = result
        row.policy_versions = result["policy_versions"]
        row.updated_at = datetime.now(UTC)
        row.updated_by = actor.user_id
        audit(
            db,
            actor.user_id,
            "publish.blocked",
            "cms_revision",
            row.id,
            blockers=result["blockers"],
        )
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "message": "Publication is blocked",
                    **result,
                    "revision_updated_at": row.updated_at.isoformat(),
                }
            },
        )
    runtime_payload = {
        "revision_id": row.id,
        "idempotency_key": body.idempotency_key,
        "expected_updated_at": body.expected_updated_at,
        "confirmed_scope": body.confirmed_scope,
        "confirmed_location_ids": sorted(body.confirmed_location_ids),
    }
    decision = await decide_tenant(
        db,
        actor.user_id,
        "cms.cms_publication.publish",
        selected_location_id=actor.selected_location_id,
    )
    approval = None
    if decision.needs_approval:
        if body.approval_request_id:
            approval = await authorize_runtime_action(
                db,
                request_id=body.approval_request_id,
                permission_key="cms.cms_publication.publish",
                payload=runtime_payload,
                maker_id=actor.user_id,
                request_model=TenantChangeRequest,
            )
        else:
            approval, created = await create_runtime_action_request(
                db,
                permission_key="cms.cms_publication.publish",
                payload=runtime_payload,
                reason=body.reason,
                maker_id=actor.user_id,
                context=await tenant_policy_context(db),
                request_model=TenantChangeRequest,
                policy_model=TenantApprovalPolicy,
            )
            audit(
                db,
                actor.user_id,
                "publish.approval-requested",
                "cms_revision",
                row.id,
                request_id=approval.id,
                created=created,
            )
            return JSONResponse(
                status_code=202,
                content=jsonable_encoder({
                    "status": "approval_required",
                    "request": await request_payload(db, approval, TenantChangeDecision),
                }),
            )
    row.validation = result
    row.policy_versions = result["policy_versions"]
    row.updated_at = datetime.now(UTC)
    row.updated_by = actor.user_id
    await activate_publication(db, row, actor.user_id, body.idempotency_key)
    if approval:
        await complete_runtime_action(
            approval,
            {"resource": "cms_revision", "resource_id": row.id},
        )
    audit(
        db,
        actor.user_id,
        "publish",
        "cms_revision",
        row.id,
        scope=row.applicability,
        policy_versions=row.policy_versions,
        idempotency_key=body.idempotency_key,
    )
    return revision_payload(row)


# Handle rollback publication for this module.
@router.post("/cms/revisions/{identifier}/rollback")
async def rollback_publication(
    identifier: str,
    body: PublishInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    await lock_publication_state(db)
    existing = await db.scalar(
        select(CmsRevision).where(CmsRevision.publication_key == body.idempotency_key)
    )
    if existing:
        if existing.base_revision_id != identifier:
            raise HTTPException(409, "Publication key belongs to another action")
        return revision_payload(existing)
    target = await db.get(CmsRevision, identifier)
    if target is None or target.status != "published":
        raise HTTPException(409, "Rollback target must be a published revision")
    assert_current(target, body.expected_updated_at)
    if body.confirmed_scope != target.applicability.get("scope") or sorted(
        body.confirmed_location_ids
    ) != sorted(target.applicability.get("location_ids", [])):
        raise HTTPException(409, "Rollback scope confirmation is stale")
    result = await preflight(db, target, actor.organization)
    if not result["valid"]:
        audit(
            db,
            actor.user_id,
            "publish.rollback-blocked",
            "cms_revision",
            target.id,
            blockers=result["blockers"],
        )
        return JSONResponse(
            status_code=422,
            content={"detail": {"message": "Rollback is blocked", **result}},
        )
    number = (await db.scalar(select(func.max(CmsRevision.revision_number))) or 0) + 1
    restored = CmsRevision(
        revision_number=number,
        status="draft",
        base_revision_id=target.id,
        content=target.content,
        applicability=target.applicability,
        validation=result,
        policy_versions=result["policy_versions"],
        created_by=actor.user_id,
        updated_by=actor.user_id,
    )
    db.add(restored)
    await db.flush()
    await sync_media(db, restored, actor.user_id, source_revision_id=target.id)
    await activate_publication(db, restored, actor.user_id, body.idempotency_key)
    audit(
        db,
        actor.user_id,
        "publish.rollback",
        "cms_revision",
        restored.id,
        restored_from=target.id,
        scope=restored.applicability,
        policy_versions=restored.policy_versions,
    )
    return revision_payload(restored)


# Handle decode preview token for this module.
def decode_preview_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            application_settings().jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            audience="dhmis-cms-preview",
            issuer="dhmis",
            options={"require": ["sub", "org", "revision", "iat", "exp"]},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Preview link is invalid or expired") from None


# Handle preview context for this module.
async def preview_context(token: str):
    payload = decode_preview_token(token)
    async with control_session() as control:
        from app.organizations.models import Organization

        organization = await control.get(Organization, payload["org"])
    if organization is None or organization.status != "active":
        raise HTTPException(404, "Organization not found")
    async with organization_session(organization) as db:
        row = await db.get(CmsRevision, payload["revision"])
        if row is None:
            raise HTTPException(404, "CMS revision not found")
    return organization, row


# Handle preview for this module.
@router.get("/cms/preview/{token}")
async def preview(token: str):
    organization, row = await preview_context(token)
    result = await storefront_data(
        organization,
        override_content=row.content,
        preview_revision=row.id,
    )
    for asset in result["content"].get("media", []):
        asset["file_url"] = f"/v1/cms/preview/{token}/media/{asset['key']}"
    return result


# Handle preview media for this module.
@router.get("/cms/preview/{token}/media/{asset_key}")
async def preview_media(token: str, asset_key: str):
    organization, row = await preview_context(token)
    async with organization_session(organization) as db:
        asset = await db.scalar(
            select(CmsMediaAsset).where(
                CmsMediaAsset.revision_id == row.id,
                CmsMediaAsset.asset_key == asset_key,
                CmsMediaAsset.visible,
            )
        )
        if asset is None or not asset.content:
            raise HTTPException(404, "CMS media not found")
        return Response(content=asset.content, media_type=asset.mime_type)

__all__ = ["ContentInput", "cms", "update_cms", "revisions", "draft", "save_draft", "upload_media", "draft_media", "publication_preflight", "preview_token", "publish", "rollback_publication", "decode_preview_token", "preview_context", "preview", "preview_media", "router"]
