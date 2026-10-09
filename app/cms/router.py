import base64
import binascii
import hashlib
import time as epoch_time
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import func, select

from app.cms.models import CmsMediaAsset, CmsRevision
from app.cms.schemas import CmsContentInput, DraftInput, MediaUploadInput, PublishInput
from app.cms.service import (
    activate_publication,
    assert_current,
    default_content,
    ensure_draft,
    lock_publication_state,
    preflight,
    public_content,
    published_revision,
    revision_payload,
    sync_media,
)
from app.core.audit import audit
from app.core.config import settings as application_settings
from app.core.database import control_session, organization_session
from app.core.rate_limit import get_fo_throttle_args
from app.core.repository import add
from app.identity.models import StaffUser
from app.identity.router import throttle
from app.identity.service import Actor, db_session, permit, role_names_with_module
from app.integrations.configuration import attach_effective_adapters
from app.organizations.configuration import configure_tenant, tenant_settings
from app.organizations.models import Location
from app.organizations.tenant_resolution import resolve_organization
from app.patients.models import Patient
from app.rbac.dependencies import permit_tenant
from app.rbac.models import TenantApprovalPolicy, TenantChangeDecision, TenantChangeRequest
from app.rbac.runtime import decide_tenant, tenant_policy_context
from app.rbac.workflow import (
    authorize_runtime_action,
    complete_runtime_action,
    create_runtime_action_request,
    request_payload,
)
from app.scheduling.models import Appointment
from app.scheduling.schemas import Booking
from app.scheduling.service import book

router = APIRouter(tags=["Front Office CMS"])


class ContentInput(BaseModel):
    headline: str = Field(min_length=2, max_length=180)
    introduction: str = Field(min_length=2, max_length=2000)
    contact_email: str = Field(default="", max_length=254)
    contact_phone: str = Field(default="", max_length=40)
    logo_url: str = Field(default="", max_length=500)


@router.get("/cms")
async def cms(db=Depends(db_session), actor=Depends(permit("settings"))):
    return (await tenant_settings(db)).public_content


@router.put("/cms")
async def update_cms(
    body: ContentInput, db=Depends(db_session), actor=Depends(permit("settings"))
):
    await configure_tenant(db, public_content=body.model_dump(), actor_id=actor.user_id)
    audit(db, actor.user_id, "configure", "cms", actor.organization.id)
    return body.model_dump()


@router.get("/cms/revisions")
async def revisions(db=Depends(db_session), actor=Depends(permit("settings"))):
    rows = (
        await db.scalars(
            select(CmsRevision).order_by(CmsRevision.revision_number.desc()).limit(100)
        )
    ).all()
    return [revision_payload(row) for row in rows]


@router.get("/cms/revisions/draft")
async def draft(db=Depends(db_session), actor=Depends(permit("settings"))):
    row = await ensure_draft(db, actor.organization, actor.user_id)
    audit(db, actor.user_id, "draft.read", "cms_revision", row.id)
    return revision_payload(row)


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
    row.content = body.content.model_dump(mode="json")
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


async def public_organization(identifier: str, surface: str):
    return (
        await resolve_organization(organization_id=identifier, surface=surface)
    ).organization


@router.get("/public/organizations/{organization_id}")
async def storefront(organization_id: str, location_id: str | None = Query(default=None)):
    organization = await public_organization(organization_id, "public")
    return await storefront_data(organization, location_id=location_id)


async def storefront_data(
    organization,
    override_content: dict | None = None,
    preview_revision: str = "",
    location_id: str | None = None,
):
    async with organization_session(organization) as db:
        settings = await tenant_settings(db)
        revision = (
            None
            if override_content is not None
            else await published_revision(db, location_id=location_id)
        )
        content = override_content or (revision.content if revision else await default_content(db, organization))
        locations = (await db.scalars(select(Location).order_by(Location.name))).all()
        providers = (
            await db.scalars(
                select(StaffUser).where(
                    StaffUser.active, StaffUser.role.in_(await role_names_with_module(db, "clinical"))
                )
            )
        ).all()
    content_locations = {
        item.get("location_id"): item for item in content.get("locations", [])
    }
    return {
        "organization_id": organization.id,
        "slug": organization.slug,
        "name": organization.name,
        "branding": settings.branding,
        "content": public_content(content),
        "cms_revision_id": preview_revision or (revision.id if revision else None),
        "cms_source": "preview" if preview_revision else "published" if revision else "provisioned-default",
        "booking_widget": settings.booking_widget,
        "services": [
            {
                "id": row["id"],
                "code": row["id"],
                "name": row["title"],
                "fee_cents": row.get("fee_cents") or 0,
                "fee_mode": row.get("fee_mode", "from"),
                "description": row.get("description", ""),
                "icon": row.get("icon", "tooth"),
            }
            for row in sorted(content.get("services", []), key=lambda item: item.get("order", 0))
            if row.get("visible", True)
        ],
        "locations": [
            {
                "id": row.id,
                "name": content_locations.get(row.id, {}).get("name") or row.name,
                "address": content_locations.get(row.id, {}).get("address", ""),
                "phone": content_locations.get(row.id, {}).get("phone", ""),
                "email": content_locations.get(row.id, {}).get("email", ""),
                "timezone": content_locations.get(row.id, {}).get("timezone") or row.timezone,
                "hours": content_locations.get(row.id, {}).get("hours", {}),
                "closure_note": content_locations.get(row.id, {}).get("closure_note", ""),
                "chairs": row.chairs,
                "opening_hour": row.opening_hour,
                "closing_hour": row.closing_hour,
            }
            for row in locations
        ],
        "providers": [{"id": row.id, "name": row.name, "location_ids": row.location_ids} for row in providers],
    }


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
        if location is None or provider is None or not provider.active:
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


@router.get("/public/tenants/{tenant_slug}")
async def storefront_by_slug(tenant_slug: str, location_id: str | None = Query(default=None)):
    resolution = await resolve_organization(slug=tenant_slug, surface="public")
    return await storefront_data(resolution.organization, location_id=location_id)


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


@router.get("/booking/tenants/{tenant_slug}")
async def booking_context(tenant_slug: str):
    resolution = await resolve_organization(slug=tenant_slug, surface="booking")
    return await storefront_data(resolution.organization)


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


@router.post("/booking/tenants/{tenant_slug}/appointments", status_code=201)
async def booking_by_slug(
    tenant_slug: str, body: PublicBooking, request: Request
):
    resolution = await resolve_organization(slug=tenant_slug, surface="booking")
    return await public_booking(resolution.organization.id, body, request)
