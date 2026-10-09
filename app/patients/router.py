from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import exists, or_, select

from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.identity.service import db_session, permit
from app.rbac.dependencies import permit_tenant
from app.rbac.models import TenantApprovalPolicy, TenantChangeDecision, TenantChangeRequest
from app.rbac.runtime import decide_tenant, tenant_policy_context
from app.rbac.workflow import (
    authorize_runtime_action,
    complete_runtime_action,
    create_runtime_action_request,
    request_payload,
)
from app.organizations.models import Location
from app.patients.models import GuardianLink, Patient
from app.patients.schemas import PatientCreate

router = APIRouter(prefix="/patients", tags=["Patients"])


@router.get("")
async def patients(
    q: str = Query("", max_length=80), db=Depends(db_session), actor=Depends(permit("patients"))
):
    query = select(Patient).where(Patient.archived_at.is_(None)).order_by(
        Patient.last_name, Patient.first_name
    ).limit(200)
    if q:
        query = query.where(or_(Patient.first_name.ilike(f"%{q}%"), Patient.last_name.ilike(f"%{q}%")))
    rows = (await db.scalars(query)).all()
    audit(db, actor.user_id, "read", "patients", count=len(rows))
    return [serialize(row) for row in rows]


@router.post("", status_code=201)
async def create(body: PatientCreate, db=Depends(db_session), actor=Depends(permit("patients"))):
    await required(db, Location, body.location_id)
    row = await add(db, Patient, body.model_dump(), actor.user_id)
    audit(db, actor.user_id, "create", "patients", row.id)
    return serialize(row)


@router.put("/{identifier}")
async def update(
    identifier: str, body: PatientCreate, db=Depends(db_session), actor=Depends(permit("patients"))
):
    row = await required(db, Patient, identifier, lock=True)
    if row.archived_at is not None:
        raise HTTPException(409, "Archived patient profiles are read-only")
    await required(db, Location, body.location_id)
    for key, value in body.model_dump().items():
        setattr(row, key, value)
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "update", "patients", row.id)
    await db.flush()
    return serialize(row)


class ArchiveInput(BaseModel):
    reason: str = Field(min_length=10, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)


async def _archive_patient(
    identifier: str,
    body: ArchiveInput,
    actor,
    db,
    *,
    restore: bool = False,
):
    permission_key = "patients.patient_profile.restore" if restore else "patients.patient_profile.archive"
    row = await required(db, Patient, identifier, lock=True)
    if restore and row.archived_at is None:
        raise HTTPException(409, "Patient profile is not archived")
    if not restore and row.archived_at is not None:
        raise HTTPException(409, "Patient profile is already archived")
    if not restore:
        linked = await db.scalar(
            select(exists().where(
                or_(GuardianLink.guardian_id == row.id, GuardianLink.dependent_id == row.id)
            ))
        )
        if linked:
            raise HTTPException(409, "Remove guardian/dependent links before archiving this profile")
    payload = {"patient_id": row.id, "restore": restore, "reason": body.reason.strip()}
    decision = await decide_tenant(db, actor.user_id, permission_key, selected_location_id=row.location_id)
    if not decision.allowed or decision.needs_step_up:
        raise HTTPException(403, "Permission denied")
    approval = None
    if decision.needs_approval:
        if body.approval_request_id:
            approval = await authorize_runtime_action(
                db,
                request_id=body.approval_request_id,
                permission_key=permission_key,
                payload=payload,
                maker_id=actor.user_id,
                request_model=TenantChangeRequest,
            )
        else:
            approval, created = await create_runtime_action_request(
                db,
                permission_key=permission_key,
                payload=payload,
                reason=body.reason,
                maker_id=actor.user_id,
                context=await tenant_policy_context(db),
                request_model=TenantChangeRequest,
                policy_model=TenantApprovalPolicy,
            )
            audit(db, actor.user_id, "archive.approval-requested", "patients", row.id, reason=body.reason)
            return JSONResponse(
                status_code=202,
                content=jsonable_encoder({
                    "status": "approval_required",
                    "request": await request_payload(db, approval, TenantChangeDecision),
                    "created": created,
                }),
            )
    if restore:
        row.archived_at = None
        row.archived_by = None
        row.archive_reason = ""
        action = "restore"
    else:
        row.archived_at = datetime.now(UTC)
        row.archived_by = actor.user_id
        row.archive_reason = body.reason.strip()
        action = "archive"
    row.updated_by = actor.user_id
    audit(db, actor.user_id, action, "patients", row.id, reason=body.reason)
    if approval:
        await complete_runtime_action(approval, {"resource": "patient_profile", "resource_id": row.id})
    await db.flush()
    return serialize(row)


@router.post("/{identifier}/archive", status_code=200)
async def archive(
    identifier: str,
    body: ArchiveInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("patients.patient_profile.archive", workflow_handles_approval=True)),
):
    return await _archive_patient(identifier, body, actor, db)


@router.post("/{identifier}/restore", status_code=200)
async def restore(
    identifier: str,
    body: ArchiveInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("patients.patient_profile.restore", workflow_handles_approval=True)),
):
    return await _archive_patient(identifier, body, actor, db, restore=True)


class GuardianInput(BaseModel):
    guardian_id: str
    dependent_id: str
    relationship: str = Field(min_length=2, max_length=60)


@router.post("/guardian-links", status_code=201)
async def guardian(body: GuardianInput, db=Depends(db_session), actor=Depends(permit("patients"))):
    from fastapi import HTTPException

    if body.guardian_id == body.dependent_id:
        raise HTTPException(422, "A patient cannot be their own guardian")
    await required(db, Patient, body.guardian_id)
    dependent = await required(db, Patient, body.dependent_id)
    existing = await db.scalar(
        select(GuardianLink).where(
            GuardianLink.guardian_id == body.guardian_id, GuardianLink.dependent_id == body.dependent_id
        )
    )
    if existing:
        return serialize(existing)
    row = await add(
        db, GuardianLink, {**body.model_dump(), "location_id": dependent.location_id}, actor.user_id
    )
    audit(db, actor.user_id, "link", "patients", dependent.id, guardian_id=body.guardian_id)
    return serialize(row)


@router.get("/{identifier}/family")
async def family(identifier: str, db=Depends(db_session), actor=Depends(permit("patients"))):
    await required(db, Patient, identifier)
    rows = (
        await db.scalars(
            select(GuardianLink).where(
                or_(GuardianLink.guardian_id == identifier, GuardianLink.dependent_id == identifier)
            )
        )
    ).all()
    audit(db, actor.user_id, "read-family", "patients", identifier)
    return [serialize(x) for x in rows]
