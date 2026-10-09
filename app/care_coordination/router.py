from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import select

from app.care_coordination.models import LabCase, Referral
from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.identity.models import StaffUser
from app.identity.service import db_session, permit, user_has_module
from app.patients.models import Patient

router = APIRouter(prefix="/care-coordination", tags=["Labs and referrals"])
LAB_TRANSITIONS = {
    "created": {"in_progress"},
    "in_progress": {"received"},
    "received": {"completed"},
    "completed": set(),
}
REFERRAL_TRANSITIONS = {
    "created": {"in_progress"},
    "in_progress": {"completed"},
    "completed": set(),
}


def result(row):
    values = serialize(row)
    values["overdue"] = row.status != "completed" and row.due_at < datetime.now(timezone.utc)
    return values


class LabInput(BaseModel):
    patient_id: str
    provider_id: str
    case_type: str = Field(min_length=2, max_length=120)
    laboratory: str = Field(min_length=2, max_length=180)
    due_at: AwareDatetime
    notes: str = Field(default="", max_length=2000)


class ReferralInput(BaseModel):
    patient_id: str
    provider_id: str
    direction: str = Field(pattern="^(inbound|outbound)$")
    specialty: str = Field(min_length=2, max_length=120)
    organization_name: str = Field(min_length=2, max_length=180)
    due_at: AwareDatetime
    reason: str = Field(min_length=3, max_length=2000)


class Transition(BaseModel):
    status: str
    note: str = Field(default="", max_length=1000)


async def validate_people(db, patient_id: str, provider_id: str):
    patient = await required(db, Patient, patient_id)
    provider = await required(db, StaffUser, provider_id)
    if not provider.active or not await user_has_module(db, provider, "clinical"):
        raise HTTPException(422, "An active clinical provider is required")
    return patient


async def transition(db, actor, row, body, allowed, resource):
    if body.status not in allowed.get(row.status, set()):
        raise HTTPException(409, f"Cannot move {resource} from {row.status} to {body.status}")
    history = list(row.status_history)
    history.append(
        {
            "from": row.status,
            "to": body.status,
            "note": body.note,
            "at": datetime.now(timezone.utc).isoformat(),
            "actor": actor.user_id,
        }
    )
    row.status = body.status
    row.status_history = history
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "status", resource, row.id, patient_id=row.patient_id)
    await db.flush()
    return result(row)


@router.get("/timeline/{patient_id}")
async def timeline(
    patient_id: str,
    db=Depends(db_session),
    actor=Depends(permit("clinical")),
):
    await required(db, Patient, patient_id)
    labs = (await db.scalars(select(LabCase).where(LabCase.patient_id == patient_id))).all()
    referrals = (
        await db.scalars(select(Referral).where(Referral.patient_id == patient_id))
    ).all()
    audit(db, actor.user_id, "read", "care_coordination", patient_id, patient_id=patient_id)
    return {
        "lab_cases": [result(row) for row in labs],
        "referrals": [result(row) for row in referrals],
    }


@router.get("/overdue")
async def overdue(
    location_id: str | None = Query(default=None),
    db=Depends(db_session),
    actor=Depends(permit("operations")),
):
    now = datetime.now(timezone.utc)
    lab_query = select(LabCase).where(LabCase.status != "completed", LabCase.due_at < now)
    referral_query = select(Referral).where(
        Referral.status != "completed", Referral.due_at < now
    )
    if location_id:
        lab_query = lab_query.where(LabCase.location_id == location_id)
        referral_query = referral_query.where(Referral.location_id == location_id)
    return {
        "lab_cases": [result(row) for row in (await db.scalars(lab_query)).all()],
        "referrals": [result(row) for row in (await db.scalars(referral_query)).all()],
    }


@router.post("/labs", status_code=201)
async def create_lab(
    body: LabInput,
    db=Depends(db_session),
    actor=Depends(permit("clinical")),
):
    patient = await validate_people(db, body.patient_id, body.provider_id)
    values = {
        **body.model_dump(),
        "location_id": patient.location_id,
        "status_history": [
            {"to": "created", "at": datetime.now(timezone.utc).isoformat(), "actor": actor.user_id}
        ],
    }
    row = await add(db, LabCase, values, actor.user_id)
    audit(db, actor.user_id, "create", "lab_cases", row.id, patient_id=patient.id)
    return result(row)


@router.post("/labs/{identifier}/transition")
async def transition_lab(
    identifier: str,
    body: Transition,
    db=Depends(db_session),
    actor=Depends(permit("clinical")),
):
    return await transition(
        db,
        actor,
        await required(db, LabCase, identifier, lock=True),
        body,
        LAB_TRANSITIONS,
        "lab_cases",
    )


@router.post("/referrals", status_code=201)
async def create_referral(
    body: ReferralInput,
    db=Depends(db_session),
    actor=Depends(permit("clinical")),
):
    patient = await validate_people(db, body.patient_id, body.provider_id)
    values = {
        **body.model_dump(),
        "location_id": patient.location_id,
        "status_history": [
            {"to": "created", "at": datetime.now(timezone.utc).isoformat(), "actor": actor.user_id}
        ],
    }
    row = await add(db, Referral, values, actor.user_id)
    audit(db, actor.user_id, "create", "referrals", row.id, patient_id=patient.id)
    return result(row)


@router.post("/referrals/{identifier}/transition")
async def transition_referral(
    identifier: str,
    body: Transition,
    db=Depends(db_session),
    actor=Depends(permit("clinical")),
):
    return await transition(
        db,
        actor,
        await required(db, Referral, identifier, lock=True),
        body,
        REFERRAL_TRANSITIONS,
        "referrals",
    )
