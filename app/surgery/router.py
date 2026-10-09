from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.clinical.models import Encounter
from app.clinical.service import close_encounter
from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.identity.service import db_session, permit
from app.surgery.models import DaySurgeryAdmission

router = APIRouter(prefix="/day-surgery", tags=["Day surgery"])
REQUIRED_PREOP = {
    "identity_confirmed",
    "consent_verified",
    "medical_history_reviewed",
    "allergies_reviewed",
    "fasting_confirmed",
    "escort_confirmed",
}


class AdmissionInput(BaseModel):
    encounter_id: str
    procedure_name: str = Field(min_length=3, max_length=180)


class PreOpInput(BaseModel):
    checklist: dict[str, bool]


class AnesthesiaInput(BaseModel):
    recorded_at: datetime | None = None
    agent: str = Field(min_length=2, max_length=160)
    dose: str = Field(min_length=1, max_length=120)
    route: str = Field(min_length=1, max_length=60)
    vitals: dict[str, str | int | float] = Field(default_factory=dict)
    note: str = Field(default="", max_length=2000)


class RecoveryInput(BaseModel):
    recovery_notes: str = Field(min_length=10, max_length=8000)


class DischargeInput(BaseModel):
    discharge_summary: str = Field(min_length=10, max_length=8000)


@router.get("/patient/{patient_id}")
async def admissions(
    patient_id: str,
    db=Depends(db_session),
    actor=Depends(permit("surgery")),
):
    rows = (
        await db.scalars(
            select(DaySurgeryAdmission)
            .where(DaySurgeryAdmission.patient_id == patient_id)
            .order_by(DaySurgeryAdmission.created_at.desc())
        )
    ).all()
    audit(db, actor.user_id, "read", "day_surgery", patient_id, patient_id=patient_id)
    return [serialize(row) for row in rows]


@router.post("/admissions", status_code=201)
async def admit(
    body: AdmissionInput,
    db=Depends(db_session),
    actor=Depends(permit("surgery")),
):
    encounter = await required(db, Encounter, body.encounter_id, lock=True)
    if encounter.status != "open":
        raise HTTPException(409, "An open checked-in encounter is required")
    existing = await db.scalar(
        select(DaySurgeryAdmission).where(DaySurgeryAdmission.encounter_id == encounter.id)
    )
    if existing:
        return serialize(existing)
    encounter.care_setting = "day_surgery"
    encounter.updated_by = actor.user_id
    row = await add(
        db,
        DaySurgeryAdmission,
        {
            "encounter_id": encounter.id,
            "patient_id": encounter.patient_id,
            "location_id": encounter.location_id,
            "provider_id": encounter.provider_id,
            "procedure_name": body.procedure_name,
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "admit", "day_surgery", row.id, patient_id=row.patient_id)
    return serialize(row)


@router.put("/admissions/{identifier}/preop")
async def preop(
    identifier: str,
    body: PreOpInput,
    db=Depends(db_session),
    actor=Depends(permit("surgery")),
):
    row = await required(db, DaySurgeryAdmission, identifier, lock=True)
    if row.status not in ("admitted", "preop_complete"):
        raise HTTPException(409, "Pre-op checklist cannot change after the procedure begins")
    if set(body.checklist) != REQUIRED_PREOP or not all(body.checklist.values()):
        raise HTTPException(422, "Every required pre-op item must be explicitly confirmed")
    row.preop_checklist = body.checklist
    row.status = "preop_complete"
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "preop", "day_surgery", row.id, patient_id=row.patient_id)
    return serialize(row)


@router.post("/admissions/{identifier}/start")
async def start(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit("surgery")),
):
    row = await required(db, DaySurgeryAdmission, identifier, lock=True)
    if row.status != "preop_complete":
        raise HTTPException(409, "Complete the pre-op checklist before starting")
    row.status = "in_procedure"
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "start", "day_surgery", row.id, patient_id=row.patient_id)
    return serialize(row)


@router.post("/admissions/{identifier}/anesthesia")
async def anesthesia(
    identifier: str,
    body: AnesthesiaInput,
    db=Depends(db_session),
    actor=Depends(permit("surgery")),
):
    row = await required(db, DaySurgeryAdmission, identifier, lock=True)
    if row.status != "in_procedure":
        raise HTTPException(409, "Anesthesia can be recorded only during the procedure")
    records = list(row.anesthesia_records)
    records.append(
        {
            **body.model_dump(exclude={"recorded_at"}),
            "recorded_at": (body.recorded_at or datetime.now(timezone.utc)).isoformat(),
            "recorded_by": actor.user_id,
        }
    )
    row.anesthesia_records = records
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "anesthesia", "day_surgery", row.id, patient_id=row.patient_id)
    return serialize(row)


@router.put("/admissions/{identifier}/recovery")
async def recovery(
    identifier: str,
    body: RecoveryInput,
    db=Depends(db_session),
    actor=Depends(permit("surgery")),
):
    row = await required(db, DaySurgeryAdmission, identifier, lock=True)
    if row.status != "in_procedure" or not row.anesthesia_records:
        raise HTTPException(409, "An anesthesia record is required before recovery")
    row.recovery_notes = body.recovery_notes
    row.status = "recovery"
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "recovery", "day_surgery", row.id, patient_id=row.patient_id)
    return serialize(row)


@router.post("/admissions/{identifier}/discharge")
async def discharge(
    identifier: str,
    body: DischargeInput,
    db=Depends(db_session),
    actor=Depends(permit("surgery")),
):
    row = await required(db, DaySurgeryAdmission, identifier, lock=True)
    if row.status != "recovery" or not row.recovery_notes.strip():
        raise HTTPException(409, "Recovery documentation is required before discharge")
    row.discharge_summary = body.discharge_summary
    row.status = "discharged"
    row.updated_by = actor.user_id
    encounter = await required(db, Encounter, row.encounter_id, lock=True)
    await close_encounter(db, actor, encounter, require_soap=False)
    audit(db, actor.user_id, "discharge", "day_surgery", row.id, patient_id=row.patient_id)
    return serialize(row)
