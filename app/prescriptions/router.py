from datetime import datetime, timezone
from html import escape

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.identity.models import StaffUser
from app.identity.service import db_session, permit, user_has_module
from app.operations.service import require_current_credentials
from app.patients.models import Patient
from app.prescriptions.models import MedicationSafetyRule, Prescription
from app.prescriptions.service import safety_flags

router = APIRouter(prefix="/prescriptions", tags=["Prescriptions"])


class PrescriptionInput(BaseModel):
    patient_id: str
    prescriber_id: str
    medication: str = Field(min_length=2, max_length=160)
    dosage: str = Field(min_length=1, max_length=120)
    route: str = Field(default="oral", min_length=1, max_length=60)
    frequency: str = Field(min_length=1, max_length=120)
    duration_days: int = Field(ge=1, le=365)
    instructions: str = Field(default="", max_length=1000)
    controlled_substance: bool = False
    override_reason: str = Field(default="", max_length=1000)


class SafetyRuleInput(BaseModel):
    medication: str = Field(min_length=2, max_length=160)
    conflicts: list[str] = Field(min_length=1, max_length=100)
    severity: str = Field(pattern="^(warning|block)$", default="warning")
    message: str = Field(min_length=5, max_length=500)


@router.get("/patient/{patient_id}")
async def history(patient_id: str, db=Depends(db_session), actor=Depends(permit("prescriptions"))):
    await required(db, Patient, patient_id)
    rows = (
        await db.scalars(
            select(Prescription)
            .where(Prescription.patient_id == patient_id)
            .order_by(Prescription.issued_at.desc())
        )
    ).all()
    audit(db, actor.user_id, "read", "prescriptions", patient_id, patient_id=patient_id)
    return [serialize(row) for row in rows]


@router.post("", status_code=201)
async def issue(
    body: PrescriptionInput,
    db=Depends(db_session),
    actor=Depends(permit("prescriptions")),
):
    patient = await required(db, Patient, body.patient_id)
    prescriber = await required(db, StaffUser, body.prescriber_id)
    if not await user_has_module(db, prescriber, "prescriptions") or not prescriber.active:
        raise HTTPException(422, "An active dentist or administrator must prescribe")
    await require_current_credentials(db, prescriber.id)
    flags = await safety_flags(db, patient, body.medication)
    if flags and len(body.override_reason.strip()) < 10:
        raise HTTPException(
            409,
            {"message": "Safety flags require an explicit override reason", "safety_flags": flags},
        )
    row = await add(
        db,
        Prescription,
        {
            **body.model_dump(),
            "location_id": patient.location_id,
            "safety_flags": flags,
            "issued_at": datetime.now(timezone.utc),
        },
        actor.user_id,
    )
    audit(
        db,
        actor.user_id,
        "issue",
        "prescriptions",
        row.id,
        patient_id=patient.id,
        controlled_substance=body.controlled_substance,
        safety_override=bool(flags),
    )
    return serialize(row)


@router.post("/{identifier}/cancel")
async def cancel(identifier: str, db=Depends(db_session), actor=Depends(permit("prescriptions"))):
    row = await required(db, Prescription, identifier, lock=True)
    if row.status == "cancelled":
        return serialize(row)
    row.status = "cancelled"
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "cancel", "prescriptions", row.id, patient_id=row.patient_id)
    return serialize(row)


@router.get("/{identifier}/print", response_class=HTMLResponse)
async def printable(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit("prescriptions")),
):
    row = await required(db, Prescription, identifier)
    patient = await required(db, Patient, row.patient_id)
    prescriber = await required(db, StaffUser, row.prescriber_id)
    audit(db, actor.user_id, "print", "prescriptions", row.id, patient_id=row.patient_id)
    controlled = "<strong>CONTROLLED SUBSTANCE</strong>" if row.controlled_substance else ""
    return HTMLResponse(
        "<!doctype html><html><head><title>Prescription</title>"
        "<style>body{font:16px sans-serif;max-width:700px;margin:48px auto;line-height:1.5}" 
        "@media print{button{display:none}}</style></head><body>"
        f"<h1>Prescription</h1>{controlled}<p>Patient: {escape(patient.first_name)} "
        f"{escape(patient.last_name)}</p><p>Medication: <strong>{escape(row.medication)}</strong> "
        f"{escape(row.dosage)} · {escape(row.route)} · {escape(row.frequency)}</p>"
        f"<p>Duration: {row.duration_days} days</p><p>{escape(row.instructions)}</p>"
        f"<p>Prescriber: {escape(prescriber.name)}</p><p>Issued: {row.issued_at.date()}</p>"
        "<button onclick=\"window.print()\">Print</button></body></html>"
    )


@router.get("/safety-rules/all")
async def rules(db=Depends(db_session), actor=Depends(permit("settings"))):
    return [serialize(row) for row in (await db.scalars(select(MedicationSafetyRule))).all()]


@router.post("/safety-rules", status_code=201)
async def create_rule(
    body: SafetyRuleInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    row = await add(db, MedicationSafetyRule, body.model_dump(), actor.user_id)
    audit(db, actor.user_id, "create", "medication_safety_rules", row.id)
    return serialize(row)
