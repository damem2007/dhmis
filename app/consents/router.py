from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.consents.models import Consent
from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.identity.security import digest
from app.identity.service import db_session, permit
from app.integrations.contracts import SignatureRequest
from app.integrations.registry import resolve
from app.patients.models import Patient

router = APIRouter(prefix="/consents", tags=["Sandbox consents"])


class ConsentInput(BaseModel):
    patient_id: str
    title: str = Field(min_length=3, max_length=180)


@router.get("/{patient_id}")
async def consents(patient_id: str, db=Depends(db_session), actor=Depends(permit("consents"))):
    rows = (await db.scalars(select(Consent).where(Consent.patient_id == patient_id))).all()
    audit(db, actor.user_id, "read", "consents", patient_id)
    return [serialize(x) for x in rows]


@router.post("", status_code=201)
async def request(body: ConsentInput, db=Depends(db_session), actor=Depends(permit("consents"))):
    patient = await required(db, Patient, body.patient_id)
    row = await add(db, Consent, {**body.model_dump(), "location_id": patient.location_id}, actor.user_id)
    audit(db, actor.user_id, "request", "consents", row.id)
    return serialize(row)


@router.post("/{identifier}/simulate-signature")
async def complete(identifier: str, db=Depends(db_session), actor=Depends(permit("consents"))):
    row = await required(db, Consent, identifier, lock=True)
    patient = await required(db, Patient, row.patient_id)
    provider = resolve(actor.organization, "signature_provider")
    request = await provider.request_signature(
        SignatureRequest(
            idempotency_key=row.id,
            document_id=row.id,
            document_digest=digest(row.title + row.template_version),
            signer_name=patient.first_name + " " + patient.last_name,
            signer_email=patient.email,
        )
    )
    from fastapi import HTTPException

    if not request.sandbox:
        raise HTTPException(409, "Use the live provider completion event; simulation is sandbox-only")
    result = await provider.get_signature(request.reference)
    row.certificate = result.certificate
    row.status = "simulated"
    from app.clinical.models import TreatmentPlan

    plan = await db.scalar(select(TreatmentPlan).where(TreatmentPlan.consent_id == row.id).with_for_update())
    if plan:
        plan.status = "accepted_simulated"
        plan.updated_by = actor.user_id
        audit(db, actor.user_id, "accept-simulated", "treatment_plans", plan.id, patient_id=plan.patient_id)
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "simulate-signature", "consents", row.id, sandbox=True)
    await db.flush()
    return serialize(row)
