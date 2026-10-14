"""Patient portal forms routes."""


from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from app.consents.models import Consent
from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.forms.models import FormSubmission, FormTemplate
from app.identity.security import digest
from app.integrations.contracts import SignatureRequest
from app.integrations.registry import resolve
from app.patient_identity.service import (
    PatientActor,
    authorized_patient_ids,
    current_patient,
    patient_db_session,
    require_patient_access,
)
from app.patients.models import Patient

router = APIRouter()

# Handle forms for this module.
@router.get("/forms")
async def forms(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    templates = (await db.scalars(select(FormTemplate).where(FormTemplate.active))).all()
    identifiers = await authorized_patient_ids(db, actor)
    submissions = (
        await db.scalars(select(FormSubmission).where(FormSubmission.patient_id.in_(identifiers)))
    ).all()
    return {"templates": [serialize(row) for row in templates], "submissions": [serialize(row) for row in submissions]}


# Defines the form response model, contract, or value object.
class FormResponse(BaseModel):
    patient_id: str
    responses: dict[str, str | bool | int | float | None]


# Create or issue submit form while applying existing validation and authorization.
@router.post("/forms/{template_id}", status_code=201)
async def submit_form(
    template_id: str,
    body: FormResponse,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    await require_patient_access(db, actor, body.patient_id)
    patient = await required(db, Patient, body.patient_id)
    template = await required(db, FormTemplate, template_id)
    expected = {field["name"] for field in template.fields}
    if set(body.responses) - expected:
        raise HTTPException(422, "Form contains unknown fields")
    row = await add(
        db,
        FormSubmission,
        {
            "template_id": template.id,
            "patient_id": patient.id,
            "location_id": patient.location_id,
            "template_version": template.version,
            "responses": body.responses,
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "portal.form", "form_submissions", row.id, patient_id=patient.id)
    return serialize(row)


# Handle consents for this module.
@router.get("/consents")
async def consents(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    identifiers = await authorized_patient_ids(db, actor)
    rows = (
        await db.scalars(
            select(Consent)
            .where(Consent.patient_id.in_(identifiers))
            .order_by(Consent.created_at.desc())
        )
    ).all()
    audit(db, actor.user_id, "portal.read", "consents", patient_id=actor.patient_id)
    return [serialize(row) for row in rows]


# Handle sign consent for this module.
@router.post("/consents/{identifier}/sign")
async def sign_consent(
    identifier: str,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    row = await required(db, Consent, identifier, lock=True)
    await require_patient_access(db, actor, row.patient_id)
    if row.status not in ("requested", "awaiting_signature"):
        raise HTTPException(409, "Consent is not awaiting a signature")
    patient = await required(db, Patient, row.patient_id)
    provider = resolve(actor.organization, "signature_provider")
    result = await provider.request_signature(
        SignatureRequest(
            idempotency_key=row.id,
            document_id=row.id,
            document_digest=digest(row.title + row.template_version),
            signer_name=patient.first_name + " " + patient.last_name,
            signer_email=patient.email,
        )
    )
    if result.sandbox:
        result = await provider.get_signature(result.reference)
        row.status = "simulated"
    else:
        row.status = "awaiting_signature"
    row.certificate = {**result.certificate, "reference": result.reference}
    row.updated_by = actor.user_id
    audit(
        db,
        actor.user_id,
        "portal.signature",
        "consents",
        row.id,
        patient_id=row.patient_id,
        sandbox=result.sandbox,
    )
    await db.flush()
    return serialize(row)


