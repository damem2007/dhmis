import hashlib
import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.billing.pricing import estimate_options
from app.clinical.models import ChartEntry, Encounter, PerioExam, RecordAddendum, TreatmentPlan
from app.clinical.schemas import AddendumInput, Acceptance, ChartInput, EncounterInput, PerioInput, TreatmentInput
from app.clinical.service import close_encounter
from app.consents.models import Consent
from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.forms.models import FormSubmission
from app.identity.models import StaffUser
from app.identity.service import current_actor, db_session, permit
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
from app.surgery.models import DaySurgeryAdmission

router = APIRouter(prefix="/clinical", tags=["Clinical charting"])


ADDENDUM_PERMISSIONS = {
    "encounter": "clinical.clinical_note.add_addendum",
    "perio_exam": "clinical.periodontal_chart.add_addendum",
    "treatment_plan": "clinical.treatment_plan.add_addendum",
    "day_surgery": "clinical.admission_day_surgery_record.add_addendum",
    "form_submission": "clinical.completed_patient_form.add_addendum",
}


def addendum_permission_actor():
    async def guard(request: Request, body: AddendumInput, actor=Depends(current_actor)):
        return await permit_tenant(
            ADDENDUM_PERMISSIONS[body.record_type],
            workflow_handles_approval=True,
        )(request, actor)

    return guard


async def validate_encounter(db, identifier, patient_id):
    if identifier:
        encounter = await required(db, Encounter, identifier)
        if encounter.patient_id != patient_id or encounter.status != "open":
            raise HTTPException(409, "An open encounter for this patient is required")


@router.get("/{patient_id}")
async def chart(patient_id: str, db=Depends(db_session), actor=Depends(permit("clinical"))):
    await required(db, Patient, patient_id)
    result = {}
    for key, model in [
        ("entries", ChartEntry),
        ("perio_exams", PerioExam),
        ("encounters", Encounter),
        ("treatment_plans", TreatmentPlan),
    ]:
        rows = (
            await db.scalars(
                select(model).where(model.patient_id == patient_id).order_by(model.created_at.desc())
            )
        ).all()
        result[key] = [serialize(x) for x in rows]
    complete = [x for x in result["perio_exams"] if x["status"] == "complete"]
    result["perio_comparison"] = {}
    if len(complete) >= 2:
        for tooth, current in complete[0]["measurements"].items():
            prior = complete[1]["measurements"].get(tooth)
            if isinstance(prior, dict):
                result["perio_comparison"][tooth] = [
                    a - b for a, b in zip(current["depths"], prior["depths"], strict=True)
                ]
    audit(db, actor.user_id, "read", "clinical", patient_id, patient_id=patient_id)
    return result


@router.post("/addenda", status_code=201)
async def addendum(
    body: AddendumInput,
    db=Depends(db_session),
    actor=Depends(addendum_permission_actor()),
):
    models = {
        "encounter": Encounter,
        "perio_exam": PerioExam,
        "treatment_plan": TreatmentPlan,
        "day_surgery": DaySurgeryAdmission,
        "form_submission": FormSubmission,
    }
    row = await required(db, models[body.record_type], body.record_id, lock=True)
    patient_id = getattr(row, "patient_id", None)
    if not patient_id:
        raise HTTPException(409, "The selected record is not patient-linked")
    patient = await required(db, Patient, patient_id)
    finalized = (
        (body.record_type == "encounter" and row.status == "completed")
        or (body.record_type == "perio_exam" and row.status == "complete")
        or (body.record_type == "treatment_plan" and row.status in {"accepted", "declined", "expired"})
        or (body.record_type == "day_surgery" and row.status in {"discharged", "completed", "finalized"})
        or (body.record_type == "form_submission" and row.status in {"completed", "finalized"})
    )
    if not finalized:
        raise HTTPException(409, "Addenda can only be added to finalized records")
    permission_key = ADDENDUM_PERMISSIONS[body.record_type]
    snapshot = jsonable_encoder(serialize(row))
    payload = {
        "record_type": body.record_type,
        "record_id": row.id,
        "patient_id": patient.id,
        "reason": body.reason.strip(),
        "content": body.content,
        "source_hash": hashlib.sha256(
            json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    decision = await decide_tenant(
        db,
        actor.user_id,
        permission_key,
        selected_location_id=patient.location_id,
    )
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
            return JSONResponse(
                status_code=202,
                content=jsonable_encoder({
                    "status": "approval_required",
                    "request": await request_payload(db, approval, TenantChangeDecision),
                    "created": created,
                }),
            )
    previous = await db.scalar(
        select(RecordAddendum)
        .where(RecordAddendum.record_id == row.id)
        .order_by(RecordAddendum.created_at.desc())
    )
    addendum_row = await add(
        db,
        RecordAddendum,
        {
            "record_type": body.record_type,
            "record_id": row.id,
            "patient_id": patient.id,
            "parent_id": previous.id if previous else None,
            "reason": body.reason.strip(),
            "content": body.content,
            "source_snapshot": snapshot,
            "source_hash": payload["source_hash"],
            "finalized_at": datetime.now(UTC),
            "finalized_by": actor.user_id,
        },
        actor.user_id,
    )
    audit(
        db,
        actor.user_id,
        "addendum",
        "record_addenda",
        addendum_row.id,
        patient_id=patient.id,
        record_type=body.record_type,
        record_id=row.id,
        reason=body.reason,
        source_hash=payload["source_hash"],
    )
    if approval:
        await complete_runtime_action(
            approval,
            {"resource": "record_addendum", "resource_id": addendum_row.id},
        )
    await db.flush()
    return serialize(addendum_row)


@router.get("/{record_type}/{identifier}/addenda")
async def list_addenda(
    record_type: str,
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit("clinical")),
):
    rows = (
        await db.scalars(
            select(RecordAddendum)
            .where(
                RecordAddendum.record_type == record_type,
                RecordAddendum.record_id == identifier,
            )
            .order_by(RecordAddendum.created_at)
        )
    ).all()
    audit(db, actor.user_id, "read-addenda", "record_addenda", identifier, record_type=record_type)
    return [serialize(row) for row in rows]


@router.post("/entries", status_code=201)
async def entry(body: ChartInput, db=Depends(db_session), actor=Depends(permit("clinical"))):
    patient = await required(db, Patient, body.patient_id)
    await validate_encounter(db, body.encounter_id, patient.id)
    row = await add(db, ChartEntry, {**body.model_dump(), "location_id": patient.location_id}, actor.user_id)
    audit(db, actor.user_id, "create", "chart_entries", row.id, patient_id=patient.id)
    return serialize(row)


@router.post("/perio", status_code=201)
async def perio(body: PerioInput, db=Depends(db_session), actor=Depends(permit("clinical"))):
    patient = await required(db, Patient, body.patient_id)
    await validate_encounter(db, body.encounter_id, patient.id)
    row = await add(db, PerioExam, {**body.model_dump(), "location_id": patient.location_id}, actor.user_id)
    audit(db, actor.user_id, "create", "perio_exams", row.id, patient_id=patient.id)
    return serialize(row)


@router.put("/encounters/{identifier}")
async def encounter_update(
    identifier: str, body: EncounterInput, db=Depends(db_session), actor=Depends(permit("clinical"))
):
    row = await required(db, Encounter, identifier, lock=True)
    if row.status != "open":
        raise HTTPException(409, "Closed encounter cannot be changed")
    from app.billing.models import Service

    for p in body.procedures:
        await required(db, Service, p.service_id)
    row.soap = body.soap
    row.procedures = [p.model_dump() for p in body.procedures]
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "update", "encounters", row.id, patient_id=row.patient_id)
    await db.flush()
    return serialize(row)


@router.post("/encounters/{identifier}/complete")
async def encounter_complete(identifier: str, db=Depends(db_session), actor=Depends(permit("clinical"))):
    row = await required(db, Encounter, identifier, lock=True)
    return serialize(await close_encounter(db, actor, row))


@router.post("/treatment-plans", status_code=201)
async def plan(body: TreatmentInput, db=Depends(db_session), actor=Depends(permit("clinical"))):
    patient = await required(db, Patient, body.patient_id)
    await required(db, StaffUser, body.provider_id)
    options = await estimate_options(db, body, patient)
    row = await add(
        db,
        TreatmentPlan,
        {
            "patient_id": patient.id,
            "location_id": patient.location_id,
            "title": body.title,
            "options": options,
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "create", "treatment_plans", row.id, patient_id=patient.id)
    return serialize(row)


@router.post("/treatment-plans/{identifier}/accept")
async def accept(
    identifier: str, body: Acceptance, db=Depends(db_session), actor=Depends(permit("clinical"))
):
    plan = await required(db, TreatmentPlan, identifier, lock=True)
    if body.option >= len(plan.options):
        raise HTTPException(422, "Unknown treatment option")
    if plan.status != "proposed":
        if plan.accepted_option != body.option:
            raise HTTPException(409, "A different option already has a signature request")
        return serialize(plan)
    consent = await add(
        db,
        Consent,
        {
            "patient_id": plan.patient_id,
            "location_id": plan.location_id,
            "title": plan.title + " — " + plan.options[body.option]["name"],
        },
        actor.user_id,
    )
    plan.accepted_option = body.option
    plan.consent_id = consent.id
    plan.status = "awaiting_signature"
    plan.updated_by = actor.user_id
    audit(db, actor.user_id, "request-acceptance", "treatment_plans", plan.id, patient_id=plan.patient_id)
    await db.flush()
    return serialize(plan)
