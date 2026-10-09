from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import func, select

from app.billing.models import Invoice
from app.claims.models import Claim, InsurancePlan
from app.claims.service import adjudicate_claim, reconcile_claim
from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.identity.service import db_session, permit
from app.integrations.contracts import ClaimRequest, EligibilityRequest
from app.integrations.registry import resolve
from app.patients.models import Patient

router = APIRouter(prefix="/claims", tags=["Sandbox claims"])


class PlanInput(BaseModel):
    patient_id: str
    payer_name: str = Field(min_length=2, max_length=160)
    member_id: str = Field(min_length=1, max_length=100)
    priority: int = Field(ge=1, le=2)
    coverage_pct: int = Field(ge=0, le=100, default=80)
    maximum_cents: int = Field(ge=0, default=200000)
    waiting_until: AwareDatetime | None = None


class Submission(BaseModel):
    invoice_id: str
    plan_id: str
    idempotency_key: str = Field(min_length=8, max_length=100)


@router.get("")
async def claims(db=Depends(db_session), actor=Depends(permit("claims"))):
    rows = (await db.scalars(select(Claim).order_by(Claim.created_at.desc()).limit(300))).all()
    audit(db, actor.user_id, "read", "claims", count=len(rows))
    return [serialize(x) for x in rows]


@router.get("/query")
async def claims_query(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=10, le=100),
    status: str = Query(default="", max_length=30),
    network: str = Query(default="", max_length=80),
    location_id: str = Query(default="", max_length=36),
    patient_id: str = Query(default="", max_length=36),
    created_from: datetime | None = Query(default=None),
    created_to: datetime | None = Query(default=None),
    db=Depends(db_session),
    actor=Depends(permit("claims")),
):
    query = select(Claim)
    if status:
        query = query.where(Claim.status == status)
    if network:
        query = query.where(Claim.network == network)
    if location_id:
        query = query.where(Claim.location_id == location_id)
    if patient_id:
        query = query.join(Invoice, Invoice.id == Claim.invoice_id).where(
            Invoice.patient_id == patient_id
        )
    if created_from:
        query = query.where(Claim.created_at >= created_from)
    if created_to:
        query = query.where(Claim.created_at <= created_to)
    total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (
        await db.scalars(
            query.order_by(Claim.created_at.desc(), Claim.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    audit(
        db,
        actor.user_id,
        "read",
        "claims",
        count=len(rows),
        page=page,
        page_size=page_size,
        filters={
            "status": status,
            "network": network,
            "location_id": location_id,
            "patient_id": patient_id,
            "created_from": created_from.isoformat() if created_from else "",
            "created_to": created_to.isoformat() if created_to else "",
        },
    )
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [serialize(row) for row in rows],
    }


@router.get("/plans/{patient_id}")
async def plans(patient_id: str, db=Depends(db_session), actor=Depends(permit("patients"))):
    await required(db, Patient, patient_id)
    rows = (
        await db.scalars(
            select(InsurancePlan)
            .where(InsurancePlan.patient_id == patient_id)
            .order_by(InsurancePlan.priority)
        )
    ).all()
    audit(db, actor.user_id, "read", "insurance_plans", patient_id, patient_id=patient_id)
    return [serialize(x) for x in rows]


@router.post("/plans", status_code=201)
async def plan(body: PlanInput, db=Depends(db_session), actor=Depends(permit("claims"))):
    patient = await required(db, Patient, body.patient_id, lock=True)
    if await db.scalar(
        select(InsurancePlan).where(
            InsurancePlan.patient_id == patient.id, InsurancePlan.priority == body.priority
        )
    ):
        raise HTTPException(409, "Coverage priority already exists for this patient")
    row = await add(
        db, InsurancePlan, {**body.model_dump(), "location_id": patient.location_id}, actor.user_id
    )
    audit(db, actor.user_id, "create", "insurance_plans", row.id, patient_id=patient.id)
    return serialize(row)


@router.post("/plans/{identifier}/eligibility")
async def eligibility(identifier: str, db=Depends(db_session), actor=Depends(permit("patients"))):
    plan = await required(db, InsurancePlan, identifier)
    result = await resolve(actor.organization, "claims_network").check_eligibility(
        EligibilityRequest(
            coverage_pct=plan.coverage_pct,
            maximum_cents=plan.maximum_cents,
            used_cents=plan.used_cents,
            waiting=bool(plan.waiting_until and plan.waiting_until > datetime.now(timezone.utc)),
        )
    )
    audit(
        db, actor.user_id, "eligibility", "insurance_plans", plan.id, patient_id=plan.patient_id, sandbox=True
    )
    return result


@router.post("", status_code=201)
async def submit(body: Submission, db=Depends(db_session), actor=Depends(permit("claims"))):
    invoice = await required(db, Invoice, body.invoice_id, lock=True)
    plan = await required(db, InsurancePlan, body.plan_id)
    if plan.patient_id != invoice.patient_id:
        raise HTTPException(422, "Plan does not belong to the invoice patient")
    existing = await db.scalar(select(Claim).where(Claim.idempotency_key == body.idempotency_key))
    if existing:
        if existing.invoice_id != invoice.id or existing.plan_id != plan.id:
            raise HTTPException(409, "Idempotency key conflicts")
        return serialize(existing)
    previous = (await db.scalars(select(Claim).where(Claim.invoice_id == invoice.id))).all()
    if any(c.plan_id == plan.id for c in previous):
        raise HTTPException(409, "Claim already exists; use its existing status or appeal")
    if plan.priority == 2 and not any(
        c.payer_order == 1 and c.status in ("paid", "denied") for c in previous
    ):
        raise HTTPException(409, "Primary claim must be reconciled or denied before secondary submission")
    amount = invoice.total_cents + invoice.adjustment_cents - invoice.paid_cents
    if amount <= 0:
        raise HTTPException(422, "Invoice has no balance to claim")
    result = await resolve(actor.organization, "claims_network").submit_claim(
        ClaimRequest(
            idempotency_key=body.idempotency_key,
            amount_cents=amount,
            payer_order=plan.priority,
            context={
                "cob_07_capability": actor.settings.jurisdiction_policy.get(
                    "cob_07_capability", "Y"
                ),
                "primary_eob_version": actor.settings.jurisdiction_policy.get(
                    "primary_eob_version", 4
                ),
                "is_blue_on_blue": actor.settings.jurisdiction_policy.get(
                    "is_blue_on_blue", False
                ),
            },
        )
    )
    row = await add(
        db,
        Claim,
        {
            "invoice_id": invoice.id,
            "location_id": invoice.location_id,
            "plan_id": plan.id,
            "idempotency_key": body.idempotency_key,
            "submitted_cents": amount,
            "payer_order": plan.priority,
            "reference": result["reference"],
            "status": "submitted",
            "network": actor.adapter_names["claims_network"],
            "due_at": datetime.now(timezone.utc) + timedelta(seconds=30),
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "submit", "claims", row.id, patient_id=invoice.patient_id, sandbox=True)
    return serialize(row)


@router.get("/{identifier}/status")
async def status(identifier: str, db=Depends(db_session), actor=Depends(permit("claims"))):
    row = await required(db, Claim, identifier)
    audit(db, actor.user_id, "read-status", "claims", row.id)
    return await resolve(actor.organization, "claims_network").get_claim_status(row.reference, row.status)


@router.post("/{identifier}/adjudicate")
async def adjudicate(identifier: str, db=Depends(db_session), actor=Depends(permit("claims"))):
    return serialize(await adjudicate_claim(db, actor, await required(db, Claim, identifier, lock=True)))


@router.post("/{identifier}/reconcile")
async def reconcile(identifier: str, db=Depends(db_session), actor=Depends(permit("claims"))):
    return serialize(await reconcile_claim(db, actor, await required(db, Claim, identifier, lock=True)))


class Appeal(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


@router.post("/{identifier}/appeal")
async def appeal(identifier: str, body: Appeal, db=Depends(db_session), actor=Depends(permit("claims"))):
    row = await required(db, Claim, identifier, lock=True)
    if row.status != "denied":
        raise HTTPException(409, "Only denied claims can be appealed")
    row.status = "appealed"
    row.due_at = datetime.now(timezone.utc) + timedelta(seconds=30)
    audit(db, actor.user_id, "appeal", "claims", row.id, reason=body.reason)
    await db.flush()
    return serialize(row)
