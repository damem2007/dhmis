from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import select

from app.billing.models import FeeVersion, Invoice, LedgerEntry, PaymentPlan, Service
from app.billing.service import create_payment_plan
from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.identity.models import StaffUser
from app.identity.service import db_session, permit
from app.integrations.registry import resolve
from app.organizations.models import Location
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

router = APIRouter(prefix="/billing", tags=["Financial operations"])


class FeeInput(BaseModel):
    service_id: str
    location_id: str | None = None
    provider_id: str | None = None
    fee_cents: int = Field(ge=0, le=10000000)
    effective_at: AwareDatetime


@router.post("/fee-versions", status_code=201)
async def fee(body: FeeInput, db=Depends(db_session), actor=Depends(permit("billing"))):
    await required(db, Service, body.service_id)
    if body.location_id:
        await required(db, Location, body.location_id)
    if body.provider_id:
        await required(db, StaffUser, body.provider_id)
    row = await add(db, FeeVersion, body.model_dump(), actor.user_id)
    audit(db, actor.user_id, "version", "fee_versions", row.id)
    return serialize(row)


@router.get("/fee-versions")
async def fees(db=Depends(db_session), actor=Depends(permit("billing"))):
    return [
        serialize(x)
        for x in (await db.scalars(select(FeeVersion).order_by(FeeVersion.effective_at.desc()))).all()
    ]


class Adjustment(BaseModel):
    amount_cents: int
    reason: str = Field(min_length=5, max_length=500)
    idempotency_key: str = Field(min_length=8, max_length=100)


@router.post("/invoices/{identifier}/adjustments")
async def adjustment(
    identifier: str, body: Adjustment, db=Depends(db_session), actor=Depends(permit("billing"))
):
    row = await required(db, Invoice, identifier, lock=True)
    existing = await db.scalar(select(LedgerEntry).where(LedgerEntry.idempotency_key == body.idempotency_key))
    if existing:
        if (
            existing.invoice_id != identifier
            or existing.amount_cents != body.amount_cents
            or existing.kind != "adjustment"
        ):
            raise HTTPException(409, "Idempotency key conflicts")
        return serialize(existing)
    if body.amount_cents == 0 or row.total_cents + row.adjustment_cents + body.amount_cents < row.paid_cents:
        raise HTTPException(422, "Adjustment cannot make the balance negative")
    row.adjustment_cents += body.amount_cents
    row.updated_by = actor.user_id
    row.status = (
        "paid"
        if row.total_cents + row.adjustment_cents == row.paid_cents
        else ("partial" if row.paid_cents else "open")
    )
    entry = await add(
        db,
        LedgerEntry,
        {
            "patient_id": row.patient_id,
            "invoice_id": row.id,
            "location_id": row.location_id,
            "kind": "adjustment",
            "amount_cents": body.amount_cents,
            "idempotency_key": body.idempotency_key,
            "reference": "manual-adjustment",
        },
        actor.user_id,
    )
    audit(
        db,
        actor.user_id,
        "adjustment",
        "invoices",
        row.id,
        patient_id=row.patient_id,
        reason=body.reason,
        amount_cents=body.amount_cents,
    )
    return serialize(entry)


class Refund(BaseModel):
    payment_id: str
    amount_cents: int = Field(gt=0)
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(min_length=8, max_length=100)
    approval_request_id: str | None = Field(default=None, max_length=36)


@router.post("/invoices/{identifier}/refunds")
async def refund(
    identifier: str,
    body: Refund,
    db=Depends(db_session),
    actor=Depends(permit_tenant("billing.payment.refund", workflow_handles_approval=True)),
):
    row = await required(db, Invoice, identifier, lock=True)
    entry = await required(db, LedgerEntry, body.payment_id)
    if entry.invoice_id != row.id or entry.kind != "payment":
        raise HTTPException(422, "Refund requires a patient payment on this invoice")
    prior = await db.scalar(select(LedgerEntry).where(LedgerEntry.idempotency_key == body.idempotency_key))
    if prior:
        if (
            prior.invoice_id != identifier
            or prior.amount_cents != body.amount_cents
            or prior.kind != "refund"
        ):
            raise HTTPException(409, "Idempotency key conflicts")
        return serialize(prior)
    refunded = (
        await db.scalars(
            select(LedgerEntry).where(LedgerEntry.kind == "refund", LedgerEntry.reference == entry.id)
        )
    ).all()
    if body.amount_cents > -entry.amount_cents - sum(x.amount_cents for x in refunded):
        raise HTTPException(422, "Refund exceeds captured payment")
    runtime_payload = {
        "invoice_id": identifier,
        "payment_id": body.payment_id,
        "amount_cents": body.amount_cents,
        "reason": body.reason,
        "idempotency_key": body.idempotency_key,
    }
    decision = await decide_tenant(
        db,
        actor.user_id,
        "billing.payment.refund",
        selected_location_id=actor.selected_location_id,
    )
    approval = None
    if decision.needs_approval:
        if body.approval_request_id:
            approval = await authorize_runtime_action(
                db,
                request_id=body.approval_request_id,
                permission_key="billing.payment.refund",
                payload=runtime_payload,
                maker_id=actor.user_id,
                request_model=TenantChangeRequest,
            )
        else:
            approval, created = await create_runtime_action_request(
                db,
                permission_key="billing.payment.refund",
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
                "refund.approval-requested",
                "invoices",
                row.id,
                request_id=approval.id,
                created=created,
                amount_cents=body.amount_cents,
            )
            return JSONResponse(
                status_code=202,
                content=jsonable_encoder(
                    {
                        "status": "approval_required",
                        "request": await request_payload(db, approval, TenantChangeDecision),
                    }
                ),
            )
    await resolve(actor.organization, "payment_gateway").refund(
        entry.reference, body.amount_cents, body.idempotency_key
    )
    row.paid_cents -= body.amount_cents
    row.status = "partial" if row.paid_cents else "open"
    row.updated_by = actor.user_id
    refund = await add(
        db,
        LedgerEntry,
        {
            "patient_id": row.patient_id,
            "invoice_id": row.id,
            "location_id": row.location_id,
            "kind": "refund",
            "amount_cents": body.amount_cents,
            "idempotency_key": body.idempotency_key,
            "reference": entry.id,
        },
        actor.user_id,
    )
    audit(
        db,
        actor.user_id,
        "refund",
        "invoices",
        row.id,
        patient_id=row.patient_id,
        reason=body.reason,
        sandbox=True,
    )
    if approval:
        await complete_runtime_action(
            approval,
            {"resource": "ledger_entry", "resource_id": refund.id},
        )
    return serialize(refund)


class PlanInput(BaseModel):
    installments: int = Field(ge=2, le=24)
    first_due: date


@router.post("/invoices/{identifier}/payment-plan", status_code=201)
async def plan(identifier: str, body: PlanInput, db=Depends(db_session), actor=Depends(permit("billing"))):
    return serialize(
        await create_payment_plan(db, actor, identifier, body.installments, body.first_due)
    )


@router.get("/statement/{patient_id}")
async def statement(patient_id: str, db=Depends(db_session), actor=Depends(permit("billing"))):
    await required(db, Patient, patient_id)
    invoices = (
        await db.scalars(select(Invoice).where(Invoice.patient_id == patient_id).order_by(Invoice.created_at))
    ).all()
    entries = (
        await db.scalars(
            select(LedgerEntry).where(LedgerEntry.patient_id == patient_id).order_by(LedgerEntry.created_at)
        )
    ).all()
    plans = (await db.scalars(select(PaymentPlan).where(PaymentPlan.patient_id == patient_id))).all()
    aging = {"0-30": 0, "31-60": 0, "61-90": 0, "90+": 0}
    for invoice in invoices:
        days = (datetime.now(timezone.utc) - invoice.created_at).days
        bucket = "0-30" if days <= 30 else "31-60" if days <= 60 else "61-90" if days <= 90 else "90+"
        aging[bucket] += invoice.total_cents + invoice.adjustment_cents - invoice.paid_cents
    balance = 0
    history = []
    for entry in entries:
        balance += entry.amount_cents
        history.append({**serialize(entry), "running_balance_cents": balance})
    audit(db, actor.user_id, "statement", "ledger", patient_id)
    return {
        "patient_id": patient_id,
        "balance_cents": balance,
        "aging": aging,
        "entries": history,
        "payment_plans": [serialize(x) for x in plans],
    }
