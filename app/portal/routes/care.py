"""Patient portal care routes."""

from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.billing.models import Invoice, LedgerEntry, PaymentPlan
from app.billing.service import create_payment_plan, payment
from app.core.audit import audit
from app.core.repository import required, serialize
from app.patient_identity.service import (
    PatientActor,
    authorized_patient_ids,
    current_patient,
    patient_db_session,
    require_patient_access,
)
from app.scheduling.models import Appointment
from app.scheduling.schemas import Booking, Cancellation
from app.scheduling.service import book, cancel_booking

router = APIRouter()

# Handle appointments for this module.
@router.get("/appointments")
async def appointments(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    identifiers = await authorized_patient_ids(db, actor)
    rows = (
        await db.scalars(
            select(Appointment)
            .where(Appointment.patient_id.in_(identifiers))
            .order_by(Appointment.starts_at.desc())
        )
    ).all()
    audit(db, actor.user_id, "portal.read", "appointments", patient_id=actor.patient_id)
    return [serialize(row) for row in rows]


# Create or issue create appointment while applying existing validation and authorization.
@router.post("/appointments", status_code=201)
async def create_appointment(
    body: Booking, actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)
):
    if not actor.organization.booking_enabled:
        raise HTTPException(404, "Online booking is not enabled")
    await require_patient_access(db, actor, body.patient_id)
    return serialize(await book(db, actor, body))


# Handle reschedule appointment for this module.
@router.put("/appointments/{identifier}")
async def reschedule_appointment(
    identifier: str,
    body: Booking,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    row = await required(db, Appointment, identifier)
    await require_patient_access(db, actor, row.patient_id)
    if body.patient_id != row.patient_id:
        raise HTTPException(422, "Appointment patient cannot be changed")
    return serialize(await book(db, actor, body, identifier))


# Apply the cancel appointment lifecycle transition and its existing safeguards.
@router.post("/appointments/{identifier}/cancel")
async def cancel_appointment(
    identifier: str,
    body: Cancellation,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    row = await required(db, Appointment, identifier)
    await require_patient_access(db, actor, row.patient_id)
    return serialize(await cancel_booking(db, actor, identifier, body.reason))


# Handle invoices for this module.
@router.get("/invoices")
async def invoices(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    identifiers = await authorized_patient_ids(db, actor)
    rows = (
        await db.scalars(select(Invoice).where(Invoice.patient_id.in_(identifiers)).order_by(Invoice.created_at.desc()))
    ).all()
    audit(db, actor.user_id, "portal.read", "invoices", patient_id=actor.patient_id)
    return [serialize(row) for row in rows]


# Defines the portal payment model, contract, or value object.
class PortalPayment(BaseModel):
    amount_cents: int = Field(gt=0)
    idempotency_key: str = Field(min_length=8, max_length=100)
    payment_method_token: str | None = None


# Defines the portal plan model, contract, or value object.
class PortalPlan(BaseModel):
    installments: int = Field(ge=2, le=24)
    first_due: date
    frequency: Literal["monthly", "biweekly"] = "monthly"


# Handle pay invoice for this module.
@router.post("/invoices/{identifier}/payments")
async def pay_invoice(
    identifier: str,
    body: PortalPayment,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    invoice = await required(db, Invoice, identifier)
    await require_patient_access(db, actor, invoice.patient_id)
    row = await payment(
        db,
        actor,
        invoice.id,
        body.amount_cents,
        body.idempotency_key,
        payment_method_token=body.payment_method_token,
    )
    return serialize(row)


# Create or issue create plan while applying existing validation and authorization.
@router.post("/invoices/{identifier}/payment-plan", status_code=201)
async def create_plan(
    identifier: str,
    body: PortalPlan,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    invoice = await required(db, Invoice, identifier)
    await require_patient_access(db, actor, invoice.patient_id)
    return serialize(
        await create_payment_plan(
            db,
            actor,
            invoice.id,
            body.installments,
            body.first_due,
            body.frequency,
        )
    )


# Handle statement for this module.
@router.get("/statements/{patient_id}")
async def statement(
    patient_id: str,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    await require_patient_access(db, actor, patient_id)
    invoices = (
        await db.scalars(select(Invoice).where(Invoice.patient_id == patient_id).order_by(Invoice.created_at))
    ).all()
    entries = (
        await db.scalars(
            select(LedgerEntry).where(LedgerEntry.patient_id == patient_id).order_by(LedgerEntry.created_at)
        )
    ).all()
    plans = (await db.scalars(select(PaymentPlan).where(PaymentPlan.patient_id == patient_id))).all()
    balance = 0
    history = []
    for entry in entries:
        balance += entry.amount_cents
        history.append({**serialize(entry), "running_balance_cents": balance})
    audit(db, actor.user_id, "portal.statement", "ledger", patient_id)
    return {"patient_id": patient_id, "balance_cents": balance, "entries": history, "payment_plans": [serialize(x) for x in plans], "invoice_count": len(invoices)}

