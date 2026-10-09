from datetime import date, datetime, time, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select

from app.billing.models import Invoice, LedgerEntry, PaymentPlan
from app.core.audit import audit
from app.core.repository import add, required
from app.integrations.contracts import IntegrationFailure, PaymentRequest
from app.integrations.registry import resolve
from app.notifications.models import OutboxMessage
from app.organizations.configuration import render_communication_template
from app.organizations.jurisdiction import jurisdiction
from app.patients.models import Patient


async def create_payment_plan(
    db, actor, invoice_id: str, installments: int, first_due: date
):
    invoice = await required(db, Invoice, invoice_id, lock=True)
    existing = await db.scalar(select(PaymentPlan).where(PaymentPlan.invoice_id == invoice_id))
    if existing:
        return existing
    balance = invoice.total_cents + invoice.adjustment_cents - invoice.paid_cents
    if balance < installments:
        raise HTTPException(422, "Balance is too small for the requested installments")
    base, remainder = divmod(balance, installments)
    schedule = [
        {
            "due": (first_due + timedelta(days=30 * index)).isoformat(),
            "amount_cents": base + (1 if index < remainder else 0),
        }
        for index in range(installments)
    ]
    row = await add(
        db,
        PaymentPlan,
        {
            "invoice_id": invoice_id,
            "patient_id": invoice.patient_id,
            "location_id": invoice.location_id,
            "installments": schedule,
        },
        actor.user_id,
    )
    patient = await db.get(Patient, invoice.patient_id)
    if patient and (patient.email or patient.phone):
        channel = "email" if patient.email else "sms"
        destination = patient.email or patient.phone
        for index, installment in enumerate(schedule):
            due = date.fromisoformat(installment["due"])
            values = {
                "clinic_name": actor.organization.name,
                "clinic_phone": actor.settings.public_content.get("contact_phone", "the clinic"),
                "patient_first_name": patient.first_name,
                "installment_amount": f"${installment['amount_cents'] / 100:.2f}",
                "due_date": due.strftime("%B %-d, %Y"),
                "plan_balance": f"${balance / 100:.2f}",
            }
            for template_key, kind, send_date in (
                ("installment-due-soon", "billing.installment-due", due - timedelta(days=3)),
                ("installment-overdue", "billing.installment-overdue", due + timedelta(days=1)),
            ):
                template = actor.settings.communication_templates[template_key]
                subject, body = render_communication_template(template, values)
                db.add(
                    OutboxMessage(
                        kind=kind,
                        payload={
                            "destination": destination,
                            "channel": channel,
                            "subject": subject,
                            "body": body,
                            "patient_id": patient.id,
                            "invoice_id": invoice.id,
                        },
                        due_at=datetime.combine(send_date, time(9), tzinfo=timezone.utc),
                        idempotency_key=f"{kind}:{row.id}:{index}",
                        created_by=actor.user_id,
                        updated_by=actor.user_id,
                    )
                )
    audit(
        db,
        actor.user_id,
        "payment-plan",
        "invoices",
        invoice_id,
        patient_id=invoice.patient_id,
    )
    return row


async def payment(
    db, actor, invoice_id, amount_cents, key, kind="payment", reference=None, payment_method_token=None
):
    invoice = await required(db, Invoice, invoice_id, lock=True)
    existing = await db.scalar(select(LedgerEntry).where(LedgerEntry.idempotency_key == key))
    if existing:
        if (
            existing.invoice_id != invoice_id
            or existing.amount_cents != -amount_cents
            or existing.kind != kind
        ):
            raise HTTPException(409, "Idempotency key was already used for another request")
        return existing
    if (
        amount_cents <= 0
        or amount_cents > invoice.total_cents + invoice.adjustment_cents - invoice.paid_cents
    ):
        raise HTTPException(422, "Payment exceeds balance or is not positive")
    if reference is None:
        result = await resolve(actor.organization, "payment_gateway").capture(
            PaymentRequest(
                amount_cents=amount_cents,
                idempotency_key=key,
                currency=jurisdiction(actor.organization.region).currency,
                patient_id=invoice.patient_id,
                invoice_id=invoice.id,
                payment_method_token=payment_method_token,
            )
        )
        if result.status != "captured":
            raise IntegrationFailure("Payment was not captured; no ledger credit was posted")
        reference = result.reference
    invoice.paid_cents += amount_cents
    invoice.status = (
        "paid" if invoice.paid_cents == invoice.total_cents + invoice.adjustment_cents else "partial"
    )
    invoice.updated_by = actor.user_id
    row = await add(
        db,
        LedgerEntry,
        {
            "patient_id": invoice.patient_id,
            "location_id": invoice.location_id,
            "invoice_id": invoice.id,
            "kind": kind,
            "amount_cents": -amount_cents,
            "idempotency_key": key,
            "reference": reference,
        },
        actor.user_id,
    )
    audit(
        db,
        actor.user_id,
        kind,
        "invoices",
        invoice.id,
        sandbox=True,
        amount_cents=amount_cents,
        patient_id=invoice.patient_id,
    )
    return row
