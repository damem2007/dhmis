from datetime import datetime, timedelta, timezone

from app.billing.models import Invoice, LedgerEntry
from app.core.audit import audit
from app.core.repository import add
from app.organizations.models import Location


async def apply_change_policy(db, actor, appointment, reason):
    location = await db.get(Location, appointment.location_id)
    policy = {**actor.settings.policy, **(location.policy if location else {})}
    notice = policy.get("cancellation_notice_hours", 24)
    fee = policy.get("cancellation_fee_cents", 0)
    if fee <= 0 or appointment.starts_at - datetime.now(timezone.utc) >= timedelta(hours=notice):
        return None
    invoice = await add(
        db,
        Invoice,
        {
            "patient_id": appointment.patient_id,
            "location_id": appointment.location_id,
            "total_cents": fee,
            "lines": [
                {
                    "name": "Late cancellation / rescheduling fee",
                    "fee_cents": fee,
                    "quantity": 1,
                    "line_total_cents": fee,
                    "reason": reason,
                }
            ],
        },
        actor.user_id,
    )
    await add(
        db,
        LedgerEntry,
        {
            "patient_id": appointment.patient_id,
            "location_id": appointment.location_id,
            "invoice_id": invoice.id,
            "kind": "charge",
            "amount_cents": fee,
            "idempotency_key": "policy:" + invoice.id,
        },
        actor.user_id,
    )
    audit(
        db,
        actor.user_id,
        "policy.fee",
        "appointments",
        appointment.id,
        patient_id=appointment.patient_id,
        invoice_id=invoice.id,
    )
    return invoice
