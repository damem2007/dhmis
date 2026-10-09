from fastapi import HTTPException

from app.billing.pricing import create_invoice
from app.core.audit import audit
from app.core.repository import required
from app.scheduling.models import Appointment


async def close_encounter(db, actor, row, *, require_soap: bool = True):
    if row.status == "completed":
        return row
    if require_soap and any(
        not row.soap.get(key, "").strip()
        for key in ["subjective", "objective", "assessment", "plan"]
    ):
        raise HTTPException(422, "All four SOAP sections are required before encounter completion")
    if row.procedures and not row.invoice_id:
        invoice = await create_invoice(db, actor, row.patient_id, row.procedures, row.provider_id)
        row.invoice_id = invoice.id
    row.status = "completed"
    row.updated_by = actor.user_id
    appointment = await required(db, Appointment, row.appointment_id)
    appointment.status = "completed"
    appointment.updated_by = actor.user_id
    audit(db, actor.user_id, "complete", "encounters", row.id, patient_id=row.patient_id)
    await db.flush()
    return row

