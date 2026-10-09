from datetime import timedelta
from zoneinfo import ZoneInfo

from fastapi import HTTPException
from sqlalchemy import or_, select, text

from app.core.audit import audit
from app.core.repository import add, required
from app.identity.models import StaffUser
from app.identity.service import user_has_module
from app.notifications.models import OutboxMessage
from app.operations.service import require_current_credentials
from app.organizations.models import Location
from app.patients.models import Patient
from app.scheduling.models import Appointment
from app.scheduling.policy import apply_change_policy


async def book(db, actor, body, existing_id=None):
    location = await required(db, Location, body.location_id)
    await required(db, Patient, body.patient_id)
    provider = await required(db, StaffUser, body.provider_id)
    await require_current_credentials(db, provider.id)
    if (
        body.chair not in location.chairs
        or not provider.active
        or not await user_has_module(db, provider, "clinical")
    ):
        raise HTTPException(422, "Invalid chair or provider")
    if provider.location_ids and body.location_id not in provider.location_ids:
        raise HTTPException(422, "Provider is not assigned to this location")
    start_local = body.starts_at.astimezone(ZoneInfo(location.timezone))
    end_local = body.ends_at.astimezone(ZoneInfo(location.timezone))
    if (
        start_local.date() != end_local.date()
        or start_local.hour < location.opening_hour
        or end_local.hour > location.closing_hour
        or (end_local.hour == location.closing_hour and end_local.minute > 0)
    ):
        raise HTTPException(422, "Appointment must be inside location opening hours")
    policy = {**actor.settings.policy, **location.policy}
    buffer = timedelta(minutes=policy.get("buffer_minutes", 0))
    # Serialize overlapping checks within this tenant, including concurrent requests.
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": actor.organization.id + ":schedule"},
    )
    query = select(Appointment).where(
        Appointment.status != "cancelled",
        Appointment.starts_at < body.ends_at + buffer,
        Appointment.ends_at > body.starts_at - buffer,
        or_(
            Appointment.provider_id == body.provider_id,
            (Appointment.location_id == body.location_id) & (Appointment.chair == body.chair),
            Appointment.patient_id == body.patient_id,
        ),
    )
    if existing_id:
        query = query.where(Appointment.id != existing_id)
    if await db.scalar(query):
        raise HTTPException(409, "Patient, provider, or chair is already booked for this time")
    if existing_id:
        row = await required(db, Appointment, existing_id, lock=True)
        if row.status != "confirmed":
            raise HTTPException(409, "Only confirmed appointments can be rescheduled")
        if row.starts_at != body.starts_at or row.ends_at != body.ends_at:
            await apply_change_policy(db, actor, row, "Rescheduled appointment")
        for key, value in body.model_dump().items():
            setattr(row, key, value)
        row.updated_by = actor.user_id
    else:
        row = await add(db, Appointment, body.model_dump(), actor.user_id)
    await db.flush()
    db.add(
        OutboxMessage(
            kind="appointment.reminder",
            payload={"appointment_id": row.id, "starts_at": row.starts_at.isoformat()},
            due_at=row.starts_at - timedelta(hours=policy.get("reminder_hours", 24)),
            idempotency_key=f"reminder:{row.id}:{row.starts_at.isoformat()}",
        )
    )
    audit(
        db,
        actor.user_id,
        "reschedule" if existing_id else "book",
        "appointments",
        row.id,
        patient_id=row.patient_id,
    )
    return row


async def book_series(db, actor, body):
    """Create a recurring series atomically; one conflict rolls back the full series."""
    from app.scheduling.schemas import Booking

    values = body.model_dump(include=set(Booking.model_fields))
    rows = []
    for index in range(body.occurrences):
        shift = timedelta(days=body.interval_days * index)
        occurrence = Booking(**{**values, "starts_at": body.starts_at + shift, "ends_at": body.ends_at + shift})
        rows.append(await book(db, actor, occurrence))
    audit(
        db,
        actor.user_id,
        "book.series",
        "appointments",
        rows[0].id,
        patient_id=body.patient_id,
        occurrence_ids=[row.id for row in rows],
    )
    return rows


async def cancel_booking(db, actor, identifier, reason):
    row = await required(db, Appointment, identifier, lock=True)
    if row.status == "cancelled":
        return row
    if row.status != "confirmed":
        raise HTTPException(409, "Appointment cannot be cancelled in its current state")
    await apply_change_policy(db, actor, row, reason)
    row.status = "cancelled"
    row.cancellation_reason = reason
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "cancel", "appointments", row.id, patient_id=row.patient_id)
    await db.flush()
    return row
