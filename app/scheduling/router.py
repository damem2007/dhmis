from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from app.core.audit import audit
from app.core.repository import required, serialize
from app.identity.service import db_session, permit
from app.scheduling.models import Appointment
from app.scheduling.schemas import Booking, Cancellation, NoShow, SeriesBooking
from app.scheduling.service import book, book_series, cancel_booking

router = APIRouter(prefix="/appointments", tags=["Scheduling"])


@router.get("")
async def appointments(db=Depends(db_session), actor=Depends(permit("scheduling"))):
    rows = (await db.scalars(select(Appointment).order_by(Appointment.starts_at).limit(300))).all()
    audit(db, actor.user_id, "read", "appointments", count=len(rows))
    return [serialize(row) for row in rows]


@router.post("", status_code=201)
async def create(body: Booking, db=Depends(db_session), actor=Depends(permit("scheduling"))):
    return serialize(await book(db, actor, body))


@router.post("/series", status_code=201)
async def create_series(
    body: SeriesBooking, db=Depends(db_session), actor=Depends(permit("scheduling"))
):
    return [serialize(row) for row in await book_series(db, actor, body)]


@router.put("/{identifier}")
async def reschedule(
    identifier: str, body: Booking, db=Depends(db_session), actor=Depends(permit("scheduling"))
):
    return serialize(await book(db, actor, body, identifier))


@router.post("/{identifier}/cancel")
async def cancel(
    identifier: str, body: Cancellation, db=Depends(db_session), actor=Depends(permit("scheduling"))
):
    return serialize(await cancel_booking(db, actor, identifier, body.reason))


@router.post("/{identifier}/no-show")
async def no_show(
    identifier: str, body: NoShow, db=Depends(db_session), actor=Depends(permit("scheduling"))
):
    from datetime import datetime, timezone

    from app.scheduling.policy import apply_change_policy

    row = await required(db, Appointment, identifier, lock=True)
    if row.status == "no-show":
        return serialize(row)
    if row.status != "confirmed":
        raise HTTPException(409, "Appointment cannot be marked no-show in its current state")
    if row.starts_at > datetime.now(timezone.utc):
        raise HTTPException(409, "A future appointment cannot be marked no-show")
    await apply_change_policy(db, actor, row, body.reason)
    row.status = "no-show"
    row.cancellation_reason = body.reason
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "no-show", "appointments", row.id, patient_id=row.patient_id)
    await db.flush()
    return serialize(row)


@router.post("/{identifier}/check-in")
async def check_in(identifier: str, db=Depends(db_session), actor=Depends(permit("scheduling"))):
    from app.clinical.models import Encounter
    from app.core.repository import add

    row = await required(db, Appointment, identifier, lock=True)
    existing = await db.scalar(select(Encounter).where(Encounter.appointment_id == identifier))
    if existing:
        return serialize(existing)
    if row.status != "confirmed":
        raise HTTPException(409, "Only confirmed appointments can be checked in")
    encounter = await add(
        db,
        Encounter,
        {
            "appointment_id": row.id,
            "patient_id": row.patient_id,
            "location_id": row.location_id,
            "provider_id": row.provider_id,
        },
        actor.user_id,
    )
    row.status = "checked-in"
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "check-in", "appointments", row.id, patient_id=row.patient_id)
    return serialize(encounter)
