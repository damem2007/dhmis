from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select

from app.billing.models import Invoice, LedgerEntry
from app.clinical.models import Encounter
from app.core.audit import audit
from app.identity.models import StaffUser
from app.identity.service import db_session, permit
from app.organizations.models import Location
from app.scheduling.models import Appointment

router = APIRouter(prefix="/reports", tags=["Reporting"])


def window(start: date, end: date):
    if end < start or (end - start).days > 366:
        raise HTTPException(422, "Report range must be 0 to 366 days")
    return (
        datetime.combine(start, time.min, tzinfo=timezone.utc),
        datetime.combine(end + timedelta(days=1), time.min, tzinfo=timezone.utc),
    )


@router.get("/performance")
async def performance(
    start: date = Query(),
    end: date = Query(),
    location_id: str | None = Query(default=None),
    provider_id: str | None = Query(default=None),
    db=Depends(db_session),
    actor=Depends(permit("reporting")),
):
    beginning, ending = window(start, end)
    if location_id:
        location = await db.get(Location, location_id)
        if location is None:
            raise HTTPException(404, "Location not found")
    if provider_id:
        provider = await db.get(StaffUser, provider_id)
        if provider is None:
            raise HTTPException(404, "Provider not found")

    invoice_query = select(Invoice).where(
        Invoice.created_at >= beginning, Invoice.created_at < ending
    )
    collection_query = select(LedgerEntry, Invoice).join(
        Invoice, LedgerEntry.invoice_id == Invoice.id
    ).where(
        LedgerEntry.created_at >= beginning,
        LedgerEntry.created_at < ending,
        LedgerEntry.kind.in_(["payment", "insurance"]),
    )
    appointment_query = select(Appointment).where(
        Appointment.starts_at >= beginning,
        Appointment.starts_at < ending,
        Appointment.status.not_in(["cancelled", "no-show"]),
    )
    encounter_query = select(Encounter).where(
        Encounter.updated_at >= beginning,
        Encounter.updated_at < ending,
        Encounter.status == "completed",
    )
    if location_id:
        invoice_query = invoice_query.where(Invoice.location_id == location_id)
        collection_query = collection_query.where(LedgerEntry.location_id == location_id)
        appointment_query = appointment_query.where(Appointment.location_id == location_id)
        encounter_query = encounter_query.where(Encounter.location_id == location_id)
        collection_query = collection_query.where(Invoice.location_id == location_id)
    if provider_id:
        invoice_query = invoice_query.where(Invoice.provider_id == provider_id)
        collection_query = collection_query.where(Invoice.provider_id == provider_id)
        appointment_query = appointment_query.where(Appointment.provider_id == provider_id)
        encounter_query = encounter_query.where(Encounter.provider_id == provider_id)

    invoices = (await db.scalars(invoice_query)).all()
    collections = (await db.execute(collection_query)).all()
    appointments = (await db.scalars(appointment_query)).all()
    encounters = (await db.scalars(encounter_query)).all()
    locations = {row.id: row for row in (await db.scalars(select(Location))).all()}
    providers = {row.id: row for row in (await db.scalars(select(StaffUser))).all()}

    breakdown = defaultdict(
        lambda: {
            "production_cents": 0,
            "collections_cents": 0,
            "appointment_minutes": 0,
            "completed_encounters": 0,
        }
    )
    for invoice in invoices:
        key = (invoice.location_id, invoice.provider_id or "unassigned")
        breakdown[key]["production_cents"] += invoice.total_cents + invoice.adjustment_cents
    for entry, invoice in collections:
        key = (invoice.location_id, invoice.provider_id or "unassigned")
        breakdown[key]["collections_cents"] += -entry.amount_cents
    for appointment in appointments:
        key = (appointment.location_id, appointment.provider_id)
        breakdown[key]["appointment_minutes"] += int(
            (appointment.ends_at - appointment.starts_at).total_seconds() // 60
        )
    for encounter in encounters:
        breakdown[(encounter.location_id, encounter.provider_id)]["completed_encounters"] += 1

    days = (end - start).days + 1
    rows = []
    for (current_location, current_provider), values in sorted(breakdown.items()):
        location = locations.get(current_location)
        capacity = (
            max(0, location.closing_hour - location.opening_hour) * 60 * len(location.chairs) * days
            if location
            else 0
        )
        rows.append(
            {
                "location_id": current_location,
                "location_name": location.name if location else "Unknown",
                "provider_id": None if current_provider == "unassigned" else current_provider,
                "provider_name": providers[current_provider].name
                if current_provider in providers
                else "Unassigned",
                **values,
                "chair_utilization_pct": round(
                    values["appointment_minutes"] * 100 / capacity, 2
                )
                if capacity
                else 0,
            }
        )
    audit(
        db,
        actor.user_id,
        "report",
        "performance",
        start=start.isoformat(),
        end=end.isoformat(),
        location_id=location_id or "",
        provider_id=provider_id or "",
    )
    return {
        "start": start,
        "end": end,
        "production_cents": sum(row["production_cents"] for row in rows),
        "collections_cents": sum(row["collections_cents"] for row in rows),
        "appointment_minutes": sum(row["appointment_minutes"] for row in rows),
        "completed_encounters": sum(row["completed_encounters"] for row in rows),
        "breakdown": rows,
    }
