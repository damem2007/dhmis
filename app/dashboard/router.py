from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from app.billing.models import Invoice
from app.claims.models import Claim
from app.core.audit import audit
from app.identity.models import StaffUser
from app.identity.service import db_session, permit, role_has
from app.organizations.models import Location
from app.patients.models import Patient
from app.scheduling.models import Appointment

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("")
async def dashboard(db=Depends(db_session), actor=Depends(permit("dashboard"))):
    location = await db.scalar(select(Location).order_by(Location.created_at))
    zone = ZoneInfo(location.timezone if location else "America/Vancouver")
    today = datetime.now(zone).date()
    start = datetime.combine(today, time.min, tzinfo=zone)
    appointments = (
        await db.execute(
            select(Appointment, Patient, StaffUser)
            .join(Patient, Patient.id == Appointment.patient_id)
            .join(StaffUser, StaffUser.id == Appointment.provider_id)
            .where(
                Appointment.starts_at >= start,
                Appointment.starts_at < start + timedelta(days=1),
                Appointment.status != "cancelled",
            )
            .order_by(Appointment.starts_at)
        )
    ).all()
    if "scheduling" not in actor.modules and not role_has(actor.role, "scheduling"):
        appointments = []
    # Financial totals are only returned to roles authorized for billing.
    balance = (
        await db.scalar(
            select(
                func.coalesce(
                    func.sum(Invoice.total_cents + Invoice.adjustment_cents - Invoice.paid_cents), 0
                )
            )
        )
        if "billing" in actor.modules or role_has(actor.role, "billing")
        else None
    )
    pending = (
        await db.scalar(select(func.count()).select_from(Claim).where(Claim.status != "paid"))
        if "billing" in actor.modules or role_has(actor.role, "billing")
        else None
    )
    audit(db, actor.user_id, "read", "dashboard")
    return {
        "location_name": location.name if location else "No location",
        "date_label": today.strftime("%A, %B %d"),
        "patient_count": await db.scalar(select(func.count()).select_from(Patient)),
        "balance_cents": balance,
        "pending_claims": pending,
        "schedule": [
            {
                "time": a.starts_at.astimezone(zone).strftime("%H:%M"),
                "patient": f"{p.first_name} {p.last_name}",
                "initials": p.first_name[0] + p.last_name[0],
                "procedure": a.procedure,
                "provider": u.name,
                "chair": a.chair,
                "status": a.status,
            }
            for a, p, u in appointments
        ],
    }
