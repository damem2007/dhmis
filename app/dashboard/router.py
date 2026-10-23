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
from app.patients.access import (
    needs_assigned_patient_filter,
    needs_location_patient_filter,
    patient_read_decision,
    visible_location_ids,
)
from app.scheduling.models import Appointment
from app.scheduling.presentation import effective_status

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


# Handle dashboard for this module.
@router.get("")
async def dashboard(db=Depends(db_session), actor=Depends(permit("dashboard"))):
    location_query = select(Location).where(Location.active)
    if actor.selected_location_id:
        location_query = location_query.where(Location.id == actor.selected_location_id)
    elif actor.location_ids:
        location_query = location_query.where(Location.id.in_(actor.location_ids))
    location = await db.scalar(location_query.order_by(Location.created_at))
    zone = ZoneInfo(location.timezone if location else "America/Vancouver")
    today = datetime.now(zone).date()
    start = datetime.combine(today, time.min, tzinfo=zone)
    appointment_query = (
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
    patient_decision = await patient_read_decision(db, actor)
    if patient_decision is not None and not patient_decision.allowed:
        appointment_query = appointment_query.where(False)
    elif needs_assigned_patient_filter(patient_decision):
        appointment_query = appointment_query.where(Appointment.provider_id == actor.user_id)
    elif needs_location_patient_filter(patient_decision, actor):
        location_ids = visible_location_ids(actor)
        appointment_query = appointment_query.where(Patient.location_id.in_(location_ids)) if location_ids else appointment_query.where(False)
    appointments = (await db.execute(appointment_query)).all()
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
    patient_count_query = select(func.count()).select_from(Patient)
    if patient_decision is not None and not patient_decision.allowed:
        patient_count_query = patient_count_query.where(False)
    elif needs_assigned_patient_filter(patient_decision):
        patient_count_query = patient_count_query.where(
            Patient.id.in_(
                select(Appointment.patient_id).where(
                    Appointment.provider_id == actor.user_id,
                    Appointment.status != "cancelled",
                )
            )
        )
    elif needs_location_patient_filter(patient_decision, actor):
        location_ids = visible_location_ids(actor)
        patient_count_query = patient_count_query.where(Patient.location_id.in_(location_ids)) if location_ids else patient_count_query.where(False)
    return {
        "location_name": location.name if location else "No location",
        "date_label": f"{today.strftime('%A, %B %d')} ({zone.key})",
        "patient_count": await db.scalar(patient_count_query),
        "balance_cents": balance,
        "pending_claims": pending,
        "schedule": [
            {
                "appointment_id": a.id,
                "patient_id": p.id,
                "time": a.starts_at.astimezone(zone).strftime("%H:%M %Z"),
                "patient": f"{p.first_name} {p.last_name}",
                "initials": p.first_name[0] + p.last_name[0],
                "procedure": a.procedure,
                "provider": u.name,
                "chair": a.chair,
                "status": effective_status(a),
                "timezone": a.timezone or zone.key,
            }
            for a, p, u in appointments
        ],
    }
