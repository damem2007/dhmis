from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.core.audit import audit
from app.core.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.core.repository import required, serialize
from app.identity.service import db_session, permit
from app.notifications.models import OutboxMessage
from app.notifications.service import dispatch
from app.patients.models import Patient
from app.scheduling.models import Appointment
from app.identity.models import StaffUser

router = APIRouter(prefix="/notifications", tags=["Notification operations"])


# Internal helper for feed item.
def _feed_item(row):
    status = row.status or "pending"
    severity = "danger" if status in {"failed", "retry"} else "warning" if status == "pending" else "info"
    payload = row.payload if isinstance(row.payload, dict) else {}
    kind = str(payload.get("title") or row.kind.replace(".", " ").replace("_", " ").strip().capitalize())
    detail = payload.get("subject") or payload.get("title") or (
        "Delivery failed and needs attention" if status in {"failed", "retry"}
        else "Delivery is queued" if status == "pending" else "Delivery completed"
    )
    cta_label = payload.get("cta_label")
    if not cta_label:
        cta_label = (
            "Review payment" if "payment" in row.kind or "billing" in row.kind
            else "View appointment" if "appointment" in row.kind or "schedule" in row.kind
            else "View patient item" if "patient" in row.kind
            else "View invitation" if "invitation" in row.kind
            else "Review recovery" if "password" in row.kind or "recovery" in row.kind
            else "View notification"
        )
    return {
        "id": row.id,
        "kind": row.kind,
        "title": kind,
        "detail": str(detail),
        "status": status,
        "severity": severity,
        "created_at": row.created_at,
        "unread": status in {"pending", "retry", "failed"},
        "cta_label": str(cta_label),
        "thread_id": payload.get("thread_id"),
        "patient_id": payload.get("patient_id"),
        "appointment_id": payload.get("appointment_id"),
    }


def _visible_to_actor(row, actor) -> bool:
    """Keep the in-app feed scoped to an explicit user or role audience.

    Outbox rows are also used for delivery bookkeeping and may not have a
    human recipient. Those rows must not become a system-wide notification
    stream for staff users.
    """
    payload = row.payload if isinstance(row.payload, dict) else {}
    if payload.get("channel") != "in_app":
        return False

    recipient_id = payload.get("user_id") or payload.get("recipient_user_id")
    audience_roles = {str(value) for value in (payload.get("audience_roles") or [])}
    audience_permissions = {str(value) for value in (payload.get("audience_permissions") or [])}
    location_id = payload.get("location_id")
    if location_id and str(location_id) not in {str(value) for value in actor.location_ids}:
        return False

    user_match = bool(recipient_id and str(recipient_id) == str(actor.user_id))
    role_match = bool(audience_roles.intersection({str(actor.role), str(actor.role_id or "")}))
    permission_match = bool(audience_permissions.intersection({str(value) for value in actor.modules}))
    return user_match or role_match or permission_match


# Build the appointment notification item with patient and provider names.
def _appointment_item(appointment, patient, provider):
    patient_name = f"{patient.first_name} {patient.last_name}".strip()
    provider_name = provider.name or provider.email
    return {
        "id": f"appointment:{appointment.id}",
        "kind": "appointment.assigned",
        "title": f"Appointment assigned to {provider_name}",
        "detail": f"{patient_name} · {appointment.procedure} · {appointment.starts_at.strftime('%b %-d, %Y at %-I:%M %p')}",
        "status": "pending",
        "severity": "info",
        "created_at": appointment.created_at,
        "unread": True,
        "cta_label": "View appointment",
        "appointment_id": appointment.id,
        "patient_id": patient.id,
    }


# Handle notification feed for this module.
@router.get("/feed")
async def notification_feed(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    db=Depends(db_session),
    actor=Depends(permit("messaging.notification_delivery.read")),
):
    all_rows = (await db.scalars(select(OutboxMessage).order_by(OutboxMessage.created_at.desc()))).all()
    visible_rows = [row for row in all_rows if _visible_to_actor(row, actor)]
    outbox_items = [_feed_item(row) for row in visible_rows]
    notified_appointments = {
        (row.payload or {}).get("appointment_id")
        for row in visible_rows
        if isinstance(row.payload, dict)
    }
    appointment_rows = (
        await db.execute(
            select(Appointment, Patient, StaffUser)
            .join(Patient, Patient.id == Appointment.patient_id)
            .join(StaffUser, StaffUser.id == Appointment.provider_id)
            .where(
                Appointment.provider_id == actor.user_id,
                Appointment.status == "confirmed",
                Appointment.starts_at >= datetime.now(UTC),
            )
            .order_by(Appointment.starts_at)
            .limit(100)
        )
    ).all()
    appointment_items = [
        _appointment_item(appointment, patient, provider)
        for appointment, patient, provider in appointment_rows
        if appointment.id not in notified_appointments
    ]
    items = sorted([*outbox_items, *appointment_items], key=lambda item: item["created_at"], reverse=True)
    total = len(items)
    unread_count = sum(item.get("unread", False) or item.get("status") in {"pending", "retry", "failed"} for item in items)
    rows = items[(page - 1) * size: page * size]
    audit(db, actor.user_id, "read", "outbox_messages")
    return {
        "items": rows,
        "page": page,
        "size": size,
        "total": total,
        "pages": (total + size - 1) // size,
        "unread_count": unread_count,
    }


# Handle messages for this module.
@router.get("")
async def messages(db=Depends(db_session), actor=Depends(permit("messaging.notification_delivery.read"))):
    rows = (
        await db.scalars(select(OutboxMessage).order_by(OutboxMessage.created_at.desc()).limit(300))
    ).all()
    audit(db, actor.user_id, "read", "outbox_messages")
    return [serialize(x) for x in rows]


# Handle run for this module.
@router.post("/dispatch")
async def run(db=Depends(db_session), actor=Depends(permit("messaging.notification_delivery.retry"))):
    return await dispatch(db, actor)


# Handle retry for this module.
@router.post("/{identifier}/retry")
async def retry(identifier: str, db=Depends(db_session), actor=Depends(permit("messaging.notification_delivery.retry"))):
    row = await required(db, OutboxMessage, identifier, lock=True)
    if row.status in ("failed", "retry"):
        row.status = "pending"
        row.attempts = 0
        row.due_at = None
        audit(db, actor.user_id, "retry", "outbox_messages", row.id)
    await db.flush()
    return serialize(row)
