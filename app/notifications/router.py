from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.core.audit import audit
from app.core.repository import required, serialize
from app.identity.service import db_session, permit
from app.notifications.models import OutboxMessage
from app.notifications.service import dispatch

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
    }


# Handle notification feed for this module.
@router.get("/feed")
async def notification_feed(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10, ge=10, le=50),
    db=Depends(db_session),
    actor=Depends(permit("messaging.notification_delivery.read")),
):
    total = await db.scalar(select(func.count()).select_from(OutboxMessage)) or 0
    unread_count = await db.scalar(
        select(func.count()).select_from(OutboxMessage).where(OutboxMessage.status.in_(("pending", "retry", "failed")))
    ) or 0
    rows = (
        await db.scalars(
            select(OutboxMessage)
            .order_by(OutboxMessage.created_at.desc())
            .offset((page - 1) * size)
            .limit(size)
        )
    ).all()
    audit(db, actor.user_id, "read", "outbox_messages")
    return {
        "items": [_feed_item(row) for row in rows],
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
