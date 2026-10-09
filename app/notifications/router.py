from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.core.audit import audit
from app.core.repository import required, serialize
from app.identity.service import db_session, permit
from app.notifications.models import OutboxMessage
from app.notifications.service import dispatch

router = APIRouter(prefix="/notifications", tags=["Notification operations"])


@router.get("")
async def messages(db=Depends(db_session), actor=Depends(permit("settings"))):
    rows = (
        await db.scalars(select(OutboxMessage).order_by(OutboxMessage.created_at.desc()).limit(300))
    ).all()
    audit(db, actor.user_id, "read", "outbox_messages")
    return [serialize(x) for x in rows]


@router.post("/dispatch")
async def run(db=Depends(db_session), actor=Depends(permit("settings"))):
    return await dispatch(db, actor)


@router.post("/{identifier}/retry")
async def retry(identifier: str, db=Depends(db_session), actor=Depends(permit("settings"))):
    row = await required(db, OutboxMessage, identifier, lock=True)
    if row.status in ("failed", "retry"):
        row.status = "pending"
        row.attempts = 0
        row.due_at = None
        audit(db, actor.user_id, "retry", "outbox_messages", row.id)
    await db.flush()
    return serialize(row)
