from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.identity.security import vault
from app.identity.service import db_session, permit
from app.messaging.models import Message, MessageThread

router = APIRouter(prefix="/messages", tags=["Secure messaging"])


@router.get("")
async def threads(db=Depends(db_session), actor=Depends(permit("patients"))):
    rows = (await db.scalars(select(MessageThread).order_by(MessageThread.updated_at.desc()))).all()
    return [serialize(row) for row in rows]


@router.get("/{identifier}")
async def thread(identifier: str, db=Depends(db_session), actor=Depends(permit("patients"))):
    record = await required(db, MessageThread, identifier)
    rows = (await db.scalars(select(Message).where(Message.thread_id == record.id).order_by(Message.created_at))).all()
    audit(db, actor.user_id, "read", "message_threads", record.id, patient_id=record.patient_id)
    return {"thread": serialize(record), "messages": [{**serialize(row), "body": vault().open(row.body_cipher), "body_cipher": None} for row in rows]}


class Reply(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


@router.post("/{identifier}/reply", status_code=201)
async def reply(
    identifier: str, body: Reply, db=Depends(db_session), actor=Depends(permit("patients"))
):
    thread = await required(db, MessageThread, identifier)
    row = await add(
        db,
        Message,
        {
            "thread_id": thread.id,
            "location_id": thread.location_id,
            "sender_type": "staff",
            "sender_id": actor.user_id,
            "body_cipher": vault().seal(body.body),
        },
        actor.user_id,
    )
    thread.updated_at = datetime.now(timezone.utc)
    thread.updated_by = actor.user_id
    audit(db, actor.user_id, "reply", "message_threads", thread.id, patient_id=thread.patient_id)
    return {**serialize(row), "body": body.body, "body_cipher": None}
