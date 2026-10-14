"""Patient portal messaging routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.identity.security import vault
from app.messaging.models import Message, MessageThread
from app.notifications.models import OutboxMessage
from app.patient_identity.service import (
    PatientActor,
    authorized_patient_ids,
    current_patient,
    patient_db_session,
    require_patient_access,
)
from app.patients.models import Patient

router = APIRouter()

# Handle threads for this module.
@router.get("/threads")
async def threads(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    identifiers = await authorized_patient_ids(db, actor)
    rows = (
        await db.scalars(
            select(MessageThread).where(MessageThread.patient_id.in_(identifiers)).order_by(MessageThread.updated_at.desc())
        )
    ).all()
    return [serialize(row) for row in rows]


# Handle thread page for this module.
@router.get("/threads/page")
async def thread_page(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=3, ge=1, le=200),
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    identifiers = await authorized_patient_ids(db, actor)
    open_rows = (
        await db.scalars(
            select(MessageThread)
            .where(MessageThread.patient_id.in_(identifiers), MessageThread.status != "closed")
            .order_by(MessageThread.updated_at.desc(), MessageThread.id.desc())
        )
    ).all()
    history_query = select(MessageThread).where(MessageThread.patient_id.in_(identifiers), MessageThread.status == "closed")
    history_total = await db.scalar(select(func.count()).select_from(history_query.subquery())) or 0
    history_rows = (
        await db.scalars(
            history_query.order_by(MessageThread.updated_at.desc(), MessageThread.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    audit(db, actor.user_id, "portal.read", "message_threads", page=page, page_size=page_size)
    return {
        "open": [serialize(row) for row in open_rows],
        "history": {
            "items": [serialize(row) for row in history_rows],
            "page": page,
            "page_size": page_size,
            "total": history_total,
            "pages": (history_total + page_size - 1) // page_size,
        },
    }


# Defines the new thread model, contract, or value object.
class NewThread(BaseModel):
    patient_id: str
    subject: str = Field(min_length=3, max_length=180)
    body: str = Field(min_length=1, max_length=8000)


# Create or issue create thread while applying existing validation and authorization.
@router.post("/threads", status_code=201)
async def create_thread(
    body: NewThread,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    await require_patient_access(db, actor, body.patient_id)
    patient = await required(db, Patient, body.patient_id)
    thread = await add(
        db,
        MessageThread,
        {"patient_id": patient.id, "location_id": patient.location_id, "subject": body.subject},
        actor.user_id,
    )
    await add(
        db,
        Message,
        {
            "thread_id": thread.id,
            "location_id": patient.location_id,
            "sender_type": "patient",
            "sender_id": actor.user_id,
            "body_cipher": vault().seal(body.body),
        },
        actor.user_id,
    )
    await add(
        db,
        OutboxMessage,
        {
            "kind": "patient.message",
            "payload": {
                "channel": "in_app",
                "thread_id": thread.id,
                "patient_id": patient.id,
                "location_id": patient.location_id,
                "title": "New patient message",
                "subject": f"{patient.first_name} {patient.last_name}: {body.subject}",
                "cta_label": "Open message",
            },
            "status": "pending",
            "idempotency_key": f"patient-message:{thread.id}",
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "portal.message", "message_threads", thread.id, patient_id=patient.id)
    return serialize(thread)


# Defines the reply model, contract, or value object.
class Reply(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


# Handle thread for this module.
@router.get("/threads/{identifier}")
async def thread(
    identifier: str,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    thread = await required(db, MessageThread, identifier)
    await require_patient_access(db, actor, thread.patient_id)
    rows = (await db.scalars(select(Message).where(Message.thread_id == thread.id).order_by(Message.created_at))).all()
    audit(db, actor.user_id, "portal.read", "message_threads", thread.id, patient_id=thread.patient_id)
    return {"thread": serialize(thread), "messages": [{**serialize(row), "body": vault().open(row.body_cipher), "body_cipher": None} for row in rows]}


# Handle reply for this module.
@router.post("/threads/{identifier}/reply", status_code=201)
async def reply(
    identifier: str,
    body: Reply,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    thread = await required(db, MessageThread, identifier)
    await require_patient_access(db, actor, thread.patient_id)
    if thread.status == "closed":
        raise HTTPException(409, "Closed conversations cannot receive replies")
    row = await add(
        db,
        Message,
        {
            "thread_id": thread.id,
            "location_id": thread.location_id,
            "sender_type": "patient",
            "sender_id": actor.user_id,
            "body_cipher": vault().seal(body.body),
        },
        actor.user_id,
    )
    await add(
        db,
        OutboxMessage,
        {
            "kind": "patient.message.reply",
            "payload": {
                "channel": "in_app",
                "thread_id": thread.id,
                "patient_id": thread.patient_id,
                "location_id": thread.location_id,
                "title": "Patient replied to a message",
                "subject": thread.subject,
                "cta_label": "Open message",
            },
            "status": "pending",
            "idempotency_key": f"patient-message:{row.id}",
        },
        actor.user_id,
    )
    thread.updated_at = datetime.now(timezone.utc)
    thread.updated_by = actor.user_id
    audit(db, actor.user_id, "portal.reply", "message_threads", thread.id, patient_id=thread.patient_id)
    return {**serialize(row), "body": body.body, "body_cipher": None}
