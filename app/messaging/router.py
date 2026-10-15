from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from app.core.audit import audit
from app.core.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.core.repository import add, required, serialize
from app.identity.security import vault
from app.identity.service import db_session, permit
from app.messaging.models import Message, MessageThread
from app.patients.models import Patient

router = APIRouter(prefix="/messages", tags=["Secure messaging"])


# Defines the new message model, contract, or value object.
class NewMessage(BaseModel):
    patient_id: str = Field(min_length=1, max_length=36)
    subject: str = Field(min_length=1, max_length=180)
    body: str = Field(min_length=1, max_length=8000)


# Handle threads for this module.
@router.get("")
async def threads(db=Depends(db_session), actor=Depends(permit("messaging.message_thread.read"))):
    rows = (await db.scalars(select(MessageThread).order_by(MessageThread.updated_at.desc()))).all()
    return [serialize(row) for row in rows]


@router.get("/patients")
async def message_patients(db=Depends(db_session), actor=Depends(permit("messaging.message_thread.read"))):
    """Return active patients available to a messaging user, including location ids for grouped selection."""
    rows = (
        await db.scalars(
            select(Patient)
            .where(Patient.archived_at.is_(None))
            .order_by(Patient.last_name, Patient.first_name)
        )
    ).all()
    audit(db, actor.user_id, "read", "patients", count=len(rows), purpose="messaging")
    return [serialize(row) for row in rows]


# Handle thread page for this module.
@router.get("/page")
async def thread_page(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    status: str = Query(default="", max_length=30),
    patient_id: str = Query(default="", max_length=36),
    search: str = Query(default="", max_length=80),
    db=Depends(db_session),
    actor=Depends(permit("messaging.message_thread.read")),
):
    query = select(MessageThread).join(Patient, Patient.id == MessageThread.patient_id)
    latest_sender = (
        select(Message.sender_type)
        .where(Message.thread_id == MessageThread.id)
        .order_by(Message.created_at.desc(), Message.id.desc())
        .limit(1)
        .scalar_subquery()
    )
    if status:
        if status == "new":
            query = query.where(MessageThread.status != "closed", latest_sender == "patient")
        else:
            query = query.where(MessageThread.status == status)
    if patient_id:
        query = query.where(MessageThread.patient_id == patient_id)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(or_(MessageThread.subject.ilike(pattern), Patient.first_name.ilike(pattern), Patient.last_name.ilike(pattern)))
    total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (
        await db.execute(
            query.add_columns(latest_sender.label("latest_sender_type"))
            .order_by(MessageThread.updated_at.desc(), MessageThread.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    new_count = await db.scalar(
        select(func.count())
        .select_from(MessageThread)
        .where(MessageThread.status != "closed", latest_sender == "patient")
    ) or 0
    audit(db, actor.user_id, "read", "message_threads", page=page, page_size=page_size)
    return {
        "items": [
            {
                **serialize(thread),
                "latest_sender_type": latest_sender_type,
                "is_new": thread.status != "closed" and latest_sender_type == "patient",
            }
            for thread, latest_sender_type in rows
        ],
        "page": page,
        "page_size": page_size,
        "total": total,
        "pages": (total + page_size - 1) // page_size,
        "new_count": new_count,
    }


# Create or issue create thread while applying existing validation and authorization.
@router.post("", status_code=201)
async def create_thread(
    body: NewMessage,
    db=Depends(db_session),
    actor=Depends(permit("messaging.staff_to_patient_message.send")),
):
    patient = await required(db, Patient, body.patient_id)
    if patient.archived_at is not None:
        raise HTTPException(409, "Archived patient profiles cannot receive messages")
    subject = body.subject.strip()
    message_body = body.body.strip()
    if not subject or not message_body:
        raise HTTPException(422, "Subject and message are required")
    thread = await add(
        db,
        MessageThread,
        {"patient_id": patient.id, "location_id": patient.location_id, "subject": subject, "status": "open"},
        actor.user_id,
    )
    message = await add(
        db,
        Message,
        {
            "thread_id": thread.id,
            "location_id": patient.location_id,
            "sender_type": "staff",
            "sender_id": actor.user_id,
            "body_cipher": vault().seal(message_body),
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "create", "message_threads", thread.id, patient_id=patient.id)
    return {
        "thread": serialize(thread),
        "message": {**serialize(message), "body": message_body, "body_cipher": None},
    }


# Handle thread for this module.
@router.get("/{identifier}")
async def thread(identifier: str, db=Depends(db_session), actor=Depends(permit("messaging.message_thread.read"))):
    record = await required(db, MessageThread, identifier)
    rows = (await db.scalars(select(Message).where(Message.thread_id == record.id).order_by(Message.created_at))).all()
    audit(db, actor.user_id, "read", "message_threads", record.id, patient_id=record.patient_id)
    return {"thread": serialize(record), "messages": [{**serialize(row), "body": vault().open(row.body_cipher), "body_cipher": None} for row in rows]}


# Defines the reply model, contract, or value object.
class Reply(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


# Handle reply for this module.
@router.post("/{identifier}/reply", status_code=201)
async def reply(
    identifier: str,
    body: Reply,
    db=Depends(db_session),
    actor=Depends(permit("messaging.staff_to_patient_message.reply")),
):
    thread = await required(db, MessageThread, identifier)
    if thread.status == "closed":
        raise HTTPException(409, "Closed conversations cannot receive replies")
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


@router.post("/{identifier}/close")
async def close_thread(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit("messaging.message_thread.close")),
):
    """Resolve a patient conversation and make it read-only for both parties."""
    thread = await required(db, MessageThread, identifier, lock=True)
    thread.status = "closed"
    thread.updated_at = datetime.now(timezone.utc)
    thread.updated_by = actor.user_id
    audit(db, actor.user_id, "close", "message_threads", thread.id, patient_id=thread.patient_id)
    await db.flush()
    return {"thread": serialize(thread)}
