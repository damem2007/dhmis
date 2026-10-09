from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.billing.models import Invoice, LedgerEntry, PaymentPlan, Service
from app.billing.service import create_payment_plan, payment
from app.cms.service import default_content, published_revision
from app.consents.models import Consent
from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.forms.models import FormSubmission, FormTemplate
from app.identity.models import StaffUser
from app.identity.service import role_names_with_module
from app.identity.security import digest, vault
from app.integrations.contracts import SignatureRequest
from app.integrations.registry import resolve
from app.messaging.models import Message, MessageThread
from app.organizations.models import Location
from app.patient_identity.service import (
    PatientActor,
    authorized_patient_ids,
    current_patient,
    patient_db_session,
    require_patient_access,
)
from app.patients.models import Patient
from app.scheduling.models import Appointment
from app.scheduling.schemas import Booking, Cancellation
from app.scheduling.service import book, cancel_booking

router = APIRouter(prefix="/portal", tags=["Patient portal"])


@router.get("/context")
async def portal_context(
    actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)
):
    revision = await published_revision(db)
    content = revision.content if revision else await default_content(db, actor.organization)
    locations = (await db.scalars(select(Location).order_by(Location.name))).all()
    providers = (
        await db.scalars(
            select(StaffUser).where(
                StaffUser.active, StaffUser.role.in_(await role_names_with_module(db, "clinical"))
            )
        )
    ).all()
    services = (await db.scalars(select(Service).order_by(Service.name))).all()
    audit(db, actor.user_id, "portal.read", "portal_context", patient_id=actor.patient_id)
    return {
        "booking_enabled": actor.organization.booking_enabled,
        "contact_phone": content.get("contact_phone") or actor.settings.public_content.get("contact_phone", ""),
        "contact_email": content.get("contact_email") or actor.settings.public_content.get("contact_email", ""),
        "locations": [serialize(row) for row in locations],
        "providers": [
            {"id": row.id, "name": row.name, "location_ids": row.location_ids}
            for row in providers
        ],
        "services": [
            {"id": row.id, "name": row.name, "fee_cents": row.fee_cents}
            for row in services
        ],
    }


@router.get("/activity")
async def recent_activity(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=5, le=50),
    kind: str | None = Query(None, pattern="^(appointment|billing|form|message)$"),
    actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)
):
    identifiers = await authorized_patient_ids(db, actor)
    fetch_limit = page * page_size
    appointments = [] if kind not in (None, "appointment") else (
        await db.scalars(
            select(Appointment)
            .where(Appointment.patient_id.in_(identifiers))
            .order_by(Appointment.updated_at.desc(), Appointment.id.desc())
            .limit(fetch_limit)
        )
    ).all()
    invoices = [] if kind not in (None, "billing") else (
        await db.scalars(
            select(Invoice)
            .where(Invoice.patient_id.in_(identifiers))
            .order_by(Invoice.updated_at.desc(), Invoice.id.desc())
            .limit(fetch_limit)
        )
    ).all()
    submissions = [] if kind not in (None, "form") else (
        await db.scalars(
            select(FormSubmission)
            .where(FormSubmission.patient_id.in_(identifiers))
            .order_by(FormSubmission.updated_at.desc(), FormSubmission.id.desc())
            .limit(fetch_limit)
        )
    ).all()
    threads = [] if kind not in (None, "message") else (
        await db.scalars(
            select(MessageThread)
            .where(MessageThread.patient_id.in_(identifiers))
            .order_by(MessageThread.updated_at.desc(), MessageThread.id.desc())
            .limit(fetch_limit)
        )
    ).all()
    counts = []
    if kind in (None, "appointment"):
        counts.append(await db.scalar(select(func.count()).select_from(Appointment).where(Appointment.patient_id.in_(identifiers))))
    if kind in (None, "billing"):
        counts.append(await db.scalar(select(func.count()).select_from(Invoice).where(Invoice.patient_id.in_(identifiers))))
    if kind in (None, "form"):
        counts.append(await db.scalar(select(func.count()).select_from(FormSubmission).where(FormSubmission.patient_id.in_(identifiers))))
    if kind in (None, "message"):
        counts.append(await db.scalar(select(func.count()).select_from(MessageThread).where(MessageThread.patient_id.in_(identifiers))))
    items = [
        {
            "id": row.id,
            "kind": "appointment",
            "title": f"Appointment {row.status}",
            "detail": row.procedure,
            "occurred_at": row.updated_at,
            "target": "book",
        }
        for row in appointments
    ]
    items += [
        {
            "id": row.id,
            "kind": "billing",
            "title": f"Invoice {row.status}",
            "detail": f"Balance {max(0, row.total_cents + row.adjustment_cents - row.paid_cents)} cents",
            "occurred_at": row.updated_at,
            "target": "billing",
        }
        for row in invoices
    ]
    items += [
        {
            "id": row.id,
            "kind": "form",
            "title": "Form submitted",
            "detail": f"Template version {row.template_version}",
            "occurred_at": row.updated_at,
            "target": "forms",
        }
        for row in submissions
    ]
    items += [
        {
            "id": row.id,
            "kind": "message",
            "title": row.subject,
            "detail": f"Secure message thread · {row.status}",
            "occurred_at": row.updated_at,
            "target": "messages",
        }
        for row in threads
    ]
    items.sort(key=lambda item: (item["occurred_at"], item["id"]), reverse=True)
    audit(db, actor.user_id, "portal.read", "recent_activity", patient_id=actor.patient_id)
    offset = (page - 1) * page_size
    return {
        "page": page,
        "page_size": page_size,
        "total": sum(count or 0 for count in counts),
        "items": items[offset : offset + page_size],
    }


@router.get("/profiles")
async def profiles(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    identifiers = await authorized_patient_ids(db, actor)
    rows = (await db.scalars(select(Patient).where(Patient.id.in_(identifiers)))).all()
    audit(db, actor.user_id, "portal.read", "patients", actor.patient_id, profile_count=len(rows))
    return [serialize(row) for row in rows]


@router.get("/appointments")
async def appointments(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    identifiers = await authorized_patient_ids(db, actor)
    rows = (
        await db.scalars(
            select(Appointment)
            .where(Appointment.patient_id.in_(identifiers))
            .order_by(Appointment.starts_at.desc())
        )
    ).all()
    audit(db, actor.user_id, "portal.read", "appointments", patient_id=actor.patient_id)
    return [serialize(row) for row in rows]


@router.post("/appointments", status_code=201)
async def create_appointment(
    body: Booking, actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)
):
    if not actor.organization.booking_enabled:
        raise HTTPException(404, "Online booking is not enabled")
    await require_patient_access(db, actor, body.patient_id)
    return serialize(await book(db, actor, body))


@router.put("/appointments/{identifier}")
async def reschedule_appointment(
    identifier: str,
    body: Booking,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    row = await required(db, Appointment, identifier)
    await require_patient_access(db, actor, row.patient_id)
    if body.patient_id != row.patient_id:
        raise HTTPException(422, "Appointment patient cannot be changed")
    return serialize(await book(db, actor, body, identifier))


@router.post("/appointments/{identifier}/cancel")
async def cancel_appointment(
    identifier: str,
    body: Cancellation,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    row = await required(db, Appointment, identifier)
    await require_patient_access(db, actor, row.patient_id)
    return serialize(await cancel_booking(db, actor, identifier, body.reason))


@router.get("/invoices")
async def invoices(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    identifiers = await authorized_patient_ids(db, actor)
    rows = (
        await db.scalars(select(Invoice).where(Invoice.patient_id.in_(identifiers)).order_by(Invoice.created_at.desc()))
    ).all()
    audit(db, actor.user_id, "portal.read", "invoices", patient_id=actor.patient_id)
    return [serialize(row) for row in rows]


class PortalPayment(BaseModel):
    amount_cents: int = Field(gt=0)
    idempotency_key: str = Field(min_length=8, max_length=100)
    payment_method_token: str | None = None


class PortalPlan(BaseModel):
    installments: int = Field(ge=2, le=24)
    first_due: date


@router.post("/invoices/{identifier}/payments")
async def pay_invoice(
    identifier: str,
    body: PortalPayment,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    invoice = await required(db, Invoice, identifier)
    await require_patient_access(db, actor, invoice.patient_id)
    row = await payment(
        db,
        actor,
        invoice.id,
        body.amount_cents,
        body.idempotency_key,
        payment_method_token=body.payment_method_token,
    )
    return serialize(row)


@router.post("/invoices/{identifier}/payment-plan", status_code=201)
async def create_plan(
    identifier: str,
    body: PortalPlan,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    invoice = await required(db, Invoice, identifier)
    await require_patient_access(db, actor, invoice.patient_id)
    return serialize(
        await create_payment_plan(db, actor, invoice.id, body.installments, body.first_due)
    )


@router.get("/statements/{patient_id}")
async def statement(
    patient_id: str,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    await require_patient_access(db, actor, patient_id)
    invoices = (
        await db.scalars(select(Invoice).where(Invoice.patient_id == patient_id).order_by(Invoice.created_at))
    ).all()
    entries = (
        await db.scalars(
            select(LedgerEntry).where(LedgerEntry.patient_id == patient_id).order_by(LedgerEntry.created_at)
        )
    ).all()
    plans = (await db.scalars(select(PaymentPlan).where(PaymentPlan.patient_id == patient_id))).all()
    balance = 0
    history = []
    for entry in entries:
        balance += entry.amount_cents
        history.append({**serialize(entry), "running_balance_cents": balance})
    audit(db, actor.user_id, "portal.statement", "ledger", patient_id)
    return {"patient_id": patient_id, "balance_cents": balance, "entries": history, "payment_plans": [serialize(x) for x in plans], "invoice_count": len(invoices)}


@router.get("/forms")
async def forms(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    templates = (await db.scalars(select(FormTemplate).where(FormTemplate.active))).all()
    identifiers = await authorized_patient_ids(db, actor)
    submissions = (
        await db.scalars(select(FormSubmission).where(FormSubmission.patient_id.in_(identifiers)))
    ).all()
    return {"templates": [serialize(row) for row in templates], "submissions": [serialize(row) for row in submissions]}


class FormResponse(BaseModel):
    patient_id: str
    responses: dict[str, str | bool | int | float | None]


@router.post("/forms/{template_id}", status_code=201)
async def submit_form(
    template_id: str,
    body: FormResponse,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    await require_patient_access(db, actor, body.patient_id)
    patient = await required(db, Patient, body.patient_id)
    template = await required(db, FormTemplate, template_id)
    expected = {field["name"] for field in template.fields}
    if set(body.responses) - expected:
        raise HTTPException(422, "Form contains unknown fields")
    row = await add(
        db,
        FormSubmission,
        {
            "template_id": template.id,
            "patient_id": patient.id,
            "location_id": patient.location_id,
            "template_version": template.version,
            "responses": body.responses,
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "portal.form", "form_submissions", row.id, patient_id=patient.id)
    return serialize(row)


@router.get("/consents")
async def consents(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    identifiers = await authorized_patient_ids(db, actor)
    rows = (
        await db.scalars(
            select(Consent)
            .where(Consent.patient_id.in_(identifiers))
            .order_by(Consent.created_at.desc())
        )
    ).all()
    audit(db, actor.user_id, "portal.read", "consents", patient_id=actor.patient_id)
    return [serialize(row) for row in rows]


@router.post("/consents/{identifier}/sign")
async def sign_consent(
    identifier: str,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    row = await required(db, Consent, identifier, lock=True)
    await require_patient_access(db, actor, row.patient_id)
    if row.status not in ("requested", "awaiting_signature"):
        raise HTTPException(409, "Consent is not awaiting a signature")
    patient = await required(db, Patient, row.patient_id)
    provider = resolve(actor.organization, "signature_provider")
    result = await provider.request_signature(
        SignatureRequest(
            idempotency_key=row.id,
            document_id=row.id,
            document_digest=digest(row.title + row.template_version),
            signer_name=patient.first_name + " " + patient.last_name,
            signer_email=patient.email,
        )
    )
    if result.sandbox:
        result = await provider.get_signature(result.reference)
        row.status = "simulated"
    else:
        row.status = "awaiting_signature"
    row.certificate = {**result.certificate, "reference": result.reference}
    row.updated_by = actor.user_id
    audit(
        db,
        actor.user_id,
        "portal.signature",
        "consents",
        row.id,
        patient_id=row.patient_id,
        sandbox=result.sandbox,
    )
    await db.flush()
    return serialize(row)


@router.get("/threads")
async def threads(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    identifiers = await authorized_patient_ids(db, actor)
    rows = (
        await db.scalars(
            select(MessageThread).where(MessageThread.patient_id.in_(identifiers)).order_by(MessageThread.updated_at.desc())
        )
    ).all()
    return [serialize(row) for row in rows]


class NewThread(BaseModel):
    patient_id: str
    subject: str = Field(min_length=3, max_length=180)
    body: str = Field(min_length=1, max_length=8000)


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
    audit(db, actor.user_id, "portal.message", "message_threads", thread.id, patient_id=patient.id)
    return serialize(thread)


class Reply(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


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


@router.post("/threads/{identifier}/reply", status_code=201)
async def reply(
    identifier: str,
    body: Reply,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    thread = await required(db, MessageThread, identifier)
    await require_patient_access(db, actor, thread.patient_id)
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
    thread.updated_at = datetime.now(timezone.utc)
    thread.updated_by = actor.user_id
    audit(db, actor.user_id, "portal.reply", "message_threads", thread.id, patient_id=thread.patient_id)
    return {**serialize(row), "body": body.body, "body_cipher": None}
