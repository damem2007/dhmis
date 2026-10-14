"""Patient portal core routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.billing.models import Invoice, Service
from app.cms.services import default_content, published_revision
from app.consents.models import Consent
from app.core.audit import audit
from app.core.repository import serialize
from app.forms.models import FormSubmission, FormTemplate
from app.identity.models import StaffUser
from app.identity.service import role_names_with_module
from app.messaging.models import MessageThread
from app.organizations.models import Location
from app.patient_identity.service import (
    PatientActor,
    authorized_patient_ids,
    current_patient,
    patient_db_session,
)
from app.patients.models import Patient
from app.scheduling.models import Appointment

router = APIRouter()

# Handle portal context for this module.
@router.get("/context")
async def portal_context(
    actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)
):
    revision = await published_revision(db)
    content = revision.content if revision else await default_content(db, actor.organization)
    locations = (await db.scalars(select(Location).where(Location.active).order_by(Location.name))).all()
    providers = (
        await db.scalars(
            select(StaffUser).where(
                StaffUser.active,
                StaffUser.is_provider,
                StaffUser.archived_at.is_(None),
                StaffUser.role.in_(await role_names_with_module(db, "clinical")),
                (StaffUser.suspended_until.is_(None) | (StaffUser.suspended_until <= datetime.now(timezone.utc))),
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


# Handle recent activity for this module.
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


@router.get("/notifications")
async def notifications(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    """Return the patient's catch-all notification feed.

    Read state is intentionally kept by the portal client so the compact bell can
    acknowledge an item without deleting it from the full notification center.
    """
    identifiers = await authorized_patient_ids(db, actor)
    now = datetime.now(timezone.utc)
    items = []

    appointments = (
        await db.scalars(
            select(Appointment)
            .where(Appointment.patient_id.in_(identifiers))
            .order_by(Appointment.starts_at.desc(), Appointment.id.desc())
        )
    ).all()
    for row in appointments:
        status = (row.status or "").lower()
        if status in {"missed", "no-show", "no_show"}:
            title = "Missed appointment"
            detail = f"{row.procedure} · {row.starts_at.astimezone().strftime('%b %-d, %Y at %-I:%M %p')}"
            occurred_at = row.updated_at
            kind = "appointment-missed"
        elif status == "confirmed" and row.starts_at >= now:
            title = "Appointment reminder"
            detail = f"{row.procedure} · {row.starts_at.astimezone().strftime('%b %-d, %Y at %-I:%M %p')}"
            occurred_at = row.starts_at
            kind = "appointment-reminder"
        else:
            continue
        items.append({"id": f"appointment:{row.id}:{kind}", "kind": kind, "title": title, "detail": detail, "occurred_at": occurred_at, "target": "book"})

    invoices = (
        await db.scalars(
            select(Invoice)
            .where(Invoice.patient_id.in_(identifiers))
            .order_by(Invoice.updated_at.desc(), Invoice.id.desc())
        )
    ).all()
    for row in invoices:
        balance = max(0, row.total_cents + row.adjustment_cents - row.paid_cents)
        if balance:
            items.append({"id": f"invoice:{row.id}:{row.updated_at.isoformat()}:due", "kind": "billing-due", "title": "Due bill", "detail": f"{balance / 100:.2f} due", "occurred_at": row.updated_at, "target": "billing"})

    submissions = (
        await db.scalars(
            select(FormSubmission)
            .where(FormSubmission.patient_id.in_(identifiers))
            .order_by(FormSubmission.updated_at.desc(), FormSubmission.id.desc())
        )
    ).all()
    submission_keys = {(row.patient_id, row.template_id) for row in submissions}
    for row in submissions:
        items.append({"id": f"form:{row.id}:{row.updated_at.isoformat()}:submitted", "kind": "form", "title": "Form submitted", "detail": f"Template version {row.template_version}", "occurred_at": row.updated_at, "target": "forms"})
    templates = (await db.scalars(select(FormTemplate).where(FormTemplate.active))).all()
    for profile_id in identifiers:
        for template in templates:
            if (profile_id, template.id) not in submission_keys:
                items.append({"id": f"form:{profile_id}:{template.id}:required", "kind": "form", "title": "Form to complete", "detail": f"{template.title} · v{template.version}", "occurred_at": template.updated_at, "target": "forms"})
    consents = (
        await db.scalars(
            select(Consent)
            .where(Consent.patient_id.in_(identifiers), Consent.status.in_(["requested", "awaiting_signature"]))
            .order_by(Consent.updated_at.desc(), Consent.id.desc())
        )
    ).all()
    for row in consents:
        items.append({"id": f"consent:{row.id}:{row.updated_at.isoformat()}", "kind": "form", "title": "Consent to review", "detail": f"{row.title} · v{row.template_version}", "occurred_at": row.updated_at, "target": "forms"})

    threads = (
        await db.scalars(
            select(MessageThread)
            .where(MessageThread.patient_id.in_(identifiers))
            .order_by(MessageThread.updated_at.desc(), MessageThread.id.desc())
        )
    ).all()
    for row in threads:
        items.append({"id": f"message:{row.id}:{row.updated_at.isoformat()}", "kind": "message", "title": "Secure message", "detail": f"{row.subject} · {row.status}", "occurred_at": row.updated_at, "target": "messages"})

    items.sort(key=lambda item: (item["occurred_at"], item["id"]), reverse=True)
    audit(db, actor.user_id, "portal.read", "notifications", patient_id=actor.patient_id)
    return {"items": items}


# Handle profiles for this module.
@router.get("/profiles")
async def profiles(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    identifiers = await authorized_patient_ids(db, actor)
    rows = (await db.scalars(select(Patient).where(Patient.id.in_(identifiers)))).all()
    audit(db, actor.user_id, "portal.read", "patients", actor.patient_id, profile_count=len(rows))
    return [serialize(row) for row in rows]


