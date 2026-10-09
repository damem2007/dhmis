from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select

from app.claims.models import Claim
from app.claims.service import adjudicate_claim
from app.core.audit import audit
from app.identity.models import StaffUser
from app.integrations.contracts import IntegrationFailure, MessageRequest
from app.integrations.registry import resolve
from app.notifications.models import OutboxMessage
from app.organizations.configuration import render_communication_template
from app.patients.models import Patient
from app.scheduling.models import Appointment


async def dispatch(db, actor, now=None):
    now = now or datetime.now(timezone.utc)
    messages = (
        await db.scalars(
            select(OutboxMessage)
            .where(
                OutboxMessage.status.in_(["pending", "retry"]),
                or_(OutboxMessage.due_at.is_(None), OutboxMessage.due_at <= now),
            )
            .with_for_update(skip_locked=True)
        )
    ).all()
    delivered = failed = suppressed = 0
    for message in messages:
        if message.kind in {
            "patient.verification",
            "staff.invitation",
            "staff.password-reset",
            "communication-template.test",
            "billing.installment-due",
            "billing.installment-overdue",
        }:
            channel = message.payload.get("channel", "email")
            request = MessageRequest(
                idempotency_key=message.idempotency_key,
                channel=channel,
                destination=message.payload["destination"],
                subject=message.payload.get(
                    "subject", "Your Client Portal verification code"
                ),
                body=message.payload["body"],
            )
            message.attempts += 1
            try:
                capability = (
                    channel + "_provider"
                    if channel + "_provider" in actor.adapter_names
                    else "messaging_provider"
                )
                message.result = await resolve(actor.organization, capability).send(request)
                if message.result.get("status") not in (
                    "simulated",
                    "sent",
                    "delivered",
                    "accepted",
                ):
                    raise IntegrationFailure("Provider did not accept delivery")
                message.status = message.result["status"]
                delivered += 1
                audit(
                    db,
                    actor.user_id,
                    message.kind + ".delivery",
                    "outbox_messages",
                    message.id,
                    patient_id=message.payload.get("patient_id", ""),
                    user_id=message.payload.get("user_id", ""),
                    sandbox=message.result.get("sandbox", False),
                )
            except IntegrationFailure as error:
                message.status = "failed" if message.attempts >= 5 else "retry"
                message.due_at = now + timedelta(seconds=30 * 2**message.attempts)
                message.result = {"error": str(error)}
                failed += 1
            continue
        appointment = await db.get(Appointment, message.payload.get("appointment_id"))
        stale = bool(
            appointment
            and message.payload.get("starts_at")
            and datetime.fromisoformat(message.payload["starts_at"]) != appointment.starts_at
        )
        if not appointment or appointment.status != "confirmed" or stale or appointment.starts_at < now:
            message.status = "suppressed"
            suppressed += 1
            continue
        patient = await db.get(Patient, appointment.patient_id)
        template = actor.settings.communication_templates.get("appointment-reminder", {})
        preferred_channel = template.get("channel", "email")
        channel = (
            preferred_channel
            if (preferred_channel == "email" and patient.email)
            or (preferred_channel == "sms" and patient.phone)
            else "email" if patient.email else "sms"
        )
        destination = patient.email if channel == "email" else patient.phone
        if not destination:
            message.status = "failed"
            message.result = {"error": "Missing contact destination"}
            failed += 1
            continue
        provider = await db.get(StaffUser, appointment.provider_id) if appointment.provider_id else None
        subject, body = render_communication_template(
            template,
            {
                "clinic_name": actor.organization.name,
                "clinic_phone": actor.settings.public_content.get("contact_phone", "the clinic"),
                "patient_first_name": patient.first_name,
                "provider_name": provider.name if provider else "your provider",
                "appointment_date": appointment.starts_at.strftime("%B %-d, %Y"),
                "appointment_time": appointment.starts_at.strftime("%-I:%M %p"),
            },
        )
        request = MessageRequest(
            idempotency_key=message.idempotency_key,
            channel=channel,
            destination=destination,
            subject=subject or "Appointment reminder",
            body=body,
        )
        message.attempts += 1
        try:
            capability = (
                channel + "_provider"
                if channel + "_provider" in actor.adapter_names
                else "messaging_provider"
            )
            message.result = await resolve(actor.organization, capability).send(request)
            if message.result.get("status") not in ("simulated", "sent", "delivered", "accepted"):
                raise IntegrationFailure("Provider did not accept delivery")
            message.status = message.result["status"]
            delivered += 1
            audit(
                db,
                actor.user_id,
                "message.delivery",
                "outbox_messages",
                message.id,
                patient_id=patient.id,
                channel=channel,
                sandbox=message.result.get("sandbox", False),
            )
        except IntegrationFailure as error:
            message.status = "failed" if message.attempts >= 5 else "retry"
            message.due_at = now + timedelta(seconds=30 * 2**message.attempts)
            message.result = {"error": str(error)}
            failed += 1
    claims = (
        await db.scalars(
            select(Claim)
            .where(Claim.status.in_(["submitted", "appealed"]), Claim.due_at <= now)
            .with_for_update(skip_locked=True)
        )
    ).all()
    advanced = 0
    for claim in claims:
        try:
            await adjudicate_claim(db, actor, claim)
            advanced += 1
        except IntegrationFailure as error:
            claim.discrepancy = str(error)
            claim.due_at = now + timedelta(minutes=5)
    await db.flush()
    return {"delivered": delivered, "failed": failed, "suppressed": suppressed, "claims_advanced": advanced}
