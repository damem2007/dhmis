from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from sqlalchemy import or_, select

from app.core.config import settings
from app.core.database import control_session
from app.integrations.configuration import platform_adapter_names
from app.integrations.contracts import IntegrationFailure, MessageRequest
from app.integrations.registry import resolve
from app.organizations.configuration import platform_configuration, render_communication_template
from app.platform_identity.models import PlatformOutboxMessage
from app.platform_identity.service import platform_audit

DELIVERED_STATES = {"simulated", "sent", "delivered", "accepted"}


@dataclass
class PlatformProviderContext:
    id: str = "dhmis-platform"
    region: str = "*"
    _effective_adapters: dict[str, str] | None = None


def platform_action_url(action: str, token: str) -> str:
    base = settings().platform_public_url.rstrip("/")
    return f"{base}/admin/?{action}={quote(token, safe='')}"


async def enqueue_platform_email(
    db,
    *,
    kind: str,
    destination: str,
    recipient_name: str,
    raw_token: str,
    reference_id: str,
    actor_id: str,
) -> PlatformOutboxMessage:
    template_key = "staff-invitation" if kind == "platform.invitation" else "password-reset"
    token_key = "invitation_link" if kind == "platform.invitation" else "reset_link"
    action = "invite" if kind == "platform.invitation" else "reset"
    configuration = await platform_configuration(db)
    template = configuration.communication_templates.get(template_key, {})
    if not template.get("active") or template.get("channel") != "email":
        raise IntegrationFailure(f"Platform {template_key} email template is not active")
    subject, body = render_communication_template(
        template,
        {
            "clinic_name": "DHMIS Platform",
            "recipient_name": recipient_name,
            token_key: platform_action_url(action, raw_token),
        },
    )
    row = PlatformOutboxMessage(
        kind=kind,
        payload={
            "channel": "email",
            "destination": destination,
            "subject": subject,
            "body": body,
            "reference_id": reference_id,
        },
        status="pending",
        idempotency_key=f"{kind}:{reference_id}",
        created_by=actor_id,
        updated_by=actor_id,
    )
    db.add(row)
    await db.flush()
    platform_audit(
        db,
        actor_id,
        f"{kind}.delivery.queued",
        details={"outbox_id": row.id, "reference_id": reference_id},
    )
    return row


async def dispatch_platform_outbox(db, now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(UTC)
    rows = (
        await db.scalars(
            select(PlatformOutboxMessage)
            .where(
                PlatformOutboxMessage.status.in_(["pending", "retry"]),
                or_(
                    PlatformOutboxMessage.due_at.is_(None),
                    PlatformOutboxMessage.due_at <= now,
                ),
            )
            .with_for_update(skip_locked=True)
        )
    ).all()
    adapters = await platform_adapter_names(db)
    context = PlatformProviderContext(_effective_adapters=adapters)
    delivered = failed = 0
    for row in rows:
        row.attempts += 1
        row.updated_by = "platform-delivery-worker"
        try:
            request = MessageRequest(
                idempotency_key=row.idempotency_key,
                channel="email",
                destination=row.payload["destination"],
                subject=row.payload["subject"],
                body=row.payload["body"],
            )
            row.result = await resolve(context, "email_provider").send(request)
            if row.result.get("status") not in DELIVERED_STATES:
                raise IntegrationFailure("Provider did not accept platform email delivery")
            row.status = row.result["status"]
            row.due_at = None
            delivered += 1
            platform_audit(
                db,
                "platform-delivery-worker",
                f"{row.kind}.delivery.accepted",
                details={
                    "outbox_id": row.id,
                    "reference_id": row.payload.get("reference_id", ""),
                    "sandbox": bool(row.result.get("sandbox")),
                },
            )
        except (IntegrationFailure, KeyError, ValueError) as error:
            row.status = "failed" if row.attempts >= 5 else "retry"
            row.due_at = now + timedelta(seconds=30 * 2**row.attempts)
            row.result = {"error": str(error)}
            failed += 1
            platform_audit(
                db,
                "platform-delivery-worker",
                f"{row.kind}.delivery.failed",
                details={
                    "outbox_id": row.id,
                    "reference_id": row.payload.get("reference_id", ""),
                    "terminal": row.status == "failed",
                },
            )
    await db.flush()
    return {"delivered": delivered, "failed": failed}


async def platform_tick(context):
    async with control_session() as db:
        return await dispatch_platform_outbox(db)
