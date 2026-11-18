import secrets
import time
from urllib.parse import quote

from sqlalchemy import select

from app.core.config import settings
from app.identity.models import PasswordResetChallenge, StaffSession
from app.identity.security import digest
from app.notifications.models import OutboxMessage
from app.organizations.configuration import (
    communication_template_deliveries,
    render_communication_template,
    tenant_settings,
)


def staff_password_reset_url(raw_token: str, tenant_slug: str) -> str:
    base = settings().tenant_admin_public_url_template.format(tenant_slug=tenant_slug).rstrip("/")
    return f"{base}/?reset={quote(raw_token, safe='')}"


# Create or issue issue password reset while applying existing validation and authorization.
async def issue_password_reset(
    db,
    user,
    *,
    initiated_by: str,
    reason: str,
    clinic_name: str = "your clinic",
    tenant_slug: str = "",
):
    previous = (
        await db.scalars(
            select(PasswordResetChallenge).where(
                PasswordResetChallenge.user_id == user.id,
                PasswordResetChallenge.used.is_(False),
            )
        )
    ).all()
    for challenge in previous:
        challenge.used = True
        challenge.updated_by = initiated_by
    raw = secrets.token_urlsafe(32)
    reset = PasswordResetChallenge(
        user_id=user.id,
        token_hash=digest(raw),
        expires=int(time.time()) + 3600,
        initiated_by=initiated_by,
        reason=reason,
        created_by=initiated_by,
        updated_by=initiated_by,
    )
    db.add(reset)
    await db.flush()
    template = (await tenant_settings(db)).communication_templates["password-reset"]
    email_template = next(
        (content for channel, content in communication_template_deliveries(template) if channel == "email"),
        None,
    )
    if email_template is None:
        # Staff accounts currently have an email identity and no verified
        # mobile channel. Do not issue an unusable reset challenge.
        raise ValueError("Password reset requires an active email template")
    subject, body = render_communication_template(
        email_template,
        {
            "recipient_name": user.name,
            "clinic_name": clinic_name,
            "reset_link": staff_password_reset_url(raw, tenant_slug) if tenant_slug else raw,
        },
    )
    message = OutboxMessage(
        kind="staff.password-reset",
        payload={
            "destination": user.email,
            "subject": subject,
            "body": body,
            "channel": "email",
            "user_id": user.id,
        },
        idempotency_key=f"staff-password-reset:{reset.id}",
        created_by=initiated_by,
        updated_by=initiated_by,
    )
    db.add(message)
    return reset, raw, message


async def issue_password_reset_and_deliver(
    db,
    user,
    organization,
    *,
    initiated_by: str,
    reason: str,
    clinic_name: str,
    tenant_slug: str,
):
    """Issue an expired-password link and deliver it through the tenant provider."""
    reset, raw, message = await issue_password_reset(
        db,
        user,
        initiated_by=initiated_by,
        reason=reason,
        clinic_name=clinic_name,
        tenant_slug=tenant_slug,
    )
    from app.identity.service import Actor
    from app.integrations.configuration import attach_effective_adapters
    from app.notifications.service import deliver_message_now

    actor = Actor(
        user_id=user.id,
        organization=organization,
        name=user.name,
        role=user.role,
        adapter_names=await attach_effective_adapters(organization),
    )
    await deliver_message_now(db, actor, message)
    return reset, raw, message


# Apply the revoke staff sessions lifecycle transition and its existing safeguards.
async def revoke_staff_sessions(db, user, *, actor_id: str):
    sessions = (await db.scalars(select(StaffSession).where(StaffSession.user_id == user.id))).all()
    for session in sessions:
        session.revoked = True
        session.updated_by = actor_id
