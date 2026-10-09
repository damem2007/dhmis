import secrets
import time

from sqlalchemy import select

from app.identity.models import PasswordResetChallenge, StaffSession
from app.identity.security import digest
from app.notifications.models import OutboxMessage
from app.organizations.configuration import render_communication_template, tenant_settings


async def issue_password_reset(
    db, user, *, initiated_by: str, reason: str, clinic_name: str = "your clinic"
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
    subject, body = render_communication_template(
        template,
        {"recipient_name": user.name, "clinic_name": clinic_name, "reset_link": raw},
    )
    db.add(
        OutboxMessage(
            kind="staff.password-reset",
            payload={
                "destination": user.email,
                "subject": subject,
                "body": body,
                "user_id": user.id,
            },
            idempotency_key=f"staff-password-reset:{reset.id}",
            created_by=initiated_by,
            updated_by=initiated_by,
        )
    )
    return reset, raw


async def revoke_staff_sessions(db, user, *, actor_id: str):
    sessions = (await db.scalars(select(StaffSession).where(StaffSession.user_id == user.id))).all()
    for session in sessions:
        session.revoked = True
        session.updated_by = actor_id
