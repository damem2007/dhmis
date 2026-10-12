import secrets
import time
from urllib.parse import quote

from fastapi import HTTPException
from sqlalchemy import select

from app.core.audit import audit
from app.core.config import settings
from app.core.repository import add
from app.identity.security import digest
from app.notifications.models import OutboxMessage
from app.notifications.service import deliver_message_now
from app.patient_identity.models import PatientInvite, PatientUser


def patient_invitation_url(raw_token: str, tenant_slug: str) -> str:
    base = settings().tenant_public_url_template.format(tenant_slug=tenant_slug).rstrip('/')
    return f"{base}/{tenant_slug}/portal?invite={quote(raw_token, safe='')}"


async def issue_patient_invite(db, patient, email: str, actor):
    normalized_email = email.strip().lower()
    if not normalized_email:
        return None
    if await db.scalar(select(PatientUser).where(PatientUser.patient_id == patient.id)):
        return None
    if await db.scalar(select(PatientUser).where(PatientUser.email == normalized_email)):
        raise HTTPException(409, 'A Client Portal account already uses this email address')
    raw = secrets.token_urlsafe(32)
    existing = (await db.scalars(select(PatientInvite).where(PatientInvite.patient_id == patient.id, PatientInvite.used.is_(False)))).all()
    for invitation in existing:
        invitation.used = True
        invitation.updated_by = actor.user_id
    record = await add(db, PatientInvite, {
        'patient_id': patient.id,
        'email': normalized_email,
        'token_hash': digest(raw),
        'expires': int(time.time()) + 86400,
    }, actor.user_id)
    link = patient_invitation_url(raw, actor.organization.slug)
    await deliver_message_now(db, actor, OutboxMessage(
        kind='patient.invitation',
        payload={
            'destination': record.email,
            'subject': f'Your {actor.organization.name} Client Portal invitation',
            'body': f'Use this one-time Client Portal invitation link within 24 hours: {link}',
            'channel': 'email',
        },
        idempotency_key=f'patient-invitation:{record.id}',
        created_by=actor.user_id,
        updated_by=actor.user_id,
    ))
    audit(db, actor.user_id, 'portal.invite', 'patients', patient.id)
    return {'invite_id': record.id, 'token': raw, 'invitation_link': link, 'expires_in': 86400}
