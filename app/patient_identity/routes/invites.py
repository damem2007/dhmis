"""Patient portal invitation routes."""

import secrets
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from app.core.audit import audit
from app.core.repository import add, required
from app.identity.security import digest
from app.identity.service import db_session, permit
from app.notifications.models import OutboxMessage
from app.notifications.service import deliver_message_now
from app.patient_identity.invitations import issue_patient_invite, patient_invitation_url
from app.patient_identity.models import PatientInvite, PatientUser
from app.patients.models import Patient

router = APIRouter()


# Defines the invite input model, contract, or value object.
class InviteInput(BaseModel):
    patient_id: str
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)


InviteInput.__module__ = "app.patient_identity.router"


# Create or issue create invite while applying existing validation and authorization.
@router.post("/invites", status_code=201)
async def create_invite(body: InviteInput, db=Depends(db_session), actor=Depends(permit("patients"))):
    patient = await required(db, Patient, body.patient_id)
    if await db.scalar(select(PatientUser).where(PatientUser.patient_id == patient.id)):
        raise HTTPException(409, "Client Portal account already exists")
    return await issue_patient_invite(db, patient, body.email, actor)


# Handle patient invites for this module.
@router.get("/invites/query")
async def patient_invites(
    search: str | None = None,
    status: str | None = None,
    page: int = 1,
    page_size: int = 25,
    db=Depends(db_session),
    actor=Depends(permit("patients")),
):
    if page < 1 or page_size < 10 or page_size > 100:
        raise HTTPException(422, "Invalid invitation pagination")
    now = int(time.time())
    query = select(PatientInvite, Patient).join(Patient, Patient.id == PatientInvite.patient_id)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(
            or_(
                PatientInvite.email.ilike(term),
                Patient.first_name.ilike(term),
                Patient.last_name.ilike(term),
            )
        )
    if status == "accepted":
        query = query.where(PatientInvite.used.is_(True))
    elif status == "expired":
        query = query.where(PatientInvite.used.is_(False), PatientInvite.expires <= now)
    elif status == "pending":
        query = query.where(PatientInvite.used.is_(False), PatientInvite.expires > now)
    elif status not in (None, ""):
        raise HTTPException(422, "Unknown invitation status")
    total = await db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    rows = (
        await db.execute(
            query.order_by(PatientInvite.created_at.desc(), PatientInvite.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    audit(db, actor.user_id, "portal.invites.read", "patients", page=page, page_size=page_size)
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [
            {
                "id": invitation.id,
                "patient_id": invitation.patient_id,
                "recipient_name": f"{patient.first_name} {patient.last_name}",
                "email": invitation.email,
                "created_at": invitation.created_at,
                "expires": invitation.expires,
                "status": "accepted" if invitation.used else "expired" if invitation.expires <= now else "pending",
            }
            for invitation, patient in rows
        ],
    }


# Handle resend patient invite for this module.
@router.post("/invites/{identifier}/resend", status_code=201)
async def resend_patient_invite(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit("patients")),
):
    invitation = await required(db, PatientInvite, identifier, lock=True)
    if invitation.used and invitation.expires > int(time.time()):
        raise HTTPException(409, "Accepted or revoked invitations cannot be resent")
    if await db.scalar(select(PatientUser).where(PatientUser.patient_id == invitation.patient_id)):
        raise HTTPException(409, "Client Portal account already exists")
    invitation.used = True
    invitation.updated_by = actor.user_id
    raw = secrets.token_urlsafe(32)
    replacement = await add(
        db,
        PatientInvite,
        {
            "patient_id": invitation.patient_id,
            "email": invitation.email,
            "token_hash": digest(raw),
            "expires": int(time.time()) + 86400,
        },
        actor.user_id,
    )
    await deliver_message_now(
        db,
        actor,
        OutboxMessage(
            kind="patient.invitation",
            payload={
                "destination": replacement.email,
                "body": f"Use this one-time Client Portal invitation link within 24 hours: {patient_invitation_url(raw, actor.organization.slug)}",
            },
            idempotency_key=f"patient-invitation:{replacement.id}",
            created_by=actor.user_id,
            updated_by=actor.user_id,
        ),
    )
    audit(db, actor.user_id, "portal.invite.resend", "patients", invitation.patient_id)
    return {"invite_id": replacement.id, "token": raw, "invitation_link": patient_invitation_url(raw, actor.organization.slug), "expires": replacement.expires}


# Apply the revoke patient invite lifecycle transition and its existing safeguards.
@router.post("/invites/{identifier}/revoke")
async def revoke_patient_invite(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit("patients")),
):
    invitation = await required(db, PatientInvite, identifier, lock=True)
    if invitation.used:
        raise HTTPException(409, "Invitation is no longer pending")
    invitation.used = True
    invitation.expires = int(time.time())
    invitation.updated_by = actor.user_id
    audit(db, actor.user_id, "portal.invite.revoke", "patients", invitation.patient_id)
    return {"revoked": True}


__all__ = ["InviteInput", "create_invite", "patient_invites", "resend_patient_invite", "revoke_patient_invite", "router"]
