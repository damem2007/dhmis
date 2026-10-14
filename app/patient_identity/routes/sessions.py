"""Patient portal account and session routes."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.audit import audit
from app.core.repository import required
from app.identity.passwords import hash_password, verify_password
from app.patient_identity.models import PatientSession, PatientUser
from app.patient_identity.service import PatientActor, current_patient, patient_db_session
from app.patients.models import Patient

router = APIRouter()


# Defines the password change model, contract, or value object.
class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=128)


PasswordChange.__module__ = "app.patient_identity.router"


# Handle me for this module.
@router.get("/me")
async def me(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    patient = await required(db, Patient, actor.patient_id)
    audit(db, actor.user_id, "portal.read", "patients", patient.id)
    return {"id": actor.user_id, "patient_id": patient.id, "organization_id": actor.organization.id, "organization_name": actor.organization.name, "organization_slug": actor.organization.slug, "name": f"{patient.first_name} {patient.last_name}", "email": (await required(db, PatientUser, actor.user_id)).email, "branding": actor.settings.branding, "logo_url": actor.settings.logo_url}


# Handle sessions for this module.
@router.get("/auth/sessions")
async def sessions(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    rows = (await db.scalars(select(PatientSession).where(PatientSession.user_id == actor.user_id, PatientSession.revoked.is_(False)).order_by(PatientSession.last_active.desc()))).all()
    audit(db, actor.user_id, "portal.sessions.read", "patient_auth", actor.user_id)
    return [{"id": row.id, "current": row.id == actor.session_id, "last_active": row.last_active, "expires": row.expires} for row in rows]


# Apply the revoke other sessions lifecycle transition and its existing safeguards.
@router.post("/auth/sessions/revoke-others")
async def revoke_other_sessions(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    rows = (await db.scalars(select(PatientSession).where(PatientSession.user_id == actor.user_id, PatientSession.id != actor.session_id, PatientSession.revoked.is_(False)))).all()
    for row in rows:
        row.revoked = True
    audit(db, actor.user_id, "portal.sessions.revoke_others", "patient_auth", actor.user_id, revoked_count=len(rows))
    return {"revoked": len(rows)}


# Update change password while preserving existing validation and audit behavior.
@router.post("/auth/password")
async def change_password(body: PasswordChange, actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    user = await required(db, PatientUser, actor.user_id, lock=True)
    if not verify_password(body.current_password, user.password_hash):
        audit(db, actor.user_id, "portal.password.failure", "patient_auth", actor.user_id)
        raise HTTPException(400, "Current password is incorrect")
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    rows = (await db.scalars(select(PatientSession).where(PatientSession.user_id == actor.user_id, PatientSession.revoked.is_(False)))).all()
    for row in rows:
        row.revoked = True
    audit(db, actor.user_id, "portal.password.change", "patient_auth", actor.user_id)
    return {"changed": True, "sessions_revoked": len(rows)}


# Handle logout for this module.
@router.post("/auth/logout")
async def logout(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    session = await required(db, PatientSession, actor.session_id, lock=True)
    session.revoked = True
    audit(db, actor.user_id, "portal.logout", "patient_auth", actor.user_id)
    return {"revoked": True}


__all__ = ["PasswordChange", "me", "sessions", "revoke_other_sessions", "change_password", "logout", "router"]
