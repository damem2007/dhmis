"""Patient portal authentication and verification routes."""

import secrets
import string
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.audit import audit
from app.core.database import organization_session
from app.core.rate_limit import get_pt_throttle_args
from app.core.repository import add
from app.identity.passwords import hash_password, verify_password
from app.identity.router import DUMMY_HASH, throttle
from app.identity.security import digest
from app.notifications.models import OutboxMessage
from app.organizations.tenant_resolution import organization_from_login, resolve_organization
from app.patient_identity.models import PatientInvite, PatientUser, PatientVerificationChallenge
from app.patient_identity.service import issue_patient_token
from app.patients.models import Patient
from app.scheduling.models import Appointment

router = APIRouter()


# Defines the accept invite model, contract, or value object.
class AcceptInvite(BaseModel):
    organization_id: str | None = None
    tenant_slug: str | None = None
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=12, max_length=128)


# Defines the login model, contract, or value object.
class Login(BaseModel):
    organization_id: str | None = None
    tenant_slug: str | None = None
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)


# Defines the verification request model, contract, or value object.
class VerificationRequest(BaseModel):
    tenant_slug: str = Field(min_length=3, max_length=80)
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    appointment_reference: str | None = Field(default=None, min_length=8, max_length=80)


# Defines the verification code model, contract, or value object.
class VerificationCode(BaseModel):
    tenant_slug: str = Field(min_length=3, max_length=80)
    challenge_token: str = Field(min_length=20, max_length=200)
    code: str = Field(pattern=r"^\d{6}$")


for _model in (AcceptInvite, Login, VerificationRequest, VerificationCode):
    _model.__module__ = "app.patient_identity.router"


# Handle accept invite for this module.
@router.post("/auth/accept")
async def accept_invite(body: AcceptInvite):
    if not await throttle("patient-invite:" + digest(body.token)):
        raise HTTPException(429, "Try again later")
    organization = await organization_from_login(body.organization_id, body.tenant_slug)
    if not organization.patient_portal_enabled:
        raise HTTPException(404, "Client Portal is not enabled")
    async with organization_session(organization) as db:
        invitation = await db.scalar(select(PatientInvite).where(PatientInvite.token_hash == digest(body.token)).with_for_update())
        if invitation is None or invitation.used or invitation.expires < int(time.time()):
            raise HTTPException(401, "Invalid invitation")
        if await db.scalar(select(PatientUser).where(PatientUser.patient_id == invitation.patient_id)):
            raise HTTPException(409, "Client Portal account already exists")
        user = await add(db, PatientUser, {"patient_id": invitation.patient_id, "email": invitation.email, "password_hash": hash_password(body.password)}, "patient-invitation")
        invitation.used = True
        audit(db, user.id, "portal.accept", "patients", user.patient_id)
    return {"status": "created"}


# Handle login for this module.
@router.post("/auth/login")
async def login(body: Login, request: Request):
    address = request.client.host if request.client else "unknown"
    limits = get_pt_throttle_args()
    tenant_key = body.tenant_slug or body.organization_id or "missing"
    if not await throttle(f"patient-login:{address}:{tenant_key}:{body.email.lower()}", limits.limit, limits.seconds):
        return JSONResponse(status_code=429, content={"detail": "Too many attempts; wait five minutes"})
    try:
        organization = await organization_from_login(body.organization_id, body.tenant_slug)
        if not organization.patient_portal_enabled:
            raise HTTPException(404, "Client Portal is not enabled")
    except HTTPException:
        verify_password(body.password, DUMMY_HASH)
        raise HTTPException(401, "Invalid credentials")
    async with organization_session(organization) as db:
        user = await db.scalar(select(PatientUser).where(PatientUser.email == body.email.lower()))
        valid = verify_password(body.password, user.password_hash if user else DUMMY_HASH) and bool(user and user.active)
        audit(db, user.id if user else "anonymous", "portal.login" if valid else "portal.failure", "patient_auth")
        if not valid:
            raise HTTPException(401, "Invalid credentials")
        token = await issue_patient_token(db, user, organization)
    return {"access_token": token, "token_type": "bearer", "expires_in": 3600}


# Create or issue request verification while applying existing validation and authorization.
@router.post("/auth/verification/request", status_code=202)
async def request_verification(body: VerificationRequest, request: Request):
    raw = secrets.token_urlsafe(32)
    generic = {"status": "verification_requested", "challenge_token": raw}
    limits = get_pt_throttle_args()
    address = request.client.host if request.client else "unknown"
    if not await throttle(f"patient-verification:{address}:{body.tenant_slug}:{body.email.lower()}", limits.limit, limits.seconds):
        return generic
    try:
        resolution = await resolve_organization(slug=body.tenant_slug, surface="portal")
    except HTTPException:
        return generic
    organization = resolution.organization
    code = "".join(secrets.choice(string.digits) for _ in range(6))
    now = int(time.time())
    async with organization_session(organization) as db:
        user = await db.scalar(select(PatientUser).where(PatientUser.email == body.email.lower(), PatientUser.active))
        patient = await db.get(Patient, user.patient_id) if user else None
        appointment = None
        if body.appointment_reference:
            appointment = await db.scalar(select(Appointment).where(Appointment.id == body.appointment_reference, Appointment.status.in_(["confirmed", "checked-in"])))
            candidate = await db.get(Patient, appointment.patient_id) if appointment else None
            patient = candidate if candidate and candidate.email.lower() == body.email.lower() else None
        if patient is None:
            audit(db, "anonymous", "portal.verification.request", "patient_auth", matched=False)
            return generic
        old = (await db.scalars(select(PatientVerificationChallenge).where(PatientVerificationChallenge.patient_id == patient.id, PatientVerificationChallenge.used.is_(False)))).all()
        for challenge in old:
            challenge.used = True
        challenge = await add(db, PatientVerificationChallenge, {"patient_id": patient.id, "appointment_id": appointment.id if appointment else None, "email": body.email.lower(), "token_hash": digest(raw), "code_hash": digest(code), "expires": now + 600, "resend_after": now + 60}, "patient-verification")
        db.add(OutboxMessage(kind="patient.verification", payload={"patient_id": patient.id, "destination": body.email.lower(), "body": f"Your DHMIS Client Portal verification code is {code}. It expires in 10 minutes."}, idempotency_key=f"patient-verification:{challenge.id}", due_at=datetime.now(timezone.utc), created_by="patient-verification", updated_by="patient-verification"))
        audit(db, "anonymous", "portal.verification.request", "patient_auth", patient_id=patient.id, matched=True)
    return {**generic, "challenge_token": raw}


# Handle verify code for this module.
@router.post("/auth/verification/verify")
async def verify_code(body: VerificationCode):
    resolution = await resolve_organization(slug=body.tenant_slug, surface="portal")
    organization = resolution.organization
    async with organization_session(organization) as db:
        challenge = await db.scalar(select(PatientVerificationChallenge).where(PatientVerificationChallenge.token_hash == digest(body.challenge_token)).with_for_update())
        now = int(time.time())
        if challenge is None or challenge.used or challenge.expires <= now or challenge.attempts >= 5:
            raise HTTPException(401, "Verification challenge is invalid or expired")
        challenge.attempts += 1
        if not secrets.compare_digest(challenge.code_hash, digest(body.code)):
            audit(db, "anonymous", "portal.verification.failure", "patient_auth")
            raise HTTPException(401, "Verification challenge is invalid or expired")
        user = await db.scalar(select(PatientUser).where(PatientUser.patient_id == challenge.patient_id).with_for_update())
        if user is None:
            user = await add(db, PatientUser, {"patient_id": challenge.patient_id, "email": challenge.email, "password_hash": hash_password(secrets.token_urlsafe(48))}, "patient-verification")
        elif not user.active:
            raise HTTPException(401, "Verification challenge is invalid or expired")
        challenge.used = True
        token = await issue_patient_token(db, user, organization, "otp")
        audit(db, user.id, "portal.verification.success", "patient_auth", patient_id=user.patient_id)
    return {"access_token": token, "token_type": "bearer", "expires_in": 3600}


__all__ = ["AcceptInvite", "Login", "VerificationRequest", "VerificationCode", "accept_invite", "login", "request_verification", "verify_code", "router"]
