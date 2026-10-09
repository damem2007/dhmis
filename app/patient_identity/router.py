import secrets
import string
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from app.core.audit import audit
from app.core.database import organization_session
from app.core.rate_limit import get_pt_throttle_args
from app.core.repository import add, required
from app.identity.passwords import hash_password, verify_password
from app.identity.router import DUMMY_HASH, throttle
from app.identity.security import digest
from app.identity.service import db_session, permit
from app.notifications.models import OutboxMessage
from app.notifications.service import deliver_message_now
from app.organizations.tenant_resolution import organization_from_login, resolve_organization
from app.patient_identity.models import (
    PatientInvite,
    PatientSession,
    PatientUser,
    PatientVerificationChallenge,
)
from app.patient_identity.service import (
    PatientActor,
    current_patient,
    issue_patient_token,
    patient_db_session,
)
from app.patients.models import Patient
from app.scheduling.models import Appointment

router = APIRouter(prefix="/portal", tags=["Patient identity"])


class InviteInput(BaseModel):
    patient_id: str
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)


class AcceptInvite(BaseModel):
    organization_id: str | None = None
    tenant_slug: str | None = None
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=12, max_length=128)


class Login(BaseModel):
    organization_id: str | None = None
    tenant_slug: str | None = None
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)


class VerificationRequest(BaseModel):
    tenant_slug: str = Field(min_length=3, max_length=80)
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    appointment_reference: str | None = Field(default=None, min_length=8, max_length=80)


class VerificationCode(BaseModel):
    tenant_slug: str = Field(min_length=3, max_length=80)
    challenge_token: str = Field(min_length=20, max_length=200)
    code: str = Field(pattern=r"^\d{6}$")


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=128)


@router.post("/invites", status_code=201)
async def create_invite(body: InviteInput, db=Depends(db_session), actor=Depends(permit("patients"))):
    patient = await required(db, Patient, body.patient_id)
    if await db.scalar(select(PatientUser).where(PatientUser.patient_id == patient.id)):
        raise HTTPException(409, "Client Portal account already exists")
    raw = secrets.token_urlsafe(32)
    existing = (
        await db.scalars(
            select(PatientInvite).where(
                PatientInvite.patient_id == patient.id, PatientInvite.used.is_(False)
            )
        )
    ).all()
    for invitation in existing:
        invitation.used = True
    record = await add(
        db,
        PatientInvite,
        {
            "patient_id": patient.id,
            "email": body.email.lower(),
            "token_hash": digest(raw),
            "expires": int(time.time()) + 86400,
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "portal.invite", "patients", patient.id)
    return {"invite_id": record.id, "token": raw, "organization_id": actor.organization.id}


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
    await deliver_message_now(db, actor, OutboxMessage(
            kind="patient.invitation",
            payload={
                "destination": replacement.email,
                "body": f"Use this one-time Client Portal invitation token within 24 hours: {raw}",
            },
            idempotency_key=f"patient-invitation:{replacement.id}",
            created_by=actor.user_id,
            updated_by=actor.user_id,
        ))
    audit(db, actor.user_id, "portal.invite.resend", "patients", invitation.patient_id)
    return {"invite_id": replacement.id, "token": raw, "expires": replacement.expires}


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


@router.post("/auth/accept")
async def accept_invite(body: AcceptInvite):
    if not await throttle("patient-invite:" + digest(body.token)):
        raise HTTPException(429, "Try again later")
    organization = await organization_from_login(body.organization_id, body.tenant_slug)
    if not organization.patient_portal_enabled:
        raise HTTPException(404, "Client Portal is not enabled")
    async with organization_session(organization) as db:
        invitation = await db.scalar(
            select(PatientInvite).where(PatientInvite.token_hash == digest(body.token)).with_for_update()
        )
        if invitation is None or invitation.used or invitation.expires < int(time.time()):
            raise HTTPException(401, "Invalid invitation")
        if await db.scalar(select(PatientUser).where(PatientUser.patient_id == invitation.patient_id)):
            raise HTTPException(409, "Client Portal account already exists")
        user = await add(
            db,
            PatientUser,
            {
                "patient_id": invitation.patient_id,
                "email": invitation.email,
                "password_hash": hash_password(body.password),
            },
            "patient-invitation",
        )
        invitation.used = True
        audit(db, user.id, "portal.accept", "patients", user.patient_id)
    return {"status": "created"}


@router.post("/auth/login")
async def login(body: Login, request: Request):
    address = request.client.host if request.client else "unknown"
    limits = get_pt_throttle_args()
    tenant_key = body.tenant_slug or body.organization_id or "missing"
    if not await throttle(
        f"patient-login:{address}:{tenant_key}:{body.email.lower()}",
        limits.limit,
        limits.seconds,
    ):
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
        valid = verify_password(body.password, user.password_hash if user else DUMMY_HASH) and bool(
            user and user.active
        )
        audit(db, user.id if user else "anonymous", "portal.login" if valid else "portal.failure", "patient_auth")
        if not valid:
            raise HTTPException(401, "Invalid credentials")
        token = await issue_patient_token(db, user, organization)
    return {"access_token": token, "token_type": "bearer", "expires_in": 3600}


@router.post("/auth/verification/request", status_code=202)
async def request_verification(body: VerificationRequest, request: Request):
    raw = secrets.token_urlsafe(32)
    generic = {"status": "verification_requested", "challenge_token": raw}
    limits = get_pt_throttle_args()
    address = request.client.host if request.client else "unknown"
    if not await throttle(
        f"patient-verification:{address}:{body.tenant_slug}:{body.email.lower()}",
        limits.limit,
        limits.seconds,
    ):
        return generic
    try:
        resolution = await resolve_organization(slug=body.tenant_slug, surface="portal")
    except HTTPException:
        return generic
    organization = resolution.organization
    code = "".join(secrets.choice(string.digits) for _ in range(6))
    now = int(time.time())
    async with organization_session(organization) as db:
        user = await db.scalar(
            select(PatientUser).where(PatientUser.email == body.email.lower(), PatientUser.active)
        )
        patient = await db.get(Patient, user.patient_id) if user else None
        appointment = None
        if body.appointment_reference:
            appointment = await db.scalar(
                select(Appointment).where(
                    Appointment.id == body.appointment_reference,
                    Appointment.status.in_(["confirmed", "checked-in"]),
                )
            )
            candidate = await db.get(Patient, appointment.patient_id) if appointment else None
            if candidate and candidate.email.lower() == body.email.lower():
                patient = candidate
            else:
                patient = None
        if patient is None:
            audit(db, "anonymous", "portal.verification.request", "patient_auth", matched=False)
            return generic
        old = (
            await db.scalars(
                select(PatientVerificationChallenge).where(
                    PatientVerificationChallenge.patient_id == patient.id,
                    PatientVerificationChallenge.used.is_(False),
                )
            )
        ).all()
        for challenge in old:
            challenge.used = True
        challenge = await add(
            db,
            PatientVerificationChallenge,
            {
                "patient_id": patient.id,
                "appointment_id": appointment.id if appointment else None,
                "email": body.email.lower(),
                "token_hash": digest(raw),
                "code_hash": digest(code),
                "expires": now + 600,
                "resend_after": now + 60,
            },
            "patient-verification",
        )
        db.add(OutboxMessage(
                kind="patient.verification",
                payload={
                    "patient_id": patient.id,
                    "destination": body.email.lower(),
                    "body": f"Your DHMIS Client Portal verification code is {code}. It expires in 10 minutes.",
                },
                idempotency_key=f"patient-verification:{challenge.id}",
                due_at=datetime.now(timezone.utc),
                created_by="patient-verification",
                updated_by="patient-verification",
            ))
        audit(db, "anonymous", "portal.verification.request", "patient_auth", patient_id=patient.id, matched=True)
    return {**generic, "challenge_token": raw}


@router.post("/auth/verification/verify")
async def verify_code(body: VerificationCode):
    resolution = await resolve_organization(slug=body.tenant_slug, surface="portal")
    organization = resolution.organization
    async with organization_session(organization) as db:
        challenge = await db.scalar(
            select(PatientVerificationChallenge)
            .where(PatientVerificationChallenge.token_hash == digest(body.challenge_token))
            .with_for_update()
        )
        now = int(time.time())
        if (
            challenge is None
            or challenge.used
            or challenge.expires <= now
            or challenge.attempts >= 5
        ):
            raise HTTPException(401, "Verification challenge is invalid or expired")
        challenge.attempts += 1
        if not secrets.compare_digest(challenge.code_hash, digest(body.code)):
            audit(db, "anonymous", "portal.verification.failure", "patient_auth")
            raise HTTPException(401, "Verification challenge is invalid or expired")
        user = await db.scalar(
            select(PatientUser).where(PatientUser.patient_id == challenge.patient_id).with_for_update()
        )
        if user is None:
            user = await add(
                db,
                PatientUser,
                {
                    "patient_id": challenge.patient_id,
                    "email": challenge.email,
                    "password_hash": hash_password(secrets.token_urlsafe(48)),
                },
                "patient-verification",
            )
        elif not user.active:
            raise HTTPException(401, "Verification challenge is invalid or expired")
        challenge.used = True
        token = await issue_patient_token(db, user, organization, "otp")
        audit(db, user.id, "portal.verification.success", "patient_auth", patient_id=user.patient_id)
    return {"access_token": token, "token_type": "bearer", "expires_in": 3600}


@router.get("/me")
async def me(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    patient = await required(db, Patient, actor.patient_id)
    audit(db, actor.user_id, "portal.read", "patients", patient.id)
    return {
        "id": actor.user_id,
        "patient_id": patient.id,
        "organization_id": actor.organization.id,
        "organization_name": actor.organization.name,
        "organization_slug": actor.organization.slug,
        "name": f"{patient.first_name} {patient.last_name}",
        "email": (await required(db, PatientUser, actor.user_id)).email,
        "branding": actor.settings.branding,
    }


@router.get("/auth/sessions")
async def sessions(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    rows = (
        await db.scalars(
            select(PatientSession)
            .where(PatientSession.user_id == actor.user_id, PatientSession.revoked.is_(False))
            .order_by(PatientSession.last_active.desc())
        )
    ).all()
    audit(db, actor.user_id, "portal.sessions.read", "patient_auth", actor.user_id)
    return [
        {
            "id": row.id,
            "current": row.id == actor.session_id,
            "last_active": row.last_active,
            "expires": row.expires,
        }
        for row in rows
    ]


@router.post("/auth/sessions/revoke-others")
async def revoke_other_sessions(
    actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)
):
    rows = (
        await db.scalars(
            select(PatientSession).where(
                PatientSession.user_id == actor.user_id,
                PatientSession.id != actor.session_id,
                PatientSession.revoked.is_(False),
            )
        )
    ).all()
    for row in rows:
        row.revoked = True
    audit(
        db,
        actor.user_id,
        "portal.sessions.revoke_others",
        "patient_auth",
        actor.user_id,
        revoked_count=len(rows),
    )
    return {"revoked": len(rows)}


@router.post("/auth/password")
async def change_password(
    body: PasswordChange,
    actor: PatientActor = Depends(current_patient),
    db=Depends(patient_db_session),
):
    user = await required(db, PatientUser, actor.user_id, lock=True)
    if not verify_password(body.current_password, user.password_hash):
        audit(db, actor.user_id, "portal.password.failure", "patient_auth", actor.user_id)
        raise HTTPException(400, "Current password is incorrect")
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    rows = (
        await db.scalars(
            select(PatientSession).where(
                PatientSession.user_id == actor.user_id,
                PatientSession.revoked.is_(False),
            )
        )
    ).all()
    for row in rows:
        row.revoked = True
    audit(db, actor.user_id, "portal.password.change", "patient_auth", actor.user_id)
    return {"changed": True, "sessions_revoked": len(rows)}


@router.post("/auth/logout")
async def logout(actor: PatientActor = Depends(current_patient), db=Depends(patient_db_session)):
    session = await required(db, PatientSession, actor.session_id, lock=True)
    session.revoked = True
    audit(db, actor.user_id, "portal.logout", "patient_auth", actor.user_id)
    return {"revoked": True}
