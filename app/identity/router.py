import base64
import secrets
import time
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, text

from app.core.audit import audit
from app.core.config import settings
from app.core.database import control_session, organization_session
from app.core.rate_limit import get_bo_throttle_args
from app.identity.models import (
    AuthChallenge,
    AuthRateLimit,
    PasswordResetChallenge,
    StaffSession,
    StaffUser,
)
from app.identity.passwords import hash_password, verify_password
from app.identity.recovery import revoke_staff_sessions
from app.identity.security import digest, vault, verify_totp
from app.identity.service import Actor, current_actor, db_session, issue_token
from app.organizations.tenant_resolution import organization_from_login

router = APIRouter(prefix="/auth", tags=["Staff identity"])
DUMMY_HASH = hash_password(secrets.token_urlsafe(32))


class Login(BaseModel):
    organization_id: str | None = Field(default=None, min_length=36, max_length=36)
    tenant_slug: str | None = Field(default=None, min_length=3, max_length=80)
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)


class ChallengeInput(BaseModel):
    organization_id: str | None = None
    tenant_slug: str | None = None
    challenge_token: str = Field(min_length=20, max_length=200)


class CodeInput(ChallengeInput):
    code: str = Field(pattern=r"^\d{6}$")


class ProfileUpdate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    photo_url: str = Field(default="", max_length=500)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=128)


class PasswordResetComplete(BaseModel):
    organization_id: str | None = None
    tenant_slug: str | None = None
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=12, max_length=128)



async def throttle(key, limit: int | None = None, seconds: int | None = None):
    defaults = get_bo_throttle_args()
    limit = limit if limit is not None else defaults.limit
    seconds = seconds if seconds is not None else defaults.seconds
    key = digest(key)
    async with control_session() as db:
        await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"), {"key": key})
        row = await db.get(AuthRateLimit, key)
        now = int(time.time())
        if row is None:
            row = AuthRateLimit(key=key, count=0, until=now + seconds)
            db.add(row)
        if row.until <= now:
            row.count = 0
            row.until = now + seconds
        row.count += 1
        allowed = row.count <= limit
    return allowed


async def organization(identifier=None, tenant_slug=None):
    try:
        return await organization_from_login(identifier, tenant_slug)
    except HTTPException as error:
        if error.status_code == 422:
            raise
        raise HTTPException(401, "Invalid credentials") from None


async def challenge_user(db, body):
    challenge = await db.scalar(
        select(AuthChallenge)
        .where(AuthChallenge.token_hash == digest(body.challenge_token))
        .with_for_update()
    )
    if challenge is None or challenge.used or challenge.expires < int(time.time()) or challenge.attempts >= 5:
        raise HTTPException(401, "MFA challenge expired; sign in again")
    user = await db.scalar(select(StaffUser).where(StaffUser.id == challenge.user_id).with_for_update())
    if user is None or not user.active:
        raise HTTPException(401, "Invalid credentials")
    return challenge, user


@router.post("/staff/login")
async def login(body: Login, request: Request):
    address = request.client.host if request.client else "unknown"
    tenant_key = body.tenant_slug or body.organization_id or "missing"
    if not await throttle(f"login:{address}:{tenant_key}:{body.email.lower()}"):
        return JSONResponse(status_code=429, content={"detail": "Too many attempts; wait five minutes"})
    org = await organization(body.organization_id, body.tenant_slug)
    raw = secrets.token_urlsafe(32)
    async with organization_session(org) as db:
        user = await db.scalar(
            select(StaffUser).where(StaffUser.email == body.email.strip().lower()).with_for_update()
        )
        valid = verify_password(body.password, user.password_hash if user else DUMMY_HASH) and bool(
            user and user.active
        )
        audit(
            db,
            user.id if user else "anonymous",
            "auth.password-success" if valid else "auth.failure",
            "staff",
            organization_id=org.id,
        )
        if not valid:
            return JSONResponse(status_code=401, content={"detail": "Invalid credentials"})
        previous = (
            await db.scalars(
                select(AuthChallenge).where(AuthChallenge.user_id == user.id, AuthChallenge.used.is_(False))
            )
        ).all()
        for old in previous:
            old.used = True
        db.add(AuthChallenge(user_id=user.id, token_hash=digest(raw), expires=int(time.time()) + 300))
        enrollment = not user.mfa_enabled
    return {
        "challenge_token": raw,
        "mfa_required": True,
        "enrollment_required": enrollment,
        "expires_in": 300,
        "organization_id": org.id,
        "tenant_slug": org.slug,
    }


@router.post("/mfa/setup")
async def setup(body: ChallengeInput):
    org = await organization(body.organization_id, body.tenant_slug)
    async with organization_session(org) as db:
        challenge, user = await challenge_user(db, body)
        if user.mfa_enabled:
            raise HTTPException(409, "MFA already enrolled")
        secret = (
            vault().open(user.mfa_secret)
            if user.mfa_secret
            else base64.b32encode(secrets.token_bytes(20)).decode()
        )
        user.mfa_secret = vault().seal(secret)
        audit(db, user.id, "mfa.setup", "staff", user.id)
        return {
            "secret": secret,
            "uri": "otpauth://totp/"
            + quote("DHMIS:" + user.email, safe="")
            + "?"
            + urlencode({"secret": secret, "issuer": "DHMIS"}),
            "issuer": "DHMIS",
        }


@router.post("/mfa/verify")
async def verify(body: CodeInput):
    org = await organization(body.organization_id, body.tenant_slug)
    async with organization_session(org) as db:
        challenge, user = await challenge_user(db, body)
        challenge.attempts += 1
        counter = (
            verify_totp(vault().open(user.mfa_secret), body.code, user.mfa_counter)
            if user.mfa_secret
            else None
        )
        if counter is None:
            audit(db, user.id, "mfa.failure", "staff", user.id)
            return JSONResponse(
                status_code=401, content={"detail": "A valid unused authenticator code is required"}
            )
        user.mfa_counter = counter
        user.mfa_enabled = True
        challenge.used = True
        access = await issue_token(db, user, org)
        audit(db, user.id, "auth.success", "staff", user.id)
    return {"access_token": access, "token_type": "bearer", "expires_in": 1800}


@router.post("/logout")
async def logout(db=Depends(db_session), actor: Actor = Depends(current_actor)):
    session = await db.get(StaffSession, actor.session_id)
    session.revoked = True
    audit(db, actor.user_id, "auth.logout", "staff", actor.user_id)
    return {"revoked": True}


@router.get("/me")
async def me(actor: Actor = Depends(current_actor)):
    from app.identity.service import ROLE_PERMISSIONS

    return {
        "id": actor.user_id,
        "name": actor.name,
        "role": actor.role,
        "selected_location_id": actor.selected_location_id,
        "assignments": actor.assignments,
        "organization_id": actor.organization.id,
        "organization_name": actor.organization.name,
        "organization_slug": actor.organization.slug,
        "environment": settings().environment,
        "mfa_enabled": True,
        "permissions": sorted(ROLE_PERMISSIONS.get(actor.role, set())),
        "branding": actor.settings.branding,
        "photo_url": actor.photo_url,
        "local_password": actor.local_password,
    }


@router.put("/profile")
async def update_profile(
    body: ProfileUpdate,
    db=Depends(db_session),
    actor: Actor = Depends(current_actor),
):
    user = await db.get(StaffUser, actor.user_id)
    user.name = body.name
    user.photo_url = body.photo_url
    user.updated_by = actor.user_id
    audit(db, actor.user_id, "profile.update", "staff", user.id)
    return {"name": user.name, "photo_url": user.photo_url}


@router.post("/password/change")
async def change_password(
    body: PasswordChange,
    db=Depends(db_session),
    actor: Actor = Depends(current_actor),
):
    user = await db.get(StaffUser, actor.user_id)
    if user.external_subject is not None:
        raise HTTPException(409, "Password is managed by the configured identity provider")
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(401, "Current password is incorrect")
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    user.updated_by = actor.user_id
    await revoke_staff_sessions(db, user, actor_id=actor.user_id)
    audit(db, actor.user_id, "password.change", "staff", user.id)
    return {"status": "changed", "reauthentication_required": True}


@router.post("/password-reset/complete")
async def complete_password_reset(body: PasswordResetComplete):
    if not await throttle("password-reset:" + digest(body.token)):
        raise HTTPException(429, "Try again later")
    org = await organization(body.organization_id, body.tenant_slug)
    async with organization_session(org) as db:
        challenge = await db.scalar(
            select(PasswordResetChallenge)
            .where(PasswordResetChallenge.token_hash == digest(body.token))
            .with_for_update()
        )
        if (
            challenge is None
            or challenge.used
            or challenge.expires <= int(time.time())
        ):
            raise HTTPException(401, "Password reset token is invalid or expired")
        user = await db.get(StaffUser, challenge.user_id)
        if user is None or not user.active or user.external_subject is not None:
            raise HTTPException(401, "Password reset token is invalid or expired")
        user.password_hash = hash_password(body.new_password)
        user.token_version += 1
        user.updated_by = user.id
        challenge.used = True
        challenge.updated_by = user.id
        await revoke_staff_sessions(db, user, actor_id=user.id)
        audit(db, user.id, "password-reset.complete", "staff", user.id)
    return {"status": "changed"}
