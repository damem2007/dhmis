import base64
import hmac
import secrets
import time
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app.core.config import settings
from app.core.database import control_session
from app.core.rate_limit import get_bo_throttle_args
from app.identity.passwords import hash_password, verify_password
from app.identity.router import DUMMY_HASH, throttle
from app.identity.security import digest, vault, verify_totp
from app.platform_identity.models import (
    PlatformChallenge,
    PlatformInvite,
    PlatformPasswordResetChallenge,
    PlatformSession,
    PlatformUser,
)
from app.platform_identity.service import (
    PlatformActor,
    current_platform,
    platform_or_bootstrap,
    issue_platform_token,
    platform_audit,
)
from app.rbac.bootstrap import seed_platform_super_admin

router = APIRouter(prefix="/platform/auth", tags=["Platform identity"])


class BootstrapInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    password: str = Field(min_length=12, max_length=128)


class LoginInput(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)


class ChallengeInput(BaseModel):
    challenge_token: str = Field(min_length=20, max_length=200)


class VerifyInput(ChallengeInput):
    code: str = Field(pattern=r"^\d{6}$")


class AcceptPlatformInvite(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=12, max_length=128)


class CompletePlatformPasswordReset(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=12, max_length=128)


class ProfileUpdate(BaseModel):
    name: str = Field(min_length=2, max_length=160)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=128)


class MfaResetInput(BaseModel):
    password: str = Field(min_length=1, max_length=256)


async def challenge_user(db, raw):
    challenge = await db.scalar(
        select(PlatformChallenge)
        .where(PlatformChallenge.token_hash == digest(raw))
        .with_for_update()
    )
    if challenge is None or challenge.used or challenge.expires < int(time.time()) or challenge.attempts >= 5:
        raise HTTPException(401, "Platform challenge expired; sign in again")
    user = await db.get(PlatformUser, challenge.user_id)
    if user is None or not user.active:
        raise HTTPException(401, "Invalid credentials")
    return challenge, user


@router.post("/bootstrap", status_code=201)
async def bootstrap(body: BootstrapInput, x_bootstrap_key: str = Header(default="")):
    #print(f"Bootstrap request received: {body}")
    if not hmac.compare_digest(x_bootstrap_key, settings().bootstrap_key.get_secret_value()):
        raise HTTPException(403, "Platform bootstrap key required")
    async with control_session() as db:
        if await db.scalar(select(PlatformUser)):
            raise HTTPException(409, "Platform identity is already bootstrapped")
        user = PlatformUser(
            name=body.name,
            email=body.email.lower(),
            password_hash=hash_password(body.password),
            created_by="bootstrap",
            updated_by="bootstrap",
        )
        db.add(user)
        await db.flush()
        platform_audit(db, user.id, "platform.bootstrap")
    return {"status": "created"}


@router.post("/login")
async def login(body: LoginInput, request: Request):
    limits = get_bo_throttle_args()
    address = request.client.host if request.client else "unknown"
    if not await throttle(
        f"platform-login:{address}:{body.email.lower()}", limits.limit, limits.seconds
    ):
        return JSONResponse(status_code=429, content={"detail": "Too many attempts; wait five minutes"})
    raw = secrets.token_urlsafe(32)
    async with control_session() as db:
        user = await db.scalar(
            select(PlatformUser).where(PlatformUser.email == body.email.lower()).with_for_update()
        )
        valid = verify_password(body.password, user.password_hash if user else DUMMY_HASH) and bool(
            user and user.active
        )
        platform_audit(db, user.id if user else "anonymous", "platform.password-success" if valid else "platform.failure")
        if not valid:
            raise HTTPException(401, "Invalid credentials")
        old = (
            await db.scalars(
                select(PlatformChallenge).where(
                    PlatformChallenge.user_id == user.id, PlatformChallenge.used.is_(False)
                )
            )
        ).all()
        for challenge in old:
            challenge.used = True
        db.add(PlatformChallenge(user_id=user.id, token_hash=digest(raw), expires=int(time.time()) + 300))
        enrollment = not user.mfa_enabled
    return {"challenge_token": raw, "enrollment_required": enrollment, "expires_in": 300}


@router.post("/invites/accept", status_code=201)
async def accept_platform_invite(body: AcceptPlatformInvite):
    async with control_session() as db:
        invitation = await db.scalar(
            select(PlatformInvite)
            .where(PlatformInvite.token_hash == digest(body.token))
            .with_for_update()
        )
        if invitation is None or invitation.status != "pending" or invitation.expires <= int(time.time()):
            raise HTTPException(401, "Invalid or expired platform invitation")
        if await db.scalar(select(PlatformUser).where(PlatformUser.email == invitation.email)):
            raise HTTPException(409, "Platform user already exists")
        user = PlatformUser(
            name=invitation.name,
            email=invitation.email,
            role=invitation.role,
            password_hash=hash_password(body.password),
            created_by="platform-invitation",
            updated_by="platform-invitation",
        )
        db.add(user)
        await db.flush()
        await seed_platform_super_admin(db, user.id)
        invitation.status = "accepted"
        invitation.updated_by = user.id
        platform_audit(db, user.id, "platform-invite.accept", details={"invite_id": invitation.id})
        return {"status": "created"}


@router.post("/password-reset/complete")
async def complete_platform_password_reset(body: CompletePlatformPasswordReset, request: Request):
    address = request.client.host if request.client else "unknown"
    if not await throttle(f"platform-reset:{address}:{digest(body.token)}", 10, 300):
        return JSONResponse(status_code=429, content={"detail": "Too many attempts; wait five minutes"})
    async with control_session() as db:
        challenge = await db.scalar(
            select(PlatformPasswordResetChallenge)
            .where(PlatformPasswordResetChallenge.token_hash == digest(body.token))
            .with_for_update()
        )
        if challenge is None or challenge.used or challenge.expires <= int(time.time()):
            raise HTTPException(401, "Invalid or expired platform password-reset link")
        user = await db.get(PlatformUser, challenge.user_id)
        if user is None or not user.active:
            raise HTTPException(401, "Invalid or expired platform password-reset link")
        challenge.used = True
        challenge.updated_by = user.id
        user.password_hash = hash_password(body.password)
        user.token_version += 1
        user.updated_by = user.id
        await db.execute(
            update(PlatformSession)
            .where(PlatformSession.user_id == user.id, PlatformSession.revoked.is_(False))
            .values(revoked=True, updated_by=user.id)
        )
        platform_audit(
            db,
            user.id,
            "platform-user.password-reset.complete",
            details={"challenge_id": challenge.id},
        )
    return {"status": "password-updated"}


@router.post("/mfa/setup")
async def setup(body: ChallengeInput):
    async with control_session() as db:
        _, user = await challenge_user(db, body.challenge_token)
        if user.mfa_enabled:
            raise HTTPException(409, "MFA already enrolled")
        secret = vault().open(user.mfa_secret) if user.mfa_secret else base64.b32encode(secrets.token_bytes(20)).decode()
        user.mfa_secret = vault().seal(secret)
        platform_audit(db, user.id, "platform.mfa.setup")
        return {
            "secret": secret,
            "uri": "otpauth://totp/" + quote("DHMIS Platform:" + user.email, safe="") + "?" + urlencode({"secret": secret, "issuer": "DHMIS Platform"}),
        }


@router.post("/mfa/verify")
async def verify(body: VerifyInput):
    async with control_session() as db:
        challenge, user = await challenge_user(db, body.challenge_token)
        challenge.attempts += 1
        counter = verify_totp(vault().open(user.mfa_secret), body.code, user.mfa_counter) if user.mfa_secret else None
        if counter is None:
            platform_audit(db, user.id, "platform.mfa.failure")
            raise HTTPException(401, "A valid unused authenticator code is required")
        user.mfa_counter = counter
        user.mfa_enabled = True
        challenge.used = True
        access = await issue_platform_token(db, user)
        platform_audit(db, user.id, "platform.auth.success")
    return {"access_token": access, "token_type": "bearer", "expires_in": 1800}


@router.get("/me")
async def me(actor: PlatformActor = Depends(current_platform)):
    async with control_session() as db:
        user = await db.get(PlatformUser, actor.user_id)
        if user is None:
            raise HTTPException(404, "Platform profile not found")
        return {"id": user.id, "name": user.name, "email": user.email, "role": user.role, "mfa_enabled": user.mfa_enabled}


@router.put("/me")
async def update_me(body: ProfileUpdate, actor: PlatformActor = Depends(current_platform)):
    async with control_session() as db:
        user = await db.get(PlatformUser, actor.user_id)
        if user is None:
            raise HTTPException(404, "Platform profile not found")
        user.name = body.name.strip()
        user.updated_by = actor.user_id
        platform_audit(db, actor.user_id, "platform.profile.update")
        return {"id": user.id, "name": user.name, "email": user.email, "role": user.role, "mfa_enabled": user.mfa_enabled}


@router.post("/password/change")
async def change_password(body: PasswordChange, actor: PlatformActor = Depends(current_platform)):
    async with control_session() as db:
        user = await db.get(PlatformUser, actor.user_id)
        if user is None or not verify_password(body.current_password, user.password_hash):
            raise HTTPException(400, "Current password is incorrect")
        user.password_hash = hash_password(body.new_password)
        user.token_version += 1
        user.updated_by = actor.user_id
        await db.execute(update(PlatformSession).where(PlatformSession.user_id == user.id, PlatformSession.revoked.is_(False)).values(revoked=True, updated_by=actor.user_id))
        platform_audit(db, actor.user_id, "platform.password.change")
    return {"status": "password-updated"}


@router.post("/mfa/reset")
async def reset_mfa(body: MfaResetInput, actor: PlatformActor = Depends(current_platform)):
    async with control_session() as db:
        user = await db.get(PlatformUser, actor.user_id)
        if user is None or not verify_password(body.password, user.password_hash):
            raise HTTPException(400, "Password is incorrect")
        user.mfa_enabled = False
        user.mfa_secret = ""
        user.mfa_counter = -1
        user.token_version += 1
        user.updated_by = actor.user_id
        await db.execute(update(PlatformSession).where(PlatformSession.user_id == user.id, PlatformSession.revoked.is_(False)).values(revoked=True, updated_by=actor.user_id))
        platform_audit(db, actor.user_id, "platform.mfa.reset")
    return {"status": "mfa-reset"}


@router.post("/logout")
async def logout(actor: PlatformActor = Depends(current_platform)):
    async with control_session() as db:
        session = await db.get(PlatformSession, actor.session_id)
        session.revoked = True
        platform_audit(db, actor.user_id, "platform.logout")
    return {"revoked": True}
