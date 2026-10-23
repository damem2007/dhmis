import base64
import hmac
import secrets
import time
from datetime import UTC, datetime
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app.core.config import settings
from app.core.database import control_session
from app.core.rate_limit import get_bo_throttle_args
from app.identity.passwords import hash_password, verify_password
from app.identity.password_policy import (
    effective_password_policy,
    password_expired,
    password_expiry_at,
    password_expiry_days_remaining,
    validate_password,
)
from app.identity.router import DUMMY_HASH, throttle
from app.identity.security import digest, vault, verify_totp
from app.platform_identity.models import (
    PlatformChallenge,
    PlatformInvite,
    PlatformOutboxMessage,
    PlatformPasswordResetChallenge,
    PlatformSession,
    PlatformUser,
)
from app.platform_identity.service import (
    PlatformActor,
    current_platform,
    is_bootstrap_platform_user,
    platform_or_bootstrap,
    issue_platform_token,
    platform_audit,
)
from app.platform_identity.delivery import enqueue_platform_email
from app.organizations.configuration import platform_configuration
from app.rbac.bootstrap import seed_platform_super_admin
from app.rbac.models import PlatformRole, PlatformRoleAssignment
from app.rbac.policy import Domain, decide
from app.rbac.runtime import approved_permissions, platform_assignments, platform_policy_context

router = APIRouter(prefix="/platform/auth", tags=["Platform identity"])


# Defines the bootstrap input model, contract, or value object.
class BootstrapInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    password: str = Field(min_length=1, max_length=128)


# Defines the login input model, contract, or value object.
class LoginInput(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)


# Defines the challenge input model, contract, or value object.
class ChallengeInput(BaseModel):
    challenge_token: str = Field(min_length=20, max_length=200)


# Defines the verify input model, contract, or value object.
class VerifyInput(ChallengeInput):
    code: str = Field(pattern=r"^\d{6}$")


# Defines the accept platform invite model, contract, or value object.
class AcceptPlatformInvite(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=1, max_length=128)


# Defines the complete platform password reset model, contract, or value object.
class CompletePlatformPasswordReset(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=1, max_length=128)
    password_confirmation: str = Field(min_length=1, max_length=128)
    code: str = Field(pattern=r"^\d{6}$")


# Defines the profile update model, contract, or value object.
class ProfileUpdate(BaseModel):
    name: str = Field(min_length=2, max_length=160)


# Defines the password change model, contract, or value object.
class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=128)


# Defines the mfa reset input model, contract, or value object.
class MfaResetInput(BaseModel):
    password: str = Field(min_length=1, max_length=256)


async def platform_permission_keys(db, user_id: str) -> list[str]:
    """Return effective platform grants for the authenticated profile.

    The platform UI uses this only to present a truthful read-only state. The
    API permission dependencies remain authoritative for every mutation.
    """
    context = await platform_policy_context(db)
    assignments = await platform_assignments(db, user_id)
    return sorted(
        key
        for key in approved_permissions(Domain.PLATFORM).keys()
        if decide(key, assignments, context).allowed
    )


# Handle challenge user for this module.
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


async def issue_expired_password_reset(db, user) -> tuple[PlatformPasswordResetChallenge, PlatformOutboxMessage]:
    """Create and deliver the reset link used by expired-password recovery."""
    raw = secrets.token_urlsafe(32)
    now = int(time.time())
    previous = (
        await db.scalars(
            select(PlatformPasswordResetChallenge).where(
                PlatformPasswordResetChallenge.user_id == user.id,
                PlatformPasswordResetChallenge.used.is_(False),
            )
        )
    ).all()
    for challenge in previous:
        challenge.used = True
        challenge.updated_by = user.id
    challenge = PlatformPasswordResetChallenge(
        user_id=user.id,
        token_hash=digest(raw),
        expires=now + 3600,
        initiated_by="expired-password-self-service",
        reason="Expired password self-service recovery",
        created_by=user.id,
        updated_by=user.id,
    )
    db.add(challenge)
    await db.flush()
    delivery = await enqueue_platform_email(
        db,
        kind="platform.password-reset",
        destination=user.email,
        recipient_name=user.name,
        raw_token=raw,
        reference_id=challenge.id,
        actor_id=user.id,
    )
    platform_audit(
        db,
        user.id,
        "platform.password-reset.expired.request",
        details={"challenge_id": challenge.id, "delivery_id": delivery.id},
    )
    return challenge, delivery


# Handle bootstrap for this module.
@router.post("/bootstrap", status_code=201)
async def bootstrap(body: BootstrapInput, x_bootstrap_key: str = Header(default="")):
    #print(f"Bootstrap request received: {body}")
    if not hmac.compare_digest(x_bootstrap_key, settings().bootstrap_key.get_secret_value()):
        raise HTTPException(403, "Platform bootstrap key required")
    async with control_session() as db:
        if await db.scalar(select(PlatformUser)):
            raise HTTPException(409, "Platform identity is already bootstrapped")
        policy = effective_password_policy((await platform_configuration(db)).password_policy)
        password_error = validate_password(body.password, policy)
        if password_error:
            raise HTTPException(422, password_error)
        user = PlatformUser(
            name=body.name,
            email=body.email.lower(),
            password_hash=hash_password(body.password),
            password_changed_at=datetime.now(UTC),
            created_by="bootstrap",
            updated_by="bootstrap",
        )
        db.add(user)
        await db.flush()
        # The first platform identity is the control-plane bootstrap operator.
        # Give it the canonical locked role so RBAC, effective-access views,
        # and maker-checker eligibility all use the same source of truth.
        role = await seed_platform_super_admin(db, user.id)
        user.role_id = role.id
        platform_audit(db, user.id, "platform.bootstrap")
    return {"status": "created"}


# Handle login for this module.
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
        policy = effective_password_policy((await platform_configuration(db)).password_policy)
        if password_expired(user.password_changed_at, policy):
            if user.mfa_enabled and user.mfa_secret:
                _, delivery = await issue_expired_password_reset(db, user)
                if delivery.status not in {"simulated", "sent", "delivered", "accepted"}:
                    return JSONResponse(
                        status_code=502,
                        content={"detail": {"code": "password_reset_delivery_failed", "message": "We could not deliver the password reset email. Please try again later."}},
                    )
            return JSONResponse(
                status_code=403,
                content={"detail": {"code": "password_expired", "message": "A reset link has been sent to your registered email address.", "reset_available": bool(user.mfa_enabled and user.mfa_secret)}},
            )
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


# Handle accept platform invite for this module.
@router.post("/invites/accept", status_code=201)
async def accept_platform_invite(body: AcceptPlatformInvite):
    async with control_session() as db:
        policy = effective_password_policy((await platform_configuration(db)).password_policy)
        password_error = validate_password(body.password, policy)
        if password_error:
            raise HTTPException(422, password_error)
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
            # The legacy field remains a compatibility marker. Canonical
            # platform access is stored in PlatformRoleAssignment below.
            role="platform_admin",
            password_hash=hash_password(body.password),
            password_changed_at=datetime.now(UTC),
            created_by="platform-invitation",
            updated_by="platform-invitation",
        )
        db.add(user)
        await db.flush()
        role_identifier = invitation.role or "platform-super-admin"
        if role_identifier == "platform_admin":
            role_identifier = "platform-super-admin"
        role = await db.scalar(
            select(PlatformRole).where(
                (PlatformRole.id == role_identifier)
                | (PlatformRole.name.ilike(role_identifier))
            )
        )
        if role is None or role.status != "published":
            raise HTTPException(422, "The invited platform role is no longer available")
        user.role_id = role.id
        db.add(
            PlatformRoleAssignment(
                user_id=user.id,
                role_id=role.id,
                level="Platform",
                created_by=user.id,
                updated_by=user.id,
            )
        )
        if role.id == "platform-super-admin":
            await seed_platform_super_admin(db, user.id)
        invitation.status = "accepted"
        invitation.updated_by = user.id
        platform_audit(db, user.id, "platform-invite.accept", details={"invite_id": invitation.id})
        return {"status": "created"}


# Handle complete platform password reset for this module.
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
        if body.password != body.password_confirmation:
            raise HTTPException(422, "Passwords do not match")
        if not user.mfa_enabled or not user.mfa_secret:
            raise HTTPException(401, "MFA must be enrolled before resetting the password")
        counter = verify_totp(vault().open(user.mfa_secret), body.code, user.mfa_counter)
        if counter is None:
            platform_audit(db, user.id, "platform.password-reset.mfa-failure", details={"challenge_id": challenge.id})
            raise HTTPException(401, "A valid unused authenticator code is required")
        policy = effective_password_policy((await platform_configuration(db)).password_policy)
        password_error = validate_password(body.password, policy)
        if password_error:
            raise HTTPException(422, password_error)
        challenge.used = True
        challenge.updated_by = user.id
        user.mfa_counter = counter
        user.password_hash = hash_password(body.password)
        user.password_changed_at = datetime.now(UTC)
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


# Handle setup for this module.
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


# Handle verify for this module.
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
        if is_bootstrap_platform_user(user):
            # Older bootstrap records may predate canonical RBAC assignment.
            # Reconcile the locked role at the first successful MFA login.
            await seed_platform_super_admin(db, user.id)
        access = await issue_platform_token(db, user)
        platform_audit(db, user.id, "platform.auth.success")
    return {"access_token": access, "token_type": "bearer", "expires_in": 1800}


# Handle me for this module.
@router.get("/me")
async def me(actor: PlatformActor = Depends(current_platform)):
    async with control_session() as db:
        user = await db.get(PlatformUser, actor.user_id)
        if user is None:
            raise HTTPException(404, "Platform profile not found")
        policy = effective_password_policy((await platform_configuration(db)).password_policy)
        expiry_at = password_expiry_at(user.password_changed_at, policy)
        assignment = await db.scalar(
            select(PlatformRoleAssignment)
            .where(PlatformRoleAssignment.user_id == user.id)
            .order_by(PlatformRoleAssignment.created_at)
        )
        assigned_role = await db.get(PlatformRole, assignment.role_id) if assignment else None
        return {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": actor.role,
            "role_id": actor.role_id or (assigned_role.id if assigned_role else user.role_id),
            "is_bootstrap_operator": actor.is_bootstrap_operator,
            "mfa_enabled": user.mfa_enabled,
            "permissions": await platform_permission_keys(db, user.id),
            "password_expires_at": expiry_at.isoformat() if expiry_at else None,
            "password_expires_in_days": password_expiry_days_remaining(user.password_changed_at, policy),
            "password_expired": password_expired(user.password_changed_at, policy),
        }


# Update update me while preserving existing validation and audit behavior.
@router.put("/me")
async def update_me(body: ProfileUpdate, actor: PlatformActor = Depends(current_platform)):
    async with control_session() as db:
        user = await db.get(PlatformUser, actor.user_id)
        if user is None:
            raise HTTPException(404, "Platform profile not found")
        policy = effective_password_policy((await platform_configuration(db)).password_policy)
        expiry_at = password_expiry_at(user.password_changed_at, policy)
        assignment = await db.scalar(
            select(PlatformRoleAssignment)
            .where(PlatformRoleAssignment.user_id == user.id)
            .order_by(PlatformRoleAssignment.created_at)
        )
        assigned_role = await db.get(PlatformRole, assignment.role_id) if assignment else None
        user.name = body.name.strip()
        user.updated_by = actor.user_id
        platform_audit(db, actor.user_id, "platform.profile.update")
        return {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": actor.role,
            "role_id": actor.role_id or (assigned_role.id if assigned_role else user.role_id),
            "is_bootstrap_operator": actor.is_bootstrap_operator,
            "mfa_enabled": user.mfa_enabled,
            "permissions": await platform_permission_keys(db, user.id),
            "password_expires_at": expiry_at.isoformat() if expiry_at else None,
            "password_expires_in_days": password_expiry_days_remaining(user.password_changed_at, policy),
            "password_expired": password_expired(user.password_changed_at, policy),
        }


# Update change password while preserving existing validation and audit behavior.
@router.post("/password/change")
async def change_password(body: PasswordChange, actor: PlatformActor = Depends(current_platform)):
    async with control_session() as db:
        user = await db.get(PlatformUser, actor.user_id)
        if user is None or not verify_password(body.current_password, user.password_hash):
            raise HTTPException(400, "Current password is incorrect")
        policy = effective_password_policy((await platform_configuration(db)).password_policy)
        password_error = validate_password(body.new_password, policy)
        if password_error:
            raise HTTPException(422, password_error)
        user.password_hash = hash_password(body.new_password)
        user.password_changed_at = datetime.now(UTC)
        user.token_version += 1
        user.updated_by = actor.user_id
        await db.execute(update(PlatformSession).where(PlatformSession.user_id == user.id, PlatformSession.revoked.is_(False)).values(revoked=True, updated_by=actor.user_id))
        platform_audit(db, actor.user_id, "platform.password.change")
    return {"status": "password-updated"}


# Handle reset mfa for this module.
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


# Handle logout for this module.
@router.post("/logout")
async def logout(actor: PlatformActor = Depends(current_platform)):
    async with control_session() as db:
        session = await db.get(PlatformSession, actor.session_id)
        session.revoked = True
        platform_audit(db, actor.user_id, "platform.logout")
    return {"revoked": True}
