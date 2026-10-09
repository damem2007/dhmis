import hmac
import time
from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from app.core.config import settings
from app.core.database import control_session
from app.platform_identity.models import PlatformAuditEvent, PlatformSession, PlatformUser

platform_bearer = HTTPBearer(auto_error=False)


@dataclass
class PlatformActor:
    user_id: str
    name: str
    role: str
    session_id: str
    mfa_authenticated_at: int = 0


def platform_audit(db, actor_id, action, *, organization_id=None, reason="", details=None):
    db.add(
        PlatformAuditEvent(
            actor_id=actor_id,
            action=action,
            organization_id=organization_id,
            reason=reason,
            details=details or {},
            created_by=actor_id,
            updated_by=actor_id,
        )
    )


async def issue_platform_token(db, user: PlatformUser):
    now = int(time.time())
    session = PlatformSession(user_id=user.id, expires=now + 1800, last_active=now)
    db.add(session)
    await db.flush()
    return jwt.encode(
        {
            "sub": user.id,
            "sid": session.id,
            "ver": user.token_version,
            "amr": ["pwd", "otp"],
            "aud": "dhmis-platform",
            "iss": "dhmis",
            "iat": now,
            "exp": now + 1800,
        },
        settings().jwt_secret.get_secret_value(),
        algorithm="HS256",
    )


async def current_platform(
    credentials: HTTPAuthorizationCredentials | None = Depends(platform_bearer),
):
    try:
        if credentials is None:
            raise ValueError()
        data = jwt.decode(
            credentials.credentials,
            settings().jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            audience="dhmis-platform",
            issuer="dhmis",
            options={"require": ["sub", "sid", "ver", "exp", "iat", "amr"]},
        )
        async with control_session() as db:
            user = await db.get(PlatformUser, data["sub"])
            session = await db.scalar(
                select(PlatformSession)
                .where(PlatformSession.id == data["sid"])
                .with_for_update()
            )
            now = int(time.time())
            if (
                user is None
                or not user.active
                or not user.mfa_enabled
                or user.token_version != data["ver"]
                or session is None
                or session.user_id != user.id
                or session.revoked
                or session.expires <= now
                or session.last_active < now - 900
            ):
                raise ValueError()
            session.last_active = now
        return PlatformActor(user.id, user.name, user.role, session.id, data["iat"])
    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise HTTPException(401, "Valid platform operator session required") from None


async def platform_or_bootstrap(
    credentials: HTTPAuthorizationCredentials | None = Depends(platform_bearer),
    x_bootstrap_key: str = Header(default=""),
):
    if hmac.compare_digest(x_bootstrap_key, settings().bootstrap_key.get_secret_value()):
        return PlatformActor("bootstrap", "Bootstrap operator", "platform_admin", "")
    return await current_platform(credentials)
