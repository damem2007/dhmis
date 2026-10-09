import time
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import or_, select

from app.core.config import settings
from app.core.database import control_session, organization_session
from app.identity.service import bearer
from app.integrations.configuration import attach_effective_adapters
from app.organizations.configuration import tenant_settings
from app.organizations.models import Organization, TenantSettings
from app.organizations.tenant_resolution import validate_request_tenant
from app.patient_identity.models import PatientSession, PatientUser
from app.patients.models import GuardianLink


@dataclass
class PatientActor:
    user_id: str
    patient_id: str
    organization: Organization
    session_id: str
    settings: TenantSettings | None = None
    adapter_names: dict[str, str] | None = None


async def issue_patient_token(
    db, user: PatientUser, organization: Organization, authentication_method="pwd"
):
    now = int(time.time())
    session = PatientSession(user_id=user.id, expires=now + 3600, last_active=now)
    db.add(session)
    await db.flush()
    return jwt.encode(
        {
            "sub": user.id,
            "patient": user.patient_id,
            "org": organization.id,
            "sid": session.id,
            "ver": user.token_version,
            "amr": [authentication_method],
            "aud": "dhmis-patient",
            "iss": "dhmis",
            "iat": now,
            "exp": now + 3600,
        },
        settings().jwt_secret.get_secret_value(),
        algorithm="HS256",
    )


async def current_patient(
    request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)
):
    try:
        if credentials is None:
            raise ValueError()
        data = jwt.decode(
            credentials.credentials,
            settings().jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            audience="dhmis-patient",
            issuer="dhmis",
            options={"require": ["sub", "patient", "org", "sid", "ver", "exp", "iat", "amr"]},
        )
        async with control_session() as db:
            organization = await db.get(Organization, data["org"])
        if (
            organization is None
            or organization.status != "active"
            or not organization.patient_portal_enabled
        ):
            raise ValueError()
        await validate_request_tenant(request, organization)
        adapter_names = await attach_effective_adapters(organization)
        async with organization_session(organization) as db:
            user = await db.get(PatientUser, data["sub"])
            session = await db.scalar(
                select(PatientSession).where(PatientSession.id == data["sid"]).with_for_update()
            )
            now = int(time.time())
            if user is None or not user.active or user.patient_id != data["patient"]:
                raise ValueError()
            if user.token_version != data["ver"]:
                raise ValueError()
            if (
                session is None
                or session.user_id != user.id
                or session.revoked
                or session.expires <= now
                or session.last_active < now - 1800
            ):
                raise ValueError()
            session.last_active = now
            runtime_settings = await tenant_settings(db)
        return PatientActor(
            user.id,
            user.patient_id,
            organization,
            session.id,
            runtime_settings,
            adapter_names,
        )
    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise HTTPException(401, "Valid patient session required") from None


async def patient_db_session(actor: PatientActor = Depends(current_patient)):
    async with organization_session(actor.organization) as db:
        yield db


async def authorized_patient_ids(db, actor: PatientActor):
    links = (
        await db.scalars(
            select(GuardianLink).where(
                or_(
                    GuardianLink.guardian_id == actor.patient_id,
                    GuardianLink.dependent_id == actor.patient_id,
                )
            )
        )
    ).all()
    return {actor.patient_id, *(link.dependent_id for link in links if link.guardian_id == actor.patient_id)}


async def require_patient_access(db, actor: PatientActor, patient_id: str):
    if patient_id not in await authorized_patient_ids(db, actor):
        raise HTTPException(403, "Patient profile is outside this portal account")
