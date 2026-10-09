import time
from dataclasses import dataclass, field

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from app.core.audit import audit
from app.core.config import settings
from app.core.database import control_session, organization_session
from app.identity.access import effective_access
from app.identity.models import StaffSession, StaffUser
from app.integrations.configuration import attach_effective_adapters
from app.organizations.configuration import tenant_settings
from app.organizations.models import Organization, TenantSettings
from app.organizations.tenant_resolution import validate_request_tenant
from app.rbac.default_roles import default_role_definitions

bearer = HTTPBearer(auto_error=False)
# Legacy compatibility guards read default-role seed data; canonical RBAC grants are
# the source of truth for new endpoints and staff assignment choices.
ROLE_PERMISSIONS = {
    item["name"]: set(item["modules"]) | set(item.get("compatibility_permissions", []))
    for item in default_role_definitions()
}
ROLE_DEFINITIONS = {item["name"]: item for item in default_role_definitions()}


def role_has(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


async def user_has_module(db, user: StaffUser, module: str) -> bool:
    if role_has(user.role, module):
        return True
    from app.rbac.models import TenantRole, TenantRoleAssignment, TenantRoleGrant

    return bool(
        await db.scalar(
            select(TenantRoleGrant.id)
            .join(TenantRole, TenantRole.id == TenantRoleGrant.role_id)
            .join(TenantRoleAssignment, TenantRoleAssignment.role_id == TenantRole.id)
            .where(
                TenantRoleAssignment.user_id == user.id,
                TenantRole.status == "published",
                TenantRoleGrant.effect == "allow",
                TenantRoleGrant.permission_key.like(f"{module}.%"),
            )
            .limit(1)
        )
    )


def is_organization_role(role: str) -> bool:
    return bool(ROLE_DEFINITIONS.get(role, {}).get("organization_scope"))


def role_names_for_module(module: str) -> tuple[str, ...]:
    """Return configured default role names that include a module capability."""
    return tuple(
        name for name, definition in ROLE_DEFINITIONS.items()
        if module in definition.get("modules", [])
    )


async def role_names_with_module(db, module: str) -> tuple[str, ...]:
    """Return published default and custom role names granting a module."""
    from app.rbac.models import TenantRole, TenantRoleGrant

    names = set(role_names_for_module(module))
    rows = (
        await db.scalars(
            select(TenantRole.name)
            .join(TenantRoleGrant, TenantRoleGrant.role_id == TenantRole.id)
            .where(
                TenantRole.status == "published",
                TenantRoleGrant.effect == "allow",
                TenantRoleGrant.permission_key.like(f"{module}.%"),
            )
        )
    ).all()
    names.update(rows)
    return tuple(sorted(names))


def organization_role_names() -> tuple[str, ...]:
    return tuple(
        name for name, definition in ROLE_DEFINITIONS.items()
        if definition.get("organization_scope")
    )


def default_role_name(scope: str = "organization") -> str:
    candidates = (
        organization_role_names()
        if scope == "organization"
        else role_names_for_module("clinical")
    )
    if not candidates:
        raise RuntimeError(f"No default role configured for {scope} scope")
    return candidates[0]


async def canonical_permission_allowed(request: Request, actor: "Actor", module: str) -> bool:
    """Evaluate a legacy module guard against the published RBAC grants.

    This keeps older routers compatible while allowing tenant-defined roles to
    work without adding their names to Python constants.
    """
    from app.rbac.registry import load_approved_registry
    from app.rbac.runtime import decide_tenant

    registry = load_approved_registry()
    keys = [
        key
        for (domain, key), definition in registry.permissions.items()
        if domain == "tenant"
        and (key == module or key.split(".", 1)[0] == module)
    ]
    if not keys:
        return False
    async with organization_session(actor.organization) as db:
        for key in keys:
            decision = await decide_tenant(
                db,
                actor.user_id,
                key,
                selected_location_id=actor.selected_location_id,
                current_ip=request.client.host if request.client else None,
            )
            if decision.allowed and not decision.needs_step_up and not decision.needs_approval:
                return True
    return False


@dataclass
class Actor:
    user_id: str
    organization: Organization
    name: str
    role: str
    session_id: str = ""
    location_ids: list[str] = field(default_factory=list)
    settings: TenantSettings | None = None
    adapter_names: dict[str, str] = field(default_factory=dict)
    photo_url: str = ""
    local_password: bool = True
    assignment_scope: str = "location"
    selected_location_id: str | None = None
    assignments: list[dict] = field(default_factory=list)
    mfa_authenticated_at: int = 0
    modules: frozenset[str] = frozenset()


async def issue_token(db, user, organization, *, ttl_seconds: int = 1800):
    now = int(time.time())
    session = StaffSession(user_id=user.id, expires=now + ttl_seconds, last_active=now)
    db.add(session)
    await db.flush()
    return jwt.encode(
        {
            "sub": user.id,
            "org": organization.id,
            "sid": session.id,
            "ver": user.token_version,
            "amr": ["pwd", "otp"],
            "aud": "dhmis-staff",
            "iss": "dhmis",
            "iat": now,
            "exp": now + ttl_seconds,
        },
        settings().jwt_secret.get_secret_value(),
        algorithm="HS256",
    )


async def current_actor(
    request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)
):
    try:
        if credentials is None:
            raise ValueError()
        data = jwt.decode(
            credentials.credentials,
            settings().jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            audience="dhmis-staff",
            issuer="dhmis",
            options={"require": ["sub", "org", "sid", "ver", "exp", "iat", "amr"]},
        )
        if "otp" not in data["amr"]:
            raise ValueError()
        async with control_session() as db:
            org = await db.get(Organization, data["org"])
        if org is None or org.status != "active":
            raise ValueError()
        await validate_request_tenant(request, org)
        adapter_names = await attach_effective_adapters(org)
        async with organization_session(org) as db:
            user = await db.get(StaffUser, data["sub"])
            session = await db.scalar(
                select(StaffSession).where(StaffSession.id == data["sid"]).with_for_update()
            )
            now = int(time.time())
            if user is None or not user.active or not user.mfa_enabled or user.token_version != data["ver"]:
                raise ValueError()
            if (
                session is None
                or session.user_id != user.id
                or session.revoked
                or session.expires <= now
                or session.last_active < now - 900
            ):
                raise ValueError()
            session.last_active = now
            runtime_settings = await tenant_settings(db)
            access = await effective_access(db, user, request.headers.get("X-DHMIS-Location"))
            from app.rbac.models import TenantRole, TenantRoleGrant

            role_row = await db.scalar(
                select(TenantRole).where(
                    TenantRole.name == access.role,
                    TenantRole.status == "published",
                )
            )
            modules = set(ROLE_DEFINITIONS.get(access.role, {}).get("modules", []))
            if role_row is not None:
                grants = (
                    await db.scalars(
                        select(TenantRoleGrant).where(
                            TenantRoleGrant.role_id == role_row.id,
                            TenantRoleGrant.effect == "allow",
                        )
                    )
                ).all()
                modules.update(grant.permission_key.split(".", 1)[0] for grant in grants)
        return Actor(
            user.id,
            org,
            user.name,
            access.role,
            session.id,
            (
                access.available_location_ids
                if access.scope == "organization"
                else [access.selected_location_id]
                if access.selected_location_id
                else []
            ),
            runtime_settings,
            adapter_names,
            user.photo_url,
            user.external_subject is None,
            access.scope,
            access.selected_location_id,
            access.assignments,
            data["iat"],
            frozenset(modules),
        )
    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise HTTPException(401, "Valid MFA-authenticated staff session required") from None


async def db_session(actor: Actor = Depends(current_actor)):
    async with organization_session(actor.organization) as db:
        # SQLAlchemy loader criteria applies location visibility to reads and identity lookups.
        db.info["actor"] = actor
        yield db


def permit(permission):
    async def guard(request: Request, actor: Actor = Depends(current_actor)):
        allowed = permission in ROLE_PERMISSIONS.get(actor.role, set())
        if not allowed:
            allowed = await canonical_permission_allowed(request, actor, permission)
        if not allowed:
            async with organization_session(actor.organization) as db:
                audit(db, actor.user_id, "access.denied", permission, organization_id=actor.organization.id)
            raise HTTPException(403, "Permission denied")
        return actor

    return guard
