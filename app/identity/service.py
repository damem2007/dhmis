import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, or_, select

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
    item["name"]: (
        set(item["modules"])
        | set(item.get("compatibility_permissions", []))
        | set(item.get("additional_permissions", []))
    )
    for item in default_role_definitions()
}
ROLE_DEFINITIONS = {item["name"]: item for item in default_role_definitions()}
TENANT_SUPER_ADMIN_ROLE_ID = "tenant-super-admin"


def is_tenant_super_admin_role(role_id: str | None, role_name: str | None = None) -> bool:
    """Recognize the protected tenant role in canonical and legacy rows."""

    normalized_id = str(role_id or "").strip().casefold().replace("_", "-")
    return normalized_id == TENANT_SUPER_ADMIN_ROLE_ID


def legacy_module_permissions_for_role(
    role_id: str | None,
    canonical_role_name: str | None = None,
) -> set[str]:
    """Return compatibility module aliases for a canonical default role.

    A few older routers still use a module-only guard (for example
    ``dashboard``), while the approved registry is action/resource based and
    does not contain a permission resource for every legacy module.  The
    canonical role id is the source of truth here.  ``canonical_role_name``
    is accepted only when it was resolved from that id through ``tenant_roles``;
    the informational ``staff_users.role`` label is never consulted.
    """

    if not role_id:
        return set()
    if is_tenant_super_admin_role(role_id, canonical_role_name):
        # The protected setup role is intentionally tenant-wide.  It receives
        # every reviewed tenant permission plus the legacy module aliases
        # required by older endpoints.
        return {
            permission.split(".", 1)[0]
            for definition in ROLE_DEFINITIONS.values()
            for permission in (
                set(definition.get("modules", ()))
                | set(definition.get("compatibility_permissions", ()))
                | set(definition.get("additional_permissions", ()))
            )
        }
    compatibility = ROLE_PERMISSIONS.get(canonical_role_name or "") or ROLE_PERMISSIONS.get(
        role_id, set()
    )
    return {
        permission.split(".", 1)[0]
        for permission in compatibility
    }


# Handle staff user available for this module.
def staff_user_available(user: StaffUser) -> bool:
    return bool(
        user.active
        and user.archived_at is None
        and (user.suspended_until is None or user.suspended_until <= datetime.now(UTC))
    )


# Handle role has for this module.
def role_has(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


# Handle user has module for this module.
async def user_has_module(db, user: StaffUser, module: str) -> bool:
    if is_tenant_super_admin_role(user.role_id, user.role):
        # The protected role is defined as tenant-wide access.  Provider and
        # care-team validation must not depend on a denormalized grant row
        # being present before the tenant repair migration runs.
        return True
    if user.role_id is None and role_has(user.role, module):
        return True
    from app.rbac.models import TenantRole, TenantRoleAssignment, TenantRoleGrant

    canonical_grant = await db.scalar(
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
    if canonical_grant:
        return True
    # A canonical assignment is authoritative even when it does not grant the
    # requested module; only users with no canonical assignment may use the
    # legacy staff-location projection.
    if await db.scalar(
        select(TenantRoleAssignment.id)
        .where(TenantRoleAssignment.user_id == user.id)
        .limit(1)
    ):
        return False
    return await _legacy_user_has_module(db, user, module)


async def _legacy_user_has_module(db, user: StaffUser, module: str) -> bool:
    """Evaluate a legacy role projection until canonical assignments exist."""
    from app.identity.models import StaffLocationAssignment
    from app.rbac.models import TenantRole, TenantRoleGrant

    identifiers = {
        value.strip().casefold()
        for value in (user.role_id, user.role)
        if isinstance(value, str) and value.strip()
    }
    if not identifiers:
        return False
    role = await db.scalar(
        select(TenantRole).where(
            TenantRole.status == "published",
            or_(
                TenantRole.id.in_(identifiers),
                func.lower(TenantRole.name).in_(identifiers),
            ),
        )
    )
    if role is None:
        return False
    assignment = await db.scalar(
        select(StaffLocationAssignment.id).where(
            StaffLocationAssignment.user_id == user.id,
            StaffLocationAssignment.active,
            func.lower(StaffLocationAssignment.role).in_(identifiers),
        )
    )
    if assignment is None:
        return False
    return bool(
        await db.scalar(
            select(TenantRoleGrant.id).where(
                TenantRoleGrant.role_id == role.id,
                TenantRoleGrant.effect == "allow",
                TenantRoleGrant.permission_key.like(f"{module}.%"),
            )
        )
    )


# Determine whether is organization role.
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


# Handle organization role names for this module.
def organization_role_names() -> tuple[str, ...]:
    return tuple(
        name for name, definition in ROLE_DEFINITIONS.items()
        if definition.get("organization_scope")
    )


# Handle default role name for this module.
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


# Defines the actor model, contract, or value object.
@dataclass
class Actor:
    user_id: str
    organization: Organization
    name: str
    role: str
    session_id: str = ""
    role_id: str | None = None
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


# Create or issue issue token while applying existing validation and authorization.
async def issue_token(db, user, organization, *, ttl_seconds: int | None = None):
    ttl_seconds = ttl_seconds if ttl_seconds is not None else settings().staff_session_ttl_seconds
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


async def renew_token(db, user, organization, session_id: str):
    """Extend the current, already-authenticated staff session and issue its replacement JWT.

    This deliberately renews only the session selected by ``current_actor``.  It
    neither creates another session nor bypasses the normal idle, revocation,
    MFA, or token-version checks performed before the route handler runs.
    """

    now = int(time.time())
    session = await db.get(StaffSession, session_id)
    if (
        session is None
        or session.user_id != user.id
        or session.revoked
        or session.expires <= now
    ):
        raise ValueError("Session is no longer available")
    ttl_seconds = settings().staff_session_ttl_seconds
    session.expires = now + ttl_seconds
    session.last_active = now
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


# Handle current actor for this module.
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
            if user is None or not staff_user_available(user) or not user.mfa_enabled or user.token_version != data["ver"]:
                raise ValueError()
            if (
                session is None
                or session.user_id != user.id
                or session.revoked
                or session.expires <= now
                or session.last_active < now - settings().staff_idle_timeout_seconds
            ):
                raise ValueError()
            session.last_active = now
            # Existing tenants may have been provisioned before the protected
            # Tenant Super Admin assignment was introduced. Repair that
            # bootstrap projection lazily during an authenticated request so
            # the admin is not left with a disabled UI while waiting for a
            # migration. The helper is idempotent and only promotes the first
            # organization-level legacy admin when no protected assignment
            # exists in the tenant.
            from app.rbac.bootstrap import (
                ensure_tenant_super_admin_grants,
                seed_tenant_super_admin,
            )
            from app.rbac.models import TenantRole, TenantRoleAssignment

            protected_role_exists = await db.scalar(
                select(TenantRole.id).where(TenantRole.id == TENANT_SUPER_ADMIN_ROLE_ID)
            )
            protected_assignment_exists = await db.scalar(
                select(TenantRoleAssignment.id).where(
                    TenantRoleAssignment.role_id == TENANT_SUPER_ADMIN_ROLE_ID
                )
            )
            if not protected_role_exists or not protected_assignment_exists:
                await seed_tenant_super_admin(
                    db,
                    "auth-superadmin-reconciliation",
                    sync_legacy=False,
                    assign_first_legacy_admin=True,
                )
            else:
                # Reconcile newly approved protected permissions before the
                # actor payload is built, so /auth/me immediately exposes the
                # same rights that the policy engine will enforce.
                await ensure_tenant_super_admin_grants(db)
            runtime_settings = await tenant_settings(db)
            access = await effective_access(db, user, request.headers.get("X-DHMIS-Location"))
            from app.rbac.models import TenantRoleGrant

            role_row = await db.get(TenantRole, access.role_id) if access.role_id else None
            # Older staff records store the default role name in role_id while
            # canonical TenantRole rows use UUIDs. Resolve that compatibility
            # shape by name so the actor still receives the role's exact
            # resource grants until the assignment projection is reconciled.
            if role_row is None:
                role_row = await db.scalar(
                    select(TenantRole).where(
                        func.lower(TenantRole.name) == str(access.role).strip().lower(),
                        TenantRole.status == "published",
                    )
                )
            # Keep the frontend's compatibility aliases keyed by the
            # canonical role id.  ``StaffUser.role`` is display-only after
            # role references were introduced and must not decide access.
            modules = legacy_module_permissions_for_role(
                access.role_id,
                role_row.name if role_row is not None else access.role,
            )
            if role_row is not None:
                grants = (
                    await db.scalars(
                        select(TenantRoleGrant).where(
                            TenantRoleGrant.role_id == role_row.id,
                            TenantRoleGrant.effect == "allow",
                        )
                    )
                ).all()
                for grant in grants:
                    # Expose both the exact grant and its module root.  The
                    # former is used by action-level UI controls; the latter
                    # keeps the existing navigation contract working.
                    modules.add(grant.permission_key)
                    modules.add(grant.permission_key.split(".", 1)[0])
            if is_tenant_super_admin_role(
                access.role_id,
                role_row.name if role_row is not None else access.role,
            ):
                # The protected role is policy-defined as every active,
                # reviewed tenant permission.  Do not make the UI depend on
                # a repair migration having populated a denormalized grant
                # row before it can render the tenant workspace.
                from app.rbac.registry import load_approved_registry

                approved = load_approved_registry()
                for (domain, key), definition in approved.permissions.items():
                    if domain != "tenant" or definition.retired or not definition.reviewed:
                        continue
                    modules.add(key)
                    modules.add(key.split(".", 1)[0])
        return Actor(
            user.id,
            org,
            user.name,
            access.role,
            session.id,
            access.role_id,
            # Keep every location assigned to the staff member available to
            # scope patient and dashboard queries. The selected location is
            # still carried separately as the active context.
            access.available_location_ids
            or ([access.selected_location_id] if access.selected_location_id else []),
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


# Handle db session for this module.
async def db_session(actor: Actor = Depends(current_actor)):
    async with organization_session(actor.organization) as db:
        # SQLAlchemy loader criteria applies location visibility to reads and identity lookups.
        db.info["actor"] = actor
        yield db


# Handle permit for this module.
def permit(permission):
    # Handle guard for this module.
    async def guard(request: Request, actor: Actor = Depends(current_actor)):
        # Canonical role ids are authoritative for the role lookup. Preserve
        # the old module-only compatibility guards for the resolved canonical
        # role name, and explicitly honor
        # the protected Tenant Super Admin role for legacy modules that have
        # no action/resource entry in the approved registry (dashboard is one
        # example).  The exact tenant permission guards still run through the
        # canonical policy engine.
        allowed = permission in ROLE_PERMISSIONS.get(actor.role, set())
        if not allowed and actor.role_id == TENANT_SUPER_ADMIN_ROLE_ID:
            # The canonical role is global policy, but this guard still only
            # accepts approved tenant permissions and legacy module aliases.
            # It must never become an arbitrary wildcard if a platform route
            # is accidentally wired to the tenant dependency.
            allowed = permission in getattr(actor, "modules", ()) or permission in (
                legacy_module_permissions_for_role(actor.role_id, actor.role)
            )
        if not allowed:
            allowed = await canonical_permission_allowed(request, actor, permission)
        if not allowed:
            async with organization_session(actor.organization) as db:
                audit(db, actor.user_id, "access.denied", permission, organization_id=actor.organization.id)
            raise HTTPException(403, {"message": "Permission denied", "required_permissions": [permission]})
        return actor

    return guard
