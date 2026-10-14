"""Seedable default role definitions; authorization still comes from RBAC grants."""

import json
from pathlib import Path

from sqlalchemy import select

from app.identity.models import StaffLocationAssignment
from app.rbac.models import TenantRole, TenantRoleGrant
from app.rbac.models import TenantRoleAssignment
from app.rbac.registry import load_approved_registry

DEFAULT_ROLES_PATH = Path(__file__).with_name("default_roles.json")


def _load_defaults() -> dict:
    """Load the versioned default-role catalogue.

    The first version of this file was a bare list of tenant roles.  Accepting
    that shape keeps older checkouts and tenant bootstrap jobs readable while
    the catalogue moves to an explicit tenant/platform structure.
    """

    payload = json.loads(DEFAULT_ROLES_PATH.read_text())
    if isinstance(payload, list):
        return {"schema_version": "0.3", "tenant_roles": payload, "platform_roles": {}}
    if not isinstance(payload, dict) or not isinstance(payload.get("tenant_roles"), list):
        raise ValueError("default_roles.json must define a tenant_roles list")
    return payload


# Handle default role definitions for this module.
def default_role_definitions() -> list[dict]:
    return _load_defaults()["tenant_roles"]


def default_platform_role_definitions() -> dict[str, dict]:
    """Return platform role capabilities declared in the same catalogue."""

    platform_roles = _load_defaults().get("platform_roles", {})
    if isinstance(platform_roles, list):
        return {item["name"]: item for item in platform_roles}
    return platform_roles


# Internal helper for permission module.
def _permission_module(permission) -> str:
    return permission.resource_key.split(".", 1)[0]


def _validate_default_permissions(registry, definitions: dict[str, dict]) -> None:
    """Fail fast when JSON names a permission that is not in the approved registry."""

    tenant_permissions = {
        key: permission
        for (domain, key), permission in registry.permissions.items()
        if domain == "tenant"
    }
    tenant_keys = set(tenant_permissions)
    tenant_modules = {
        _permission_module(permission)
        for (domain, _), permission in registry.permissions.items()
        if domain == "tenant"
    }
    for name, definition in definitions.items():
        unknown_modules = set(definition.get("modules", ())) - tenant_modules - {
            # These roots are retained for legacy endpoint guards. They do
            # not map to approved canonical permission resources.
            "analytics",
            "consents",
            "dashboard",
            "prescriptions",
            "reporting",
            "surgery",
        }
        if unknown_modules:
            raise ValueError(
                f"Default role {name!r} references unknown tenant modules: "
                f"{', '.join(sorted(unknown_modules))}"
            )
        unknown_permissions = set(definition.get("additional_permissions", ())) - tenant_keys
        if unknown_permissions:
            raise ValueError(
                f"Default role {name!r} references unknown tenant permissions: "
                f"{', '.join(sorted(unknown_permissions))}"
            )
        inactive_permissions = {
            key
            for key in definition.get("additional_permissions", ())
            if not tenant_permissions[key].reviewed or tenant_permissions[key].retired
        }
        if inactive_permissions:
            raise ValueError(
                f"Default role {name!r} references inactive tenant permissions: "
                f"{', '.join(sorted(inactive_permissions))}"
            )


# Handle seed default tenant roles for this module.
async def seed_default_tenant_roles(db, actor_id: str = "rbac-bootstrap") -> dict[str, TenantRole]:
    definitions = {item["name"]: item for item in default_role_definitions()}
    roles = {row.name: row for row in (await db.scalars(select(TenantRole))).all()}
    for name, definition in definitions.items():
        role = roles.get(name)
        if role is None:
            role = TenantRole(
                name=name,
                description=f"Default {name} role; permissions are stored as editable RBAC grants.",
                status="published",
                # Tenant Super Admin is the only protected tenant role. The
                # operational default roles are intentionally editable by
                # governed tenant administrators.
                locked=False,
                created_by=actor_id,
                updated_by=actor_id,
            )
            db.add(role)
            await db.flush()
            roles[name] = role
        elif role.locked:
            # Older tenants were seeded with every default role locked. Keep
            # the existing records aligned with the current tenant RBAC model.
            role.locked = False
    registry = load_approved_registry()
    _validate_default_permissions(registry, definitions)
    existing = {
        (row.role_id, row.permission_key)
        for row in (await db.scalars(select(TenantRoleGrant))).all()
    }
    for name, definition in definitions.items():
        role = roles[name]
        explicit_permissions = set(definition.get("additional_permissions", ()))
        for permission in registry.permissions.values():
            if permission.domain.value != "tenant":
                continue
            if not permission.reviewed or permission.retired:
                continue
            if (
                _permission_module(permission) not in definition["modules"]
                and permission.key not in explicit_permissions
            ):
                continue
            if permission.key not in explicit_permissions and permission.action not in {
                "read",
                "create",
                "update",
            }:
                continue
            if definition["organization_scope"] and "Organization" in {scope.value for scope in permission.valid_scopes}:
                scope = "Organization"
            elif not definition["organization_scope"] and "Location" in {scope.value for scope in permission.valid_scopes}:
                scope = "Location"
            elif "Organization" in {scope.value for scope in permission.valid_scopes}:
                scope = "Organization"
            elif "Location" in {scope.value for scope in permission.valid_scopes}:
                scope = "Location"
            else:
                continue
            if (role.id, permission.key) not in existing:
                db.add(
                    TenantRoleGrant(
                        role_id=role.id,
                        permission_key=permission.key,
                        effect="allow",
                        scope=scope,
                        created_by=actor_id,
                        updated_by=actor_id,
                    )
                )
    await db.flush()
    return roles


async def sync_legacy_assignments(db, roles: dict[str, TenantRole], actor_id: str = "rbac-bootstrap"):
    """Bridge legacy assignment rows to canonical role assignments during development seeding."""
    legacy = (
        await db.scalars(select(StaffLocationAssignment).where(StaffLocationAssignment.active))
    ).all()
    existing = {
        (row.user_id, row.role_id, row.level, row.location_id)
        for row in (await db.scalars(select(TenantRoleAssignment))).all()
    }
    super_admin_users = set(
        await db.scalars(
            select(TenantRoleAssignment.user_id).where(
                TenantRoleAssignment.role_id == "tenant-super-admin"
            )
        )
    )
    for assignment in legacy:
        if assignment.user_id in super_admin_users:
            continue
        role = roles.get(assignment.role)
        if role is None:
            continue
        level = "Organization" if assignment.scope == "organization" else "Location"
        key = (assignment.user_id, role.id, level, assignment.location_id)
        if key in existing:
            continue
        db.add(
            TenantRoleAssignment(
                user_id=assignment.user_id,
                role_id=role.id,
                level=level,
                location_id=assignment.location_id,
                created_by=actor_id,
                updated_by=actor_id,
            )
        )
        existing.add(key)
    await db.flush()
