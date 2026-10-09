"""Seedable default role definitions; authorization still comes from RBAC grants."""

import json
from pathlib import Path

from sqlalchemy import select

from app.identity.models import StaffLocationAssignment
from app.rbac.models import TenantRole, TenantRoleGrant
from app.rbac.models import TenantRoleAssignment
from app.rbac.registry import load_approved_registry

DEFAULT_ROLES_PATH = Path(__file__).with_name("default_roles.json")


def default_role_definitions() -> list[dict]:
    return json.loads(DEFAULT_ROLES_PATH.read_text())


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
                locked=True,
                created_by=actor_id,
                updated_by=actor_id,
            )
            db.add(role)
            await db.flush()
            roles[name] = role
    registry = load_approved_registry()
    existing = {
        (row.role_id, row.permission_key)
        for row in (await db.scalars(select(TenantRoleGrant))).all()
    }
    for name, definition in definitions.items():
        role = roles[name]
        for permission in registry.permissions.values():
            if permission.domain.value != "tenant" or permission.resource_key.split(".", 1)[0] not in definition["modules"]:
                continue
            if permission.action not in {"read", "create", "update"}:
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
    for assignment in legacy:
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
