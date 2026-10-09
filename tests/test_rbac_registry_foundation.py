from sqlalchemy import func, select

from app.core.database import control_session, tenant_session
from app.rbac.bootstrap import (
    PLATFORM_SUPER_ADMIN_ROLE_ID,
    TENANT_SUPER_ADMIN_ROLE_ID,
    seed_tenant_super_admin,
)
from app.rbac.models import (
    PermissionRegistryRecord,
    PlatformRole,
    TenantRole,
    TenantRoleAssignment,
)
from app.rbac.registry import load_approved_registry, synchronize_permission_registry


def test_approved_registry_is_complete_and_keeps_domain_identity():
    registry = load_approved_registry()
    assert registry.version == "0.3.0-approved"
    assert len(registry.permissions) == 1089
    assert sum(p.domain.value == "platform" for p in registry.permissions.values()) == 244
    assert sum(p.domain.value == "tenant" for p in registry.permissions.values()) == 845
    assert ("platform", "access.permission_catalogue.read") in registry.permissions
    assert ("tenant", "access.permission_catalogue.read") in registry.permissions
    assert ("platform", "audit.audit_export.export") in registry.permissions
    assert ("tenant", "audit.audit_export.export") in registry.permissions


async def test_registry_sync_and_locked_roles_are_tenant_isolated(tenants):
    async with control_session() as db:
        result = await synchronize_permission_registry(db, "test-registry-sync")
        assert result["permissions"] == 1089
        assert result["inserted"] == result["updated"] == result["retired"] == 0
        assert await db.scalar(select(func.count()).select_from(PermissionRegistryRecord)) == 1089
        assert await db.scalar(
            select(func.count()).where(
                PermissionRegistryRecord.key == "access.permission_catalogue.read"
            )
        ) == 2
        platform_role = await db.get(PlatformRole, PLATFORM_SUPER_ADMIN_ROLE_ID)
        assert platform_role and platform_role.locked and platform_role.domain == "platform"

    first, second = tenants
    async with tenant_session(first["org"].schema_name) as db:
        role = await seed_tenant_super_admin(db, "test-rbac-bootstrap")
        assert role.id == TENANT_SUPER_ADMIN_ROLE_ID
        assert role.locked and role.status == "published" and role.domain == "tenant"
        assignments = (
            await db.scalars(
                select(TenantRoleAssignment).where(
                    TenantRoleAssignment.user_id == first["user"].id,
                    TenantRoleAssignment.role_id == role.id,
                )
            )
        ).all()
        assert len(assignments) == 1
        assert assignments[0].level == "Organization"
        db.add(
            TenantRole(
                id="tenant-a-only-role",
                domain="tenant",
                name="Tenant A only role",
                status="draft",
                created_by="test",
                updated_by="test",
            )
        )

    async with tenant_session(second["org"].schema_name) as db:
        assert await db.get(TenantRole, "tenant-a-only-role") is None
        assert await db.get(TenantRole, TENANT_SUPER_ADMIN_ROLE_ID) is not None
