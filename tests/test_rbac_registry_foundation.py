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


# Exercise or prepare test approved registry is complete and keeps domain identity for this test module.
def test_approved_registry_is_complete_and_keeps_domain_identity():
    registry = load_approved_registry()
    assert registry.version == "0.4.0-approved"
    assert len(registry.permissions) == 1185
    assert sum(p.domain.value == "platform" for p in registry.permissions.values()) == 270
    assert sum(p.domain.value == "tenant" for p in registry.permissions.values()) == 915
    assert ("platform", "access.permission_catalogue.read") in registry.permissions
    assert ("tenant", "access.permission_catalogue.read") in registry.permissions
    assert ("platform", "audit.audit_export.export") in registry.permissions
    assert ("tenant", "audit.audit_export.export") in registry.permissions
    quick_chart = registry.permissions[("tenant", "clinical.quick_chart_set.use")]
    assert {scope.value for scope in quick_chart.valid_scopes} == {
        "Organization",
        "Location",
    }
    assert ("tenant", "clinical.quick_chart_set.archive") in registry.permissions
    assert ("tenant", "clinical.code_library.deactivate") in registry.permissions
    assert {
        (domain, "security.password_policy.read")
        for domain in ("platform", "tenant")
    } <= set(registry.permissions)
    assert {
        (domain, "security.password_policy.update")
        for domain in ("platform", "tenant")
    } <= set(registry.permissions)
    assert all(
        not registry.permissions[(domain, f"security.password_policy.{action}")].default_grant
        for domain in ("platform", "tenant")
        for action in ("read", "update")
    )
    assert {
        ("tenant", f"billing.discount.{action}")
        for action in ("read", "create", "update", "archive")
    } <= set(registry.permissions)
    encounter_approval = registry.permissions[("tenant", "clinical.clinical_encounter.approve")]
    assert not encounter_approval.default_grant
    assert encounter_approval.requires == ("read",)
    assert all(
        not permission.default_grant
        for (domain, key), permission in registry.permissions.items()
        if domain == "tenant"
        and tuple(key.split(".", 2)[0:2])
        in {
            ("clinical", "quick_chart_set"),
            ("clinical", "treatment_catalogue_item"),
            ("clinical", "chart_settings"),
            ("clinical", "code_library"),
            ("reports", "quote"),
        }
    )


# Exercise or prepare test registry sync and locked roles are tenant isolated for this test module.
async def test_registry_sync_and_locked_roles_are_tenant_isolated(tenants):
    async with control_session() as db:
        result = await synchronize_permission_registry(db, "test-registry-sync")
        assert result["permissions"] == 1185
        assert result["inserted"] == result["updated"] == result["retired"] == 0
        assert await db.scalar(select(func.count()).select_from(PermissionRegistryRecord)) == 1185
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
