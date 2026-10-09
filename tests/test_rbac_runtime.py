from app.core.database import tenant_session
from app.rbac.bootstrap import seed_tenant_super_admin
from app.rbac.policy import (
    Assignment,
    Domain,
    Grant,
    GrantEffect,
    PolicyContext,
    Role,
    RoleStatus,
    Scope,
    decide,
)
from app.rbac.runtime import (
    approved_permissions,
    approved_rules,
    approved_sod_rules,
    decide_tenant,
)


def _role(role_id: str, grants: dict, *, parent_id: str | None = None):
    return Role(
        id=role_id,
        name=role_id,
        domain=Domain.TENANT,
        status=RoleStatus.PUBLISHED,
        grants=grants,
        parent_id=parent_id,
    )


def _context(*roles: Role):
    return PolicyContext(
        permissions=approved_permissions(Domain.TENANT),
        roles={role.id: role for role in roles},
        rules=approved_rules(),
        sod_rules=approved_sod_rules(),
    )


def test_domain_contexts_preserve_shared_keys_without_cross_domain_access():
    tenant = approved_permissions(Domain.TENANT)
    platform = approved_permissions(Domain.PLATFORM)

    assert len(tenant) == 845
    assert len(platform) == 244
    assert tenant["access.permission_catalogue.read"].domain is Domain.TENANT
    assert platform["access.permission_catalogue.read"].domain is Domain.PLATFORM
    assert "access.platform_user.read" not in tenant
    assert "access.tenant_role.read" not in platform


def test_decision_enforces_inheritance_deny_dependencies_and_scope():
    allow_read = Grant(GrantEffect.ALLOW, Scope.ORGANIZATION)
    parent = _role(
        "parent",
        {
            "billing.payment.read": allow_read,
            "billing.payment.update": allow_read,
            "billing.payment.refund": allow_read,
        },
    )
    child = _role("child", {}, parent_id=parent.id)
    assignment = Assignment("user", child.id, Scope.LOCATION, "location-a")
    inherited = decide("billing.payment.refund", [assignment], _context(parent, child))

    assert inherited.allowed
    assert inherited.reach is Scope.LOCATION
    assert inherited.needs_approval

    deny = _role(
        "deny",
        {"billing.payment.refund": Grant(GrantEffect.DENY, Scope.ORGANIZATION)},
    )
    denied = decide(
        "billing.payment.refund",
        [assignment, Assignment("user", deny.id, Scope.ORGANIZATION)],
        _context(parent, child, deny),
    )
    assert not denied.allowed
    assert "explicitly denies" in " ".join(denied.trace)

    refund_only = _role(
        "refund-only",
        {"billing.payment.refund": allow_read},
    )
    missing_dependency = decide(
        "billing.payment.refund",
        [Assignment("user", refund_only.id, Scope.ORGANIZATION)],
        _context(refund_only),
    )
    assert not missing_dependency.allowed
    assert "missing dependency: read, update" in missing_dependency.trace[-1]

    relationship = _role(
        "relationship",
        {"patients.patient_profile.read": Grant(GrantEffect.ALLOW, Scope.ASSIGNED)},
    )
    filtered = decide(
        "patients.patient_profile.read",
        [Assignment("user", relationship.id, Scope.ORGANIZATION)],
        _context(relationship),
    )
    assert filtered.allowed
    assert filtered.reach is Scope.ORGANIZATION
    assert filtered.filter_scope is Scope.ASSIGNED


async def test_persisted_tenant_context_defaults_to_deny_and_is_tenant_isolated(tenants):
    first, second = tenants
    async with tenant_session(first["org"].schema_name) as db:
        from app.rbac.bootstrap import TENANT_SUPER_ADMIN_ROLE_ID
        from app.rbac.models import TenantRoleAssignment

        await db.execute(
            TenantRoleAssignment.__table__.delete().where(
                TenantRoleAssignment.user_id == first["front"].id,
                TenantRoleAssignment.role_id == TENANT_SUPER_ADMIN_ROLE_ID,
            )
        )
        await seed_tenant_super_admin(db, "test-runtime")
        allowed = await decide_tenant(
            db,
            first["user"].id,
            "access.permission_catalogue.read",
        )
        unassigned = await decide_tenant(
            db,
            first["front"].id,
            "access.permission_catalogue.read",
        )
        cross_tenant = await decide_tenant(
            db,
            second["user"].id,
            "access.permission_catalogue.read",
        )
        wrong_domain = await decide_tenant(
            db,
            first["user"].id,
            "access.platform_user.read",
        )

        assert allowed.allowed
        assert not unassigned.allowed
        assert not cross_tenant.allowed
        assert not wrong_domain.allowed
        assert wrong_domain.trace == ("unknown permission",)


async def test_tenant_permission_api_uses_canonical_domain_guard(client, tenants):
    tenant = tenants[0]
    async with tenant_session(tenant["org"].schema_name) as db:
        from app.rbac.bootstrap import TENANT_SUPER_ADMIN_ROLE_ID
        from app.rbac.models import TenantRoleAssignment

        await db.execute(
            TenantRoleAssignment.__table__.delete().where(
                TenantRoleAssignment.user_id == tenant["front"].id,
                TenantRoleAssignment.role_id == TENANT_SUPER_ADMIN_ROLE_ID,
            )
        )
        await seed_tenant_super_admin(db, "test-api")

    catalogue = await client.get(
        "/v1/rbac/permissions?domain=tenant&size=10",
        headers=tenant["headers"],
    )
    assert catalogue.status_code == 200
    assert catalogue.json()["total"] == 845
    assert all(item["domain"] == "tenant" for item in catalogue.json()["items"])

    rejected_domain = await client.get(
        "/v1/rbac/permissions?domain=platform",
        headers=tenant["headers"],
    )
    assert rejected_domain.status_code == 403

    denied = await client.get(
        "/v1/rbac/permissions?domain=tenant",
        headers=tenant["front_headers"],
    )
    assert denied.status_code == 403

    check = await client.get(
        "/v1/rbac/check?key=access.permission_catalogue.read",
        headers=tenant["headers"],
    )
    assert check.status_code == 200
    assert check.json()["allowed"] is True
