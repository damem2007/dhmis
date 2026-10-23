from types import SimpleNamespace

from app.analytics.scope import resolve_scope
from app.identity.models import StaffLocationAssignment
from app.identity.service import (
    TENANT_SUPER_ADMIN_ROLE_ID,
    is_tenant_super_admin_role,
    legacy_module_permissions_for_role,
    permit,
    user_has_module,
)
from app.rbac.models import TenantRole, TenantRoleAssignment
from app.rbac.runtime import tenant_assignments


def test_canonical_tenant_super_admin_exposes_legacy_module_aliases():
    permissions = legacy_module_permissions_for_role(TENANT_SUPER_ADMIN_ROLE_ID)

    # These are compatibility roots used by older routers and the back-office
    # shell; they are not a substitute for action-level RBAC checks.
    assert {"dashboard", "patients", "clinical", "settings"}.issubset(permissions)


def test_tenant_super_admin_policy_is_independent_of_display_label_or_tenant():
    canonical = legacy_module_permissions_for_role(
        TENANT_SUPER_ADMIN_ROLE_ID,
        "Tenant Super Admin",
    )
    another_tenant_label = legacy_module_permissions_for_role(
        TENANT_SUPER_ADMIN_ROLE_ID,
        "Localized tenant administrator",
    )

    assert canonical == another_tenant_label


def test_tenant_super_admin_legacy_role_id_is_canonicalized():
    assert is_tenant_super_admin_role("tenant_super_admin")
    assert legacy_module_permissions_for_role("tenant_super_admin")


def test_default_role_compatibility_uses_resolved_canonical_role():
    assert "dashboard" in legacy_module_permissions_for_role("admin")
    assert "dashboard" in legacy_module_permissions_for_role("role-uuid", "admin")
    assert legacy_module_permissions_for_role("Tenant Super Admin") == set()


async def test_legacy_module_guard_honors_canonical_super_admin_id():
    actor = type("Actor", (), {"role_id": TENANT_SUPER_ADMIN_ROLE_ID, "role": "Admin"})()

    assert await permit("dashboard")(object(), actor) is actor


async def test_super_admin_module_checks_do_not_require_materialized_grants():
    user = type("User", (), {"role_id": TENANT_SUPER_ADMIN_ROLE_ID, "role": "Tenant Super Admin"})()

    assert await user_has_module(None, user, "clinical")


def test_super_admin_analytics_scope_is_tenant_wide():
    actor = type("Actor", (), {"role_id": TENANT_SUPER_ADMIN_ROLE_ID, "role": "Tenant Super Admin"})()

    scope = resolve_scope(actor)

    assert scope.profile == "organization-executive"
    assert scope.location_ids == ()
    assert scope.can_view_financial and scope.can_export


class _ScalarRows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _LegacyAssignmentDb:
    async def scalars(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        if entity is TenantRoleAssignment:
            return _ScalarRows([])
        if entity is StaffLocationAssignment:
            return _ScalarRows(
                [
                    SimpleNamespace(
                        user_id="legacy-user",
                        role="admin",
                        scope="organization",
                        location_id=None,
                        active=True,
                    )
                ]
            )
        if entity is TenantRole:
            return _ScalarRows(
                [SimpleNamespace(id="role-uuid", name="Admin", status="published")]
            )
        raise AssertionError(entity)


async def test_legacy_staff_assignment_is_evaluated_by_canonical_runtime():
    assignments = await tenant_assignments(_LegacyAssignmentDb(), "legacy-user")

    assert len(assignments) == 1
    assert assignments[0].role_id == "role-uuid"
    assert assignments[0].level.value == "Organization"
