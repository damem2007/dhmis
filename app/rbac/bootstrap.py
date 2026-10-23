from sqlalchemy import select

from app.identity.models import StaffLocationAssignment, StaffUser
from app.identity.service import default_role_name
from app.platform_identity.models import PlatformUser
from app.rbac.models import (
    PlatformApprovalPolicy,
    PlatformFourEyesRule,
    PlatformRole,
    PlatformRoleAssignment,
    PlatformRoleGrant,
    PlatformSoDRule,
    TenantApprovalPolicy,
    TenantFourEyesRule,
    TenantRole,
    TenantRoleAssignment,
    TenantRoleGrant,
    TenantSoDRule,
)
from app.rbac.registry import load_approved_registry

PLATFORM_SUPER_ADMIN_ROLE_ID = "platform-super-admin"
TENANT_SUPER_ADMIN_ROLE_ID = "tenant-super-admin"
APPROVAL_POLICY_ID = "approval-policy"


# Handle default approval policy for this module.
def default_approval_policy() -> dict:
    return {
        "require_role_grant_critical_or_four_eyes": True,
        "require_high_risk_assignment": True,
        "require_sod_conflict": True,
        "require_every_change": False,
        "require_superadmin_change": True,
        "approvers_needed": 1,
        "expires_after_hours": 72,
        "tenant_eligible_roles": ["tenant-owner", "tenant-super-admin"],
        "platform_eligible_roles": ["platform-super-admin"],
        "break_glass_enabled": True,
        "break_glass_requires_step_up_mfa": True,
        "break_glass_review_within_hours": 24,
    }


# Handle seed rbac governance for this module.
async def seed_rbac_governance(db, domain: str, actor_id: str = "rbac-bootstrap"):
    approved = load_approved_registry()
    if domain == "platform":
        policy_model, rule_model, sod_model = (
            PlatformApprovalPolicy,
            PlatformFourEyesRule,
            PlatformSoDRule,
        )
        scopes = {"Platform", "Both"}
    else:
        policy_model, rule_model, sod_model = (
            TenantApprovalPolicy,
            TenantFourEyesRule,
            TenantSoDRule,
        )
        scopes = {"Tenant", "Both"}
    if await db.get(policy_model, APPROVAL_POLICY_ID) is None:
        db.add(
            policy_model(
                id=APPROVAL_POLICY_ID,
                settings=default_approval_policy(),
                created_by=actor_id,
                updated_by=actor_id,
            )
        )
    existing_rules = set(await db.scalars(select(rule_model.id)))
    db.add_all(
        rule_model(
            id=item["id"],
            name=item["name"],
            scope=item["scope"],
            priority=item["priority"],
            patterns=item["patterns"],
            created_by=actor_id,
            updated_by=actor_id,
        )
        for item in approved.raw["fourEyesRules"]
        if item["scope"] in scopes and item["id"] not in existing_rules
    )
    existing_sod = set(await db.scalars(select(sod_model.id)))
    db.add_all(
        sod_model(
            id=item["id"],
            message=item["message"],
            side_a=item["sideA"],
            side_b=item["sideB"],
            created_by=actor_id,
            updated_by=actor_id,
        )
        for item in approved.raw["sodRules"]
        if item["id"] not in existing_sod
    )
    await db.flush()


# Handle seed platform super admin for this module.
async def seed_platform_super_admin(db, actor_id: str = "rbac-bootstrap") -> PlatformRole:
    from app.rbac.default_roles import default_platform_role_definitions

    await seed_rbac_governance(db, "platform", actor_id)
    registry = load_approved_registry()
    definition = default_platform_role_definitions().get(PLATFORM_SUPER_ADMIN_ROLE_ID)
    if definition is None:
        raise ValueError(
            f"default_roles.json must define {PLATFORM_SUPER_ADMIN_ROLE_ID!r}"
        )
    configured_modules = set(definition.get("modules", ()))
    active_platform_modules = {
        permission.resource_key.split(".", 1)[0]
        for permission in registry.permissions.values()
        if permission.domain.value == "platform" and permission.reviewed and not permission.retired
    }
    unknown_modules = configured_modules - active_platform_modules
    if unknown_modules:
        raise ValueError(
            "Platform Super Admin references unknown platform modules: "
            + ", ".join(sorted(unknown_modules))
        )
    missing_modules = active_platform_modules - configured_modules
    if missing_modules:
        raise ValueError(
            "default_roles.json is missing active platform modules: "
            + ", ".join(sorted(missing_modules))
        )
    role = await db.get(PlatformRole, PLATFORM_SUPER_ADMIN_ROLE_ID)
    if role is None:
        role = PlatformRole(
            id=PLATFORM_SUPER_ADMIN_ROLE_ID,
            domain="platform",
            name="Platform Super Admin",
            description="Locked platform role with every active reviewed platform permission.",
            status="published",
            locked=True,
            created_by=actor_id,
            updated_by=actor_id,
        )
        db.add(role)
        await db.flush()
    # The locked Platform Super Admin role is the reviewed control-plane
    # authority. Keep its grants synchronized so newly approved permissions,
    # including tenant onboarding activation, are effective without manual
    # role editing.
    existing_grants = {
        row.permission_key
        for row in (await db.scalars(select(PlatformRoleGrant).where(PlatformRoleGrant.role_id == role.id))).all()
    }
    db.add_all(
        PlatformRoleGrant(
            role_id=role.id,
            permission_key=permission.key,
            effect="allow",
            scope="Platform",
            created_by=actor_id,
            updated_by=actor_id,
        )
        for permission in registry.permissions.values()
        if permission.domain.value == "platform"
        and permission.reviewed
        and not permission.retired
        and permission.key not in existing_grants
    )
    await db.flush()
    # Bootstrap and MFA reconciliation pass the affected user id as
    # ``actor_id``. Do not grant the locked role to every active operator when
    # one account is being reconciled; that made newly invited operators show
    # up as Platform Super Admins as well.
    users = []
    if actor_id and actor_id != "rbac-bootstrap":
        user = await db.get(PlatformUser, actor_id)
        if user is not None and user.active:
            users = [user]
    else:
        # Schema/bootstrap reconciliation should only recover the account
        # created by the platform bootstrap flow. Invited operators must keep
        # the role selected on their invitation.
        users = (
            await db.scalars(
                select(PlatformUser).where(
                    PlatformUser.active,
                    PlatformUser.created_by == "bootstrap",
                )
            )
        ).all()
    assigned = set(
        await db.scalars(
            select(PlatformRoleAssignment.user_id).where(
                PlatformRoleAssignment.role_id == role.id
            )
        )
    )
    db.add_all(
        PlatformRoleAssignment(
            user_id=user.id,
            role_id=role.id,
            level="Platform",
            created_by=actor_id,
            updated_by=actor_id,
        )
        for user in users
        if user.id not in assigned
    )
    await db.flush()
    return role


# Synchronize the protected tenant role with the approved tenant permission
# registry. This is intentionally idempotent so policy reads can repair a
# tenant that was provisioned before a new permission was added.
async def ensure_tenant_super_admin_grants(
    db,
    actor_id: str = "rbac-superadmin-sync",
    *,
    role: TenantRole | None = None,
) -> TenantRole | None:
    sync_key = "tenant_super_admin_grants_synced"
    if getattr(db, "info", {}).get(sync_key):
        return role

    role = role or await db.get(TenantRole, TENANT_SUPER_ADMIN_ROLE_ID)
    if role is None:
        return None

    registry = load_approved_registry()
    existing_grants = {
        row.permission_key
        for row in (
            await db.scalars(
                select(TenantRoleGrant).where(TenantRoleGrant.role_id == role.id)
            )
        ).all()
    }
    added = False
    for permission in registry.permissions.values():
        if (
            permission.domain.value != "tenant"
            or not permission.reviewed
            or permission.retired
            or permission.key in existing_grants
        ):
            continue
        valid_scopes = {scope.value for scope in permission.valid_scopes}
        if "Organization" in valid_scopes:
            scope = "Organization"
        elif "Location" in valid_scopes:
            scope = "Location"
        else:
            continue
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
        existing_grants.add(permission.key)
        added = True
    if added:
        await db.flush()
    getattr(db, "info", {})[sync_key] = True
    return role


async def ensure_platform_super_admin_grants(
    db,
    actor_id: str = "rbac-superadmin-sync",
    *,
    role: PlatformRole | None = None,
) -> PlatformRole | None:
    """Keep the protected platform role aligned with approved permissions."""
    sync_key = "platform_super_admin_grants_synced"
    if getattr(db, "info", {}).get(sync_key):
        return role

    role = role or await db.get(PlatformRole, PLATFORM_SUPER_ADMIN_ROLE_ID)
    if role is None:
        return None

    registry = load_approved_registry()
    existing_grants = {
        row.permission_key
        for row in (
            await db.scalars(
                select(PlatformRoleGrant).where(
                    PlatformRoleGrant.role_id == role.id
                )
            )
        ).all()
    }
    added = False
    for permission in registry.permissions.values():
        if (
            permission.domain.value != "platform"
            or not permission.reviewed
            or permission.retired
            or permission.key in existing_grants
        ):
            continue
        db.add(
            PlatformRoleGrant(
                role_id=role.id,
                permission_key=permission.key,
                effect="allow",
                scope="Platform",
                created_by=actor_id,
                updated_by=actor_id,
            )
        )
        existing_grants.add(permission.key)
        added = True
    if added:
        await db.flush()
    getattr(db, "info", {})[sync_key] = True
    return role


# Handle seed tenant super admin for this module.
async def seed_tenant_super_admin(
    db,
    actor_id: str = "rbac-bootstrap",
    *,
    sync_legacy: bool = False,
    assign_first_legacy_admin: bool = True,
    include_default_roles: bool = True,
) -> TenantRole:
    from app.rbac.default_roles import seed_default_tenant_roles, sync_legacy_assignments

    default_roles = (
        await seed_default_tenant_roles(db, actor_id)
        if include_default_roles
        else {}
    )
    await seed_rbac_governance(db, "tenant", actor_id)
    role = await db.get(TenantRole, TENANT_SUPER_ADMIN_ROLE_ID)
    if role is None:
        role = TenantRole(
            id=TENANT_SUPER_ADMIN_ROLE_ID,
            domain="tenant",
            name="Tenant Super Admin",
            description="Locked tenant role with every active reviewed tenant permission.",
            status="published",
            locked=True,
            created_by=actor_id,
            updated_by=actor_id,
        )
        db.add(role)
        await db.flush()
    else:
        # The protected setup role is canonical by identifier. Normalize its
        # metadata on every bootstrap pass so a partially provisioned tenant
        # cannot remain unpublished, unlocked, or attached to another domain.
        role.domain = "tenant"
        role.name = "Tenant Super Admin"
        role.status = "published"
        role.locked = True
        role.description = (
            "Locked tenant role with every active reviewed tenant permission."
        )
        role.updated_by = actor_id
    # The protected setup role is intentionally broader than the editable
    # default roles. Keep its canonical grants synchronized with every active
    # reviewed tenant permission so onboarding administrators can configure a
    # tenant immediately after accepting the invitation.
    await ensure_tenant_super_admin_grants(db, actor_id, role=role)
    assigned = set(
        await db.scalars(
            select(TenantRoleAssignment.user_id).where(
                TenantRoleAssignment.role_id == role.id,
                TenantRoleAssignment.level == "Organization",
            )
        )
    )
    legacy_admins = []
    if assign_first_legacy_admin:
        legacy_admins = (
            await db.scalars(
                select(StaffLocationAssignment).where(
                    StaffLocationAssignment.active,
                    StaffLocationAssignment.scope == "organization",
                    StaffLocationAssignment.role == default_role_name(),
                )
                .order_by(StaffLocationAssignment.created_at, StaffLocationAssignment.id)
            )
        ).all()
    bootstrap_user_id = legacy_admins[0].user_id if legacy_admins else None
    if not assigned and bootstrap_user_id is None:
        # Tenants reconciled to canonical RBAC may no longer have a matching
        # legacy location row. Keep the same first organization-admin rule by
        # falling back to the canonical assignment projection.
        bootstrap_user_id = await db.scalar(
            select(TenantRoleAssignment.user_id)
            .join(TenantRole, TenantRole.id == TenantRoleAssignment.role_id)
            .where(
                TenantRoleAssignment.level == "Organization",
                TenantRoleAssignment.location_id.is_(None),
                TenantRole.status == "published",
                TenantRole.name == default_role_name("organization"),
            )
            .order_by(TenantRoleAssignment.created_at, TenantRoleAssignment.id)
            .limit(1)
        )
    if not assigned and bootstrap_user_id:
        db.add(
            TenantRoleAssignment(
                user_id=bootstrap_user_id,
                role_id=role.id,
                level="Organization",
                created_by=actor_id,
                updated_by=actor_id,
            )
        )
        promoted_user = await db.get(StaffUser, bootstrap_user_id)
        if promoted_user is not None:
            promoted_user.role_id = role.id
            promoted_user.role = role.name
    await db.flush()
    # Canonical role assignments are authoritative. Legacy assignment rows are
    # bridged only by an explicit caller (for example, invite acceptance for a
    # newly created account), never as a broad bootstrap side effect.
    if sync_legacy:
        await sync_legacy_assignments(db, default_roles, actor_id)
    return role
