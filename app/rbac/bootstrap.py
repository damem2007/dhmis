from sqlalchemy import select

from app.identity.models import StaffLocationAssignment
from app.identity.service import organization_role_names
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
    TenantSoDRule,
)
from app.rbac.registry import load_approved_registry

PLATFORM_SUPER_ADMIN_ROLE_ID = "platform-super-admin"
TENANT_SUPER_ADMIN_ROLE_ID = "tenant-super-admin"
APPROVAL_POLICY_ID = "approval-policy"


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


async def seed_platform_super_admin(db, actor_id: str = "rbac-bootstrap") -> PlatformRole:
    await seed_rbac_governance(db, "platform", actor_id)
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
        for permission in load_approved_registry().permissions.values()
        if permission.domain.value == "platform"
        and permission.reviewed
        and not permission.retired
        and permission.key not in existing_grants
    )
    await db.flush()
    users = (await db.scalars(select(PlatformUser).where(PlatformUser.active))).all()
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


async def seed_tenant_super_admin(
    db,
    actor_id: str = "rbac-bootstrap",
    *,
    sync_legacy: bool = False,
) -> TenantRole:
    from app.rbac.default_roles import seed_default_tenant_roles, sync_legacy_assignments

    default_roles = await seed_default_tenant_roles(db, actor_id)
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
    legacy_admins = (
        await db.scalars(
            select(StaffLocationAssignment).where(
                StaffLocationAssignment.active,
                StaffLocationAssignment.scope == "organization",
                StaffLocationAssignment.role.in_(organization_role_names()),
            )
        )
    ).all()
    assigned = set(
        await db.scalars(
            select(TenantRoleAssignment.user_id).where(
                TenantRoleAssignment.role_id == role.id,
                TenantRoleAssignment.level == "Organization",
            )
        )
    )
    db.add_all(
        TenantRoleAssignment(
            user_id=assignment.user_id,
            role_id=role.id,
            level="Organization",
            created_by=actor_id,
            updated_by=actor_id,
        )
        for assignment in legacy_admins
        if assignment.user_id not in assigned
    )
    await db.flush()
    # Canonical role assignments are authoritative. Legacy assignment rows are
    # bridged only by an explicit caller (for example, invite acceptance for a
    # newly created account), never as a broad bootstrap side effect.
    if sync_legacy:
        await sync_legacy_assignments(db, default_roles, actor_id)
    return role
