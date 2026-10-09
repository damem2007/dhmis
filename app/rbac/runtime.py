from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.rbac.models import (
    PlatformFourEyesRule,
    PlatformRole,
    PlatformRoleAssignment,
    PlatformRoleGrant,
    PlatformSoDRule,
    TenantFourEyesRule,
    TenantRole,
    TenantRoleAssignment,
    TenantRoleGrant,
    TenantSoDRule,
)
from app.rbac.policy import (
    Assignment,
    Conditions,
    Decision,
    Domain,
    FourEyesRule,
    FourEyesScope,
    Grant,
    GrantEffect,
    PolicyContext,
    Role,
    RoleStatus,
    Scope,
    SoDRule,
    decide,
)
from app.rbac.registry import ApprovedRegistry, load_approved_registry


def approved_permissions(
    domain: Domain,
    registry: ApprovedRegistry | None = None,
):
    approved = registry or load_approved_registry()
    return {
        key: permission
        for (permission_domain, key), permission in approved.permissions.items()
        if permission_domain == domain.value
    }


def approved_rules(registry: ApprovedRegistry | None = None) -> list[FourEyesRule]:
    approved = registry or load_approved_registry()
    return [
        FourEyesRule(
            id=item["id"],
            name=item["name"],
            scope=FourEyesScope(item["scope"]),
            priority=int(item["priority"]),
            patterns=tuple(item["patterns"]),
        )
        for item in approved.raw.get("fourEyesRules", [])
    ]


def approved_sod_rules(registry: ApprovedRegistry | None = None) -> list[SoDRule]:
    approved = registry or load_approved_registry()
    return [
        SoDRule(
            id=item["id"],
            message=item["message"],
            side_a=tuple(item["sideA"]),
            side_b=tuple(item["sideB"]),
        )
        for item in approved.raw.get("sodRules", [])
    ]


def _condition_value(values: dict[str, Any], snake: str, camel: str):
    return values.get(snake, values.get(camel))


def conditions_from_record(values: dict[str, Any] | None) -> Conditions | None:
    if not values:
        return None
    expires_at = _condition_value(values, "expires_at", "expiresAt")
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return Conditions(
        step_up_mfa_minutes=_condition_value(
            values, "step_up_mfa_minutes", "stepUpMfaMinutes"
        ),
        requires_approval=_condition_value(
            values, "requires_approval", "requiresApproval"
        ),
        expires_at=expires_at,
        ip_allow_list=tuple(
            _condition_value(values, "ip_allow_list", "ipAllowList") or ()
        ),
    )


def _roles_from_records(role_rows, grant_rows, domain: Domain) -> dict[str, Role]:
    grants_by_role: dict[str, dict[str, Grant]] = {}
    for row in grant_rows:
        grants_by_role.setdefault(row.role_id, {})[row.permission_key] = Grant(
            effect=GrantEffect(row.effect),
            scope=Scope(row.scope),
            conditions=conditions_from_record(row.conditions),
        )
    return {
        row.id: Role(
            id=row.id,
            name=row.name,
            domain=domain,
            status=RoleStatus(row.status),
            grants=grants_by_role.get(row.id, {}),
            description=row.description,
            parent_id=row.parent_id,
            locked=row.locked,
            version=row.version,
        )
        for row in role_rows
    }


def _context(domain: Domain, role_rows, grant_rows, rule_rows=None, sod_rows=None) -> PolicyContext:
    approved = load_approved_registry()
    return PolicyContext(
        permissions=approved_permissions(domain, approved),
        roles=_roles_from_records(role_rows, grant_rows, domain),
        rules=(
            [
                FourEyesRule(
                    id=row.id,
                    name=row.name,
                    scope=FourEyesScope(row.scope),
                    priority=row.priority,
                    patterns=tuple(row.patterns),
                )
                for row in rule_rows
            ]
            if rule_rows is not None
            else approved_rules(approved)
        ),
        sod_rules=(
            [
                SoDRule(
                    id=row.id,
                    message=row.message,
                    side_a=tuple(row.side_a),
                    side_b=tuple(row.side_b),
                )
                for row in sod_rows
            ]
            if sod_rows is not None
            else approved_sod_rules(approved)
        ),
    )


async def tenant_policy_context(db) -> PolicyContext:
    roles = (await db.scalars(select(TenantRole))).all()
    grants = (await db.scalars(select(TenantRoleGrant))).all()
    rules = (await db.scalars(select(TenantFourEyesRule))).all()
    sod = (await db.scalars(select(TenantSoDRule))).all()
    return _context(Domain.TENANT, roles, grants, rules, sod)


async def platform_policy_context(db) -> PolicyContext:
    roles = (await db.scalars(select(PlatformRole))).all()
    grants = (await db.scalars(select(PlatformRoleGrant))).all()
    rules = (await db.scalars(select(PlatformFourEyesRule))).all()
    sod = (await db.scalars(select(PlatformSoDRule))).all()
    return _context(Domain.PLATFORM, roles, grants, rules, sod)


def _assignment(row) -> Assignment:
    return Assignment(
        user_id=row.user_id,
        role_id=row.role_id,
        level=Scope(row.level),
        location_id=row.location_id,
        expires_at=row.expires_at,
    )


async def tenant_assignments(
    db,
    user_id: str,
    selected_location_id: str | None = None,
) -> list[Assignment]:
    query = select(TenantRoleAssignment).where(TenantRoleAssignment.user_id == user_id)
    rows = (await db.scalars(query)).all()
    return [
        _assignment(row)
        for row in rows
        if row.level == Scope.ORGANIZATION.value
        or selected_location_id is None
        or row.location_id == selected_location_id
    ]


async def platform_assignments(db, user_id: str) -> list[Assignment]:
    rows = (
        await db.scalars(
            select(PlatformRoleAssignment).where(
                PlatformRoleAssignment.user_id == user_id
            )
        )
    ).all()
    return [_assignment(row) for row in rows]


async def decide_tenant(
    db,
    user_id: str,
    permission_key: str,
    *,
    selected_location_id: str | None = None,
    mfa_age_minutes: int | None = None,
    current_ip: str | None = None,
) -> Decision:
    context = await tenant_policy_context(db)
    assignments = await tenant_assignments(db, user_id, selected_location_id)
    return decide(
        permission_key,
        assignments,
        context,
        mfa_age_minutes=mfa_age_minutes,
        current_ip=current_ip,
    )


async def decide_platform(
    db,
    user_id: str,
    permission_key: str,
    *,
    mfa_age_minutes: int | None = None,
    current_ip: str | None = None,
) -> Decision:
    context = await platform_policy_context(db)
    assignments = await platform_assignments(db, user_id)
    return decide(
        permission_key,
        assignments,
        context,
        mfa_age_minutes=mfa_age_minutes,
        current_ip=current_ip,
    )
