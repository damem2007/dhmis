from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, func, select

from app.rbac.policy import (
    ApprovalPolicy,
    Assignment,
    Domain,
    Grant,
    GrantEffect,
    Risk,
    RoleStatus,
    Scope,
    allowed_actions_for_resource,
    diff_grants,
    effective_allowed_keys,
    find_conflicts,
    requires_approval,
    validate_grants,
)
from app.rbac.runtime import conditions_from_record


def condition_values(values: dict[str, Any]) -> dict[str, Any]:
    conditions = conditions_from_record(values)
    if conditions is None:
        return {}
    return {
        "step_up_mfa_minutes": conditions.step_up_mfa_minutes,
        "requires_approval": conditions.requires_approval,
        "expires_at": conditions.expires_at.isoformat() if conditions.expires_at else None,
        "ip_allow_list": list(conditions.ip_allow_list),
    }


def grant_values(item) -> dict[str, Any]:
    return {
        "permission_key": item.permission_key,
        "effect": item.effect,
        "scope": item.scope,
        "conditions": condition_values(item.conditions.model_dump(exclude_none=True)),
    }


async def assert_unique_name(db, role_model, name: str, exclude_id: str | None = None):
    query = select(role_model.id).where(
        func.lower(role_model.name) == name.strip().lower(),
        role_model.status != RoleStatus.ARCHIVED.value,
    )
    if exclude_id:
        query = query.where(role_model.id != exclude_id)
    if await db.scalar(query):
        raise HTTPException(409, "A non-archived role already uses this name")


async def role_payload(db, role, grant_model, assignment_model):
    grants = (
        await db.scalars(
            select(grant_model)
            .where(grant_model.role_id == role.id)
            .order_by(grant_model.permission_key)
        )
    ).all()
    users = await db.scalar(
        select(func.count(func.distinct(assignment_model.user_id))).where(
            assignment_model.role_id == role.id
        )
    )
    return {
        "id": role.id,
        "domain": role.domain,
        "name": role.name,
        "description": role.description,
        "status": role.status,
        "parent_id": role.parent_id,
        "locked": role.locked,
        "version": role.version,
        "user_count": users or 0,
        "permission_count": len(grants),
        "grants": [
            {
                "permission_key": grant.permission_key,
                "effect": grant.effect,
                "scope": grant.scope,
                "conditions": grant.conditions,
            }
            for grant in grants
        ],
        "created_at": role.created_at,
        "updated_at": role.updated_at,
    }


async def require_role(db, role_model, identifier: str, *, lock: bool = False):
    query = select(role_model).where(role_model.id == identifier)
    if lock:
        query = query.with_for_update()
    role = await db.scalar(query)
    if role is None:
        raise HTTPException(404, "Role not found")
    return role


def ensure_mutable(role, *, draft_only: bool = False):
    if role.locked:
        raise HTTPException(409, "Super Admin roles cannot be edited")
    if draft_only and role.status != RoleStatus.DRAFT.value:
        raise HTTPException(409, "Published role changes require a governed change request")


def direct_grants(items) -> dict[str, Grant]:
    return {
        item.permission_key: Grant(
            effect=GrantEffect(item.effect),
            scope=Scope(item.scope),
            conditions=conditions_from_record(item.conditions.model_dump(exclude_none=True)),
        )
        for item in items
    }


def clear_unmet_dependents(role, context) -> tuple[dict[str, Grant], list[str]]:
    remaining = dict(role.grants)
    cleared: list[str] = []
    while True:
        candidate = type(role)(**{**role.__dict__, "grants": remaining})
        synthetic = Assignment(
            user_id="__validation__",
            role_id=candidate.id,
            level=(
                Scope.PLATFORM
                if candidate.domain is Domain.PLATFORM
                else Scope.ORGANIZATION
            ),
        )
        remove: list[str] = []
        for key in remaining:
            permission = context.permissions.get(key)
            if permission is None or not permission.requires:
                continue
            actions = allowed_actions_for_resource(
                context.permissions_by_resource.get(permission.resource_key, []),
                [synthetic],
                type(context)(
                    permissions=context.permissions,
                    roles={**context.roles, candidate.id: candidate},
                    rules=context.rules,
                    sod_rules=context.sod_rules,
                    permissions_by_resource=context.permissions_by_resource,
                ),
            )
            if any(required not in actions for required in permission.requires):
                remove.append(key)
        if not remove:
            return remaining, cleared
        for key in remove:
            remaining.pop(key, None)
            cleared.append(key)


async def replace_role_grants(
    db,
    role,
    items,
    context,
    grant_model,
    actor_id: str,
):
    ensure_mutable(role, draft_only=True)
    requested = direct_grants(items)
    if len(requested) != len(items):
        raise HTTPException(422, "Each permission may appear only once")
    before = dict(context.roles[role.id].grants)
    candidate = context.roles[role.id]
    candidate.grants = requested
    candidate.grants, cleared = clear_unmet_dependents(candidate, context)
    context.roles[role.id] = candidate
    issues = validate_grants(candidate, context)
    if issues:
        raise HTTPException(
            422,
            {
                "message": "Role grants are invalid",
                "issues": [
                    {"key": issue.key, "code": issue.code.value, "message": issue.message}
                    for issue in issues
                ],
            },
        )
    await db.execute(delete(grant_model).where(grant_model.role_id == role.id))
    db.add_all(
        grant_model(
            role_id=role.id,
            permission_key=key,
            effect=grant.effect.value,
            scope=grant.scope.value,
            conditions={
                "step_up_mfa_minutes": grant.conditions.step_up_mfa_minutes,
                "requires_approval": grant.conditions.requires_approval,
                "expires_at": (
                    grant.conditions.expires_at.isoformat()
                    if grant.conditions and grant.conditions.expires_at
                    else None
                ),
                "ip_allow_list": list(grant.conditions.ip_allow_list),
            }
            if grant.conditions
            else {},
            created_by=actor_id,
            updated_by=actor_id,
        )
        for key, grant in candidate.grants.items()
    )
    role.version += 1
    role.updated_by = actor_id
    await db.flush()
    changes = diff_grants(before, candidate.grants)
    conflicts = find_conflicts(candidate, context)
    changed_permissions = [
        context.permissions[change.key]
        for change in changes
        if change.key in context.permissions and change.after is not None
    ]
    approval = requires_approval(
        changed_permissions,
        conflicts=len(conflicts),
        touches_locked_role=False,
        high_risk_assignment=False,
        policy=ApprovalPolicy(),
        rules=context.rules,
    )
    return {
        "changes": len(changes),
        "cleared_dependents": cleared,
        "conflicts": conflicts,
        "requires_approval_on_publish": approval,
    }


def role_requires_approval(role, context) -> tuple[bool, list[str]]:
    conflicts = find_conflicts(role, context)
    permissions = [
        context.permissions[key]
        for key in effective_allowed_keys(role, context)
        if key in context.permissions
    ]
    return (
        requires_approval(
            permissions,
            conflicts=len(conflicts),
            touches_locked_role=role.locked,
            high_risk_assignment=False,
            policy=ApprovalPolicy(),
            rules=context.rules,
        ),
        conflicts,
    )


def assignment_is_high_risk(role, context) -> bool:
    return any(
        context.permissions[key].risk >= Risk.HIGH
        for key in effective_allowed_keys(role, context)
        if key in context.permissions
    )
