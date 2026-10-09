import time
from datetime import UTC, datetime
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import AwareDatetime, BaseModel, Field, model_validator
from sqlalchemy import delete, func, or_, select

from app.core.audit import audit
from app.core.database import control_session, organization_session
from app.identity.models import StaffUser
from app.identity.service import Actor, current_actor
from app.organizations.models import Location
from app.platform_identity.models import PlatformUser
from app.platform_identity.service import PlatformActor, current_platform, platform_audit
from app.rbac.dependencies import permit_platform, permit_tenant
from app.rbac.management import (
    assert_unique_name,
    assignment_is_high_risk,
    direct_grants,
    ensure_mutable,
    replace_role_grants,
    require_role,
    role_payload,
    role_requires_approval,
)
from app.rbac.models import (
    PlatformApprovalPolicy,
    PlatformChangeDecision,
    PlatformChangeNotificationReceipt,
    PlatformChangeRequest,
    PlatformFourEyesRule,
    PlatformPolicyVersion,
    PlatformRole,
    PlatformRoleAssignment,
    PlatformRoleGrant,
    TenantApprovalPolicy,
    TenantChangeDecision,
    TenantChangeNotificationReceipt,
    TenantChangeRequest,
    TenantFourEyesRule,
    TenantPolicyVersion,
    TenantRole,
    TenantRoleAssignment,
    TenantRoleGrant,
)
from app.rbac.policy import (
    Decision,
    Domain,
    RoleStatus,
    active_assignments,
    four_eyes_stats,
    overlapping_rule_matches,
    validate_grants,
)
from app.rbac.runtime import (
    approved_permissions,
    decide_platform,
    decide_tenant,
    platform_assignments,
    platform_policy_context,
    tenant_assignments,
    tenant_policy_context,
)
from app.rbac.workflow import (
    create_governance_change_request,
    create_role_change_request,
    decide_request,
    expire_requests,
    load_approval_policy,
    request_payload,
    withdraw_request,
)

router = APIRouter(tags=["Roles and access"])

PAGE_SIZES = {10, 25, 50}


class RoleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=1000)
    parent_id: str | None = Field(default=None, max_length=36)
    copy_from_id: str | None = Field(default=None, max_length=36)


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    parent_id: str | None = Field(default=None, max_length=36)
    version: int = Field(ge=1)


class GrantConditions(BaseModel):
    step_up_mfa_minutes: int | None = Field(default=None, ge=0, le=1440)
    requires_approval: bool | None = None
    expires_at: AwareDatetime | None = None
    ip_allow_list: list[str] = Field(default_factory=list, max_length=100)


class GrantInput(BaseModel):
    permission_key: str = Field(min_length=5, max_length=180)
    effect: str = Field(pattern="^(allow|deny)$")
    scope: str = Field(pattern="^(Platform|Organization|Location|Assigned|Own)$")
    conditions: GrantConditions = Field(default_factory=GrantConditions)


class GrantSet(BaseModel):
    version: int = Field(ge=1)
    grants: list[GrantInput] = Field(max_length=1200)


class RoleAssignmentInput(BaseModel):
    user_id: str = Field(min_length=1, max_length=36)
    role_id: str = Field(min_length=1, max_length=36)
    level: str = Field(pattern="^(Platform|Organization|Location)$")
    location_id: str | None = Field(default=None, max_length=36)
    expires_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def valid_reach(self):
        if self.level == "Location" and not self.location_id:
            raise ValueError("Location assignments require location_id")
        if self.level != "Location" and self.location_id:
            raise ValueError("Only Location assignments may include location_id")
        return self


class RoleChangeInput(BaseModel):
    version: int = Field(ge=1)
    grants: list[GrantInput] = Field(max_length=1200)
    publish: bool = False
    reason: str = Field(min_length=8, max_length=1000)
    acknowledge_conflicts: bool = False
    break_glass: bool = False


class RequestDecisionInput(BaseModel):
    comment: str = Field(default="", max_length=2000)


class ApprovalPolicyChangeInput(BaseModel):
    settings: dict
    reason: str = Field(min_length=8, max_length=1000)


class FourEyesRuleInput(BaseModel):
    id: str = Field(min_length=1, max_length=80, pattern="^[a-z0-9][a-z0-9-]*$")
    name: str = Field(min_length=3, max_length=180)
    scope: str = Field(pattern="^(Off|Tenant|Platform|Both)$")
    priority: int = Field(gt=0, le=100000)
    patterns: list[str] = Field(min_length=1, max_length=100)


class FourEyesRulesChangeInput(BaseModel):
    rules: list[FourEyesRuleInput] = Field(max_length=500)
    reason: str = Field(min_length=8, max_length=1000)


async def tenant_role_lifecycle_actor(
    action: str,
    request: Request,
    actor: Actor = Depends(current_actor),
):
    permission = (
        "access.tenant_role.archive"
        if action == "archive"
        else "access.tenant_role.update"
    )
    return await permit_tenant(permission, workflow_handles_approval=True)(request, actor)


async def platform_role_lifecycle_actor(
    action: str,
    request: Request,
    actor: PlatformActor = Depends(current_platform),
):
    permission = (
        "access.platform_role.archive"
        if action == "archive"
        else "access.platform_role.update"
    )
    return await permit_platform(permission, workflow_handles_approval=True)(request, actor)


def _page(values: list[dict], page: int, size: int):
    if size not in PAGE_SIZES:
        raise HTTPException(422, "Page size must be 10, 25, or 50")
    total = len(values)
    start = (page - 1) * size
    return {
        "items": values[start : start + size],
        "page": page,
        "size": size,
        "total": total,
        "pages": (total + size - 1) // size,
    }


def _permission_row(permission):
    return {
        "key": permission.key,
        "domain": permission.domain.value,
        "module_id": permission.module_id,
        "module_name": permission.module_name,
        "resource_key": permission.resource_key,
        "resource_name": permission.resource_name,
        "action": permission.action,
        "group": permission.group.value,
        "risk": int(permission.risk),
        "restricted": permission.restricted,
        "reviewed": permission.reviewed,
        "retired": permission.retired,
        "requires": list(permission.requires),
        "valid_scopes": [scope.value for scope in permission.valid_scopes],
    }


def _catalogue(
    domain: Domain,
    page: int,
    size: int,
    module: str | None,
    search: str | None,
    reviewed: bool | None,
):
    needle = (search or "").strip().lower()
    rows = []
    for permission in approved_permissions(domain).values():
        if module and permission.module_id != module:
            continue
        if reviewed is not None and permission.reviewed is not reviewed:
            continue
        haystack = " ".join(
            (permission.key, permission.module_name, permission.resource_name, permission.action)
        ).lower()
        if needle and needle not in haystack:
            continue
        rows.append(_permission_row(permission))
    rows.sort(key=lambda item: (item["module_id"], item["resource_key"], item["action"]))
    return _page(rows, page, size)


def _decision_row(permission_key: str, decision: Decision):
    return {
        "permission_key": permission_key,
        "allowed": decision.allowed,
        "reach": decision.reach.value if decision.reach else None,
        "filter_scope": decision.filter_scope.value if decision.filter_scope else None,
        "needs_approval": decision.needs_approval,
        "needs_step_up": decision.needs_step_up,
        "governing_rule_id": decision.governing_rule_id,
        "matching_rules": [
            {
                "rule_id": match.rule_id,
                "rule_name": match.rule_name,
                "priority": match.priority,
                "governs": match.governs,
            }
            for match in decision.matching_rules
        ],
        "trace": list(decision.trace),
    }


def _policy_payload(context, policy, page: int, size: int):
    rules = sorted(context.rules, key=lambda rule: (rule.priority, rule.id))
    rule_rows = []
    for rule in rules:
        stats = four_eyes_stats(rule, context.permissions, rules)
        rule_rows.append(
            {
                "id": rule.id,
                "name": rule.name,
                "scope": rule.scope.value,
                "priority": rule.priority,
                "patterns": list(rule.patterns),
                "matches": stats.matches,
                "governed": stats.governed,
                "overlaps": stats.overlaps,
            }
        )
    overlaps = []
    for key, matches in overlapping_rule_matches(context.permissions, rules).items():
        permission = context.permissions[key]
        overlaps.append(
            {
                "permission_key": key,
                "label": f"{permission.resource_name} · {permission.action.replace('_', ' ')}",
                "match_count": len(matches),
                "rules": [
                    {
                        "id": match.rule_id,
                        "name": match.rule_name,
                        "priority": match.priority,
                        "governs": match.governs,
                    }
                    for match in matches
                ],
            }
        )
    overlaps.sort(key=lambda item: item["permission_key"])
    awaiting_review = [
        _permission_row(permission)
        for permission in context.permissions.values()
        if not permission.reviewed and not permission.retired
    ]
    awaiting_review.sort(key=lambda item: item["key"])
    return {
        "settings": asdict(policy),
        "rules": _page(rule_rows, page, size),
        "overlaps": overlaps,
        "awaiting_review": awaiting_review,
    }


@router.get("/rbac/permissions")
async def tenant_permissions(
    domain: str = Query(default="tenant", pattern="^(tenant|platform)$"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10),
    module: str | None = None,
    search: str | None = None,
    reviewed: bool | None = None,
    actor: Actor = Depends(permit_tenant("access.permission_catalogue.read")),
):
    if domain != Domain.TENANT.value:
        raise HTTPException(403, "Tenant identities cannot inspect platform permissions")
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        audit(db, actor.user_id, "rbac.permissions.read", "permission_catalogue")
    return _catalogue(Domain.TENANT, page, size, module, search, reviewed)


@router.get("/platform/rbac/permissions")
async def platform_permissions(
    domain: str = Query(default="platform", pattern="^(tenant|platform)$"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10),
    module: str | None = None,
    search: str | None = None,
    reviewed: bool | None = None,
    actor: PlatformActor = Depends(permit_platform("access.permission_catalogue.read")),
):
    if domain != Domain.PLATFORM.value:
        raise HTTPException(403, "Platform identities cannot inspect tenant permissions here")
    async with control_session() as db:
        platform_audit(
            db,
            actor.user_id,
            "platform-rbac.permissions.read",
            details={"domain": domain},
        )
    return _catalogue(Domain.PLATFORM, page, size, module, search, reviewed)


@router.get("/rbac/policy")
async def tenant_policy(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10),
    actor: Actor = Depends(permit_tenant("access.tenant_role.read")),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        context = await tenant_policy_context(db)
        policy = await load_approval_policy(db, TenantApprovalPolicy)
        audit(db, actor.user_id, "rbac.policy.read", "approval_policy")
        return _policy_payload(context, policy, page, size)


@router.get("/platform/rbac/policy")
async def platform_policy(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10),
    actor: PlatformActor = Depends(permit_platform("access.platform_role.read")),
):
    async with control_session() as db:
        context = await platform_policy_context(db)
        policy = await load_approval_policy(db, PlatformApprovalPolicy)
        platform_audit(db, actor.user_id, "platform-rbac.policy.read")
        return _policy_payload(context, policy, page, size)


@router.put("/rbac/policy", status_code=202)
async def change_tenant_policy(
    body: ApprovalPolicyChangeInput,
    actor: Actor = Depends(
        permit_tenant("access.tenant_role.update", workflow_handles_approval=True)
    ),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        row, created = await create_governance_change_request(
            db,
            kind="approval-policy",
            patch={"resource": "approval-policy", "settings": body.settings},
            reason=body.reason,
            maker_id=actor.user_id,
            domain=Domain.TENANT,
            request_model=TenantChangeRequest,
            policy_model=TenantApprovalPolicy,
        )
        audit(
            db,
            actor.user_id,
            "rbac.policy.change-requested",
            "approval_policy",
            row.id,
            created=created,
        )
        return await request_payload(db, row, TenantChangeDecision)


@router.put("/platform/rbac/policy", status_code=202)
async def change_platform_policy(
    body: ApprovalPolicyChangeInput,
    actor: PlatformActor = Depends(
        permit_platform("access.platform_role.update", workflow_handles_approval=True)
    ),
):
    async with control_session() as db:
        row, created = await create_governance_change_request(
            db,
            kind="approval-policy",
            patch={"resource": "approval-policy", "settings": body.settings},
            reason=body.reason,
            maker_id=actor.user_id,
            domain=Domain.PLATFORM,
            request_model=PlatformChangeRequest,
            policy_model=PlatformApprovalPolicy,
        )
        platform_audit(
            db,
            actor.user_id,
            "platform-rbac.policy.change-requested",
            details={"request_id": row.id, "created": created},
        )
        return await request_payload(db, row, PlatformChangeDecision)


@router.put("/rbac/four-eyes-rules", status_code=202)
async def change_tenant_four_eyes_rules(
    body: FourEyesRulesChangeInput,
    actor: Actor = Depends(
        permit_tenant("access.tenant_role.update", workflow_handles_approval=True)
    ),
):
    values = [rule.model_dump() for rule in body.rules]
    if any(rule["scope"] == "Platform" for rule in values):
        raise HTTPException(422, "Tenant policy cannot create a Platform-only rule")
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        row, created = await create_governance_change_request(
            db,
            kind="four-eyes-rules",
            patch={"resource": "four-eyes-rules", "rules": values},
            reason=body.reason,
            maker_id=actor.user_id,
            domain=Domain.TENANT,
            request_model=TenantChangeRequest,
            policy_model=TenantApprovalPolicy,
        )
        audit(
            db,
            actor.user_id,
            "rbac.four-eyes-rules.change-requested",
            "four_eyes_rules",
            row.id,
            created=created,
        )
        return await request_payload(db, row, TenantChangeDecision)


@router.put("/platform/rbac/four-eyes-rules", status_code=202)
async def change_platform_four_eyes_rules(
    body: FourEyesRulesChangeInput,
    actor: PlatformActor = Depends(
        permit_platform("access.platform_role.update", workflow_handles_approval=True)
    ),
):
    values = [rule.model_dump() for rule in body.rules]
    if any(rule["scope"] == "Tenant" for rule in values):
        raise HTTPException(422, "Platform policy cannot create a Tenant-only rule")
    async with control_session() as db:
        row, created = await create_governance_change_request(
            db,
            kind="four-eyes-rules",
            patch={"resource": "four-eyes-rules", "rules": values},
            reason=body.reason,
            maker_id=actor.user_id,
            domain=Domain.PLATFORM,
            request_model=PlatformChangeRequest,
            policy_model=PlatformApprovalPolicy,
        )
        platform_audit(
            db,
            actor.user_id,
            "platform-rbac.four-eyes-rules.change-requested",
            details={"request_id": row.id, "created": created},
        )
        return await request_payload(db, row, PlatformChangeDecision)


@router.get("/rbac/check")
async def tenant_check(
    request: Request,
    key: str = Query(min_length=5, max_length=180),
    user_id: str | None = None,
    actor: Actor = Depends(permit_tenant("access.staff_role_assignment.read")),
):
    subject_id = user_id or actor.user_id
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        decision = await decide_tenant(
            db,
            subject_id,
            key,
            selected_location_id=actor.selected_location_id,
            current_ip=request.client.host if request.client else None,
        )
        audit(
            db,
            actor.user_id,
            "rbac.effective-access.read",
            "staff",
            subject_id,
            permission_key=key,
        )
    return _decision_row(key, decision)


@router.get("/platform/rbac/check")
async def platform_check(
    request: Request,
    key: str = Query(min_length=5, max_length=180),
    user_id: str | None = None,
    actor: PlatformActor = Depends(
        permit_platform("access.platform_user_role_assignment.read")
    ),
):
    subject_id = user_id or actor.user_id
    async with control_session() as db:
        decision = await decide_platform(
            db,
            subject_id,
            key,
            current_ip=request.client.host if request.client else None,
        )
        platform_audit(
            db,
            actor.user_id,
            "platform-rbac.effective-access.read",
            details={"subject_id": subject_id, "permission_key": key},
        )
    return _decision_row(key, decision)


async def _list_roles(
    db,
    role_model,
    grant_model,
    assignment_model,
    page: int,
    size: int,
    status: str | None,
    search: str | None,
):
    if size not in PAGE_SIZES:
        raise HTTPException(422, "Page size must be 10, 25, or 50")
    filters = []
    if status:
        filters.append(role_model.status == status)
    if search:
        needle = f"%{search.strip()}%"
        filters.append(or_(role_model.name.ilike(needle), role_model.description.ilike(needle)))
    total = await db.scalar(select(func.count()).select_from(role_model).where(*filters))
    roles = (
        await db.scalars(
            select(role_model)
            .where(*filters)
            .order_by(role_model.locked.desc(), role_model.name)
            .offset((page - 1) * size)
            .limit(size)
        )
    ).all()
    return {
        "items": [
            await role_payload(db, role, grant_model, assignment_model) for role in roles
        ],
        "page": page,
        "size": size,
        "total": total or 0,
        "pages": ((total or 0) + size - 1) // size,
    }


async def _create_role(
    db,
    body: RoleCreate,
    role_model,
    grant_model,
    assignment_model,
    domain: Domain,
    actor_id: str,
):
    await assert_unique_name(db, role_model, body.name)
    parent = None
    if body.parent_id:
        parent = await require_role(db, role_model, body.parent_id)
        if parent.status == RoleStatus.ARCHIVED.value:
            raise HTTPException(422, "Archived roles cannot be inherited")
    source = None
    if body.copy_from_id:
        source = await require_role(db, role_model, body.copy_from_id)
    role = role_model(
        domain=domain.value,
        name=body.name.strip(),
        description=body.description.strip(),
        status=RoleStatus.DRAFT.value,
        parent_id=parent.id if parent else None,
        created_by=actor_id,
        updated_by=actor_id,
    )
    db.add(role)
    await db.flush()
    if source:
        grants = (
            await db.scalars(select(grant_model).where(grant_model.role_id == source.id))
        ).all()
        db.add_all(
            grant_model(
                role_id=role.id,
                permission_key=grant.permission_key,
                effect=grant.effect,
                scope=grant.scope,
                conditions=grant.conditions,
                created_by=actor_id,
                updated_by=actor_id,
            )
            for grant in grants
        )
        await db.flush()
    return await role_payload(db, role, grant_model, assignment_model)


async def _update_role(
    db,
    identifier: str,
    body: RoleUpdate,
    role_model,
    grant_model,
    assignment_model,
    actor_id: str,
):
    role = await require_role(db, role_model, identifier, lock=True)
    ensure_mutable(role, draft_only=True)
    if role.version != body.version:
        raise HTTPException(409, "Role changed; refresh before editing")
    if body.name is not None:
        await assert_unique_name(db, role_model, body.name, role.id)
        role.name = body.name.strip()
    if body.description is not None:
        role.description = body.description.strip()
    if "parent_id" in body.model_fields_set:
        if body.parent_id == role.id:
            raise HTTPException(422, "A role cannot inherit from itself")
        if body.parent_id:
            parent = await require_role(db, role_model, body.parent_id)
            if parent.status == RoleStatus.ARCHIVED.value:
                raise HTTPException(422, "Archived roles cannot be inherited")
        role.parent_id = body.parent_id
    role.version += 1
    role.updated_by = actor_id
    context = (
        await platform_policy_context(db)
        if role.domain == Domain.PLATFORM.value
        else await tenant_policy_context(db)
    )
    context.roles[role.id].name = role.name
    context.roles[role.id].description = role.description
    context.roles[role.id].parent_id = role.parent_id
    issues = validate_grants(context.roles[role.id], context)
    if issues:
        raise HTTPException(
            422,
            {
                "message": "Role is invalid",
                "issues": [
                    {"key": issue.key, "code": issue.code.value, "message": issue.message}
                    for issue in issues
                ],
            },
        )
    await db.flush()
    return await role_payload(db, role, grant_model, assignment_model)


async def _delete_draft(db, identifier: str, role_model, grant_model, actor_id: str):
    role = await require_role(db, role_model, identifier, lock=True)
    ensure_mutable(role)
    if role.status != RoleStatus.DRAFT.value:
        raise HTTPException(409, "Only draft roles can be permanently deleted")
    await db.execute(delete(grant_model).where(grant_model.role_id == role.id))
    await db.delete(role)
    return {"status": "deleted", "role_id": identifier, "actor_id": actor_id}


async def _lifecycle(
    db,
    identifier: str,
    action: str,
    role_model,
    grant_model,
    assignment_model,
    actor_id: str,
):
    role = await require_role(db, role_model, identifier, lock=True)
    ensure_mutable(role)
    if action == "publish":
        if role.status != RoleStatus.DRAFT.value:
            raise HTTPException(409, "Only draft roles can be published")
        context = (
            await platform_policy_context(db)
            if role.domain == Domain.PLATFORM.value
            else await tenant_policy_context(db)
        )
        issues = validate_grants(context.roles[role.id], context)
        if issues:
            raise HTTPException(
                422,
                {
                    "message": "Role is invalid",
                    "issues": [
                        {"key": issue.key, "code": issue.code.value, "message": issue.message}
                        for issue in issues
                    ],
                },
            )
        approval, conflicts = role_requires_approval(context.roles[role.id], context)
        if approval:
            raise HTTPException(
                409,
                {
                    "message": "Role publication requires maker-checker approval",
                    "conflicts": conflicts,
                },
            )
        role.status = RoleStatus.PUBLISHED.value
    elif action == "deactivate":
        if role.status != RoleStatus.PUBLISHED.value:
            raise HTTPException(409, "Only published roles can be deactivated")
        role.status = RoleStatus.INACTIVE.value
    elif action == "reactivate":
        if role.status != RoleStatus.INACTIVE.value:
            raise HTTPException(409, "Only inactive roles can be reactivated")
        role.status = RoleStatus.PUBLISHED.value
    elif action == "archive":
        users = await db.scalar(
            select(func.count()).select_from(assignment_model).where(
                assignment_model.role_id == role.id
            )
        )
        if users:
            raise HTTPException(409, "Remove all role assignments before archiving")
        if role.status == RoleStatus.ARCHIVED.value:
            raise HTTPException(409, "Role is already archived")
        role.status = RoleStatus.ARCHIVED.value
    elif action == "restore":
        if role.status != RoleStatus.ARCHIVED.value:
            raise HTTPException(409, "Only archived roles can be restored")
        role.status = RoleStatus.INACTIVE.value
    else:
        raise HTTPException(404, "Unknown role lifecycle action")
    role.version += 1
    role.updated_by = actor_id
    await db.flush()
    return await role_payload(db, role, grant_model, assignment_model)


async def _assign_role(
    db,
    body: RoleAssignmentInput,
    role_model,
    assignment_model,
    user_model,
    domain: Domain,
    actor_id: str,
):
    role = await require_role(db, role_model, body.role_id, lock=True)
    if role.status != RoleStatus.PUBLISHED.value:
        raise HTTPException(409, "Only published roles can be assigned")
    if await db.get(user_model, body.user_id) is None:
        raise HTTPException(404, "User not found")
    if domain is Domain.PLATFORM and body.level != "Platform":
        raise HTTPException(422, "Platform roles require Platform assignment reach")
    if domain is Domain.TENANT and body.level == "Platform":
        raise HTTPException(422, "Tenant roles cannot use Platform assignment reach")
    if body.location_id and await db.get(Location, body.location_id) is None:
        raise HTTPException(404, "Location not found")
    context = (
        await platform_policy_context(db)
        if domain is Domain.PLATFORM
        else await tenant_policy_context(db)
    )
    if role.locked or assignment_is_high_risk(context.roles[role.id], context):
        raise HTTPException(409, "High-risk role assignment requires maker-checker approval")
    row = assignment_model(
        user_id=body.user_id,
        role_id=body.role_id,
        level=body.level,
        location_id=body.location_id,
        expires_at=body.expires_at,
        created_by=actor_id,
        updated_by=actor_id,
    )
    db.add(row)
    await db.flush()
    return {
        "id": row.id,
        "user_id": row.user_id,
        "role_id": row.role_id,
        "level": row.level,
        "location_id": row.location_id,
        "expires_at": row.expires_at,
    }


async def _unassign_role(db, identifier: str, assignment_model, role_model):
    assignment = await db.get(assignment_model, identifier)
    if assignment is None:
        raise HTTPException(404, "Role assignment not found")
    role = await require_role(db, role_model, assignment.role_id, lock=True)
    if role.locked:
        holders = await db.scalar(
            select(func.count(func.distinct(assignment_model.user_id))).where(
                assignment_model.role_id == role.id
            )
        )
        if (holders or 0) <= 1:
            raise HTTPException(409, "The last Super Admin holder cannot be removed")
        raise HTTPException(409, "Super Admin assignment removal requires maker-checker approval")
    await db.delete(assignment)
    return {"status": "unassigned", "assignment_id": identifier}


async def _request_list(
    db,
    request_model,
    decision_model,
    *,
    page: int,
    size: int,
    status: str | None,
    mine: bool,
    actor_id: str,
):
    if size not in PAGE_SIZES:
        raise HTTPException(422, "Page size must be 10, 25, or 50")
    await expire_requests(db, request_model)
    filters = []
    if status:
        filters.append(request_model.status == status)
    if mine:
        filters.append(request_model.maker_id == actor_id)
    total = await db.scalar(select(func.count()).select_from(request_model).where(*filters))
    rows = (
        await db.scalars(
            select(request_model)
            .where(*filters)
            .order_by(
                (request_model.status == "pending").desc(),
                request_model.created_at.desc(),
            )
            .offset((page - 1) * size)
            .limit(size)
        )
    ).all()
    return {
        "items": [await request_payload(db, row, decision_model) for row in rows],
        "page": page,
        "size": size,
        "total": total or 0,
        "pages": ((total or 0) + size - 1) // size,
    }


async def _approval_notifications(
    db,
    request_model,
    decision_model,
    receipt_model,
    *,
    actor_id: str,
    role_keys: set[str],
    eligible_roles: tuple[str, ...],
):
    await expire_requests(db, request_model)
    rows = (
        await db.scalars(
            select(request_model).order_by(request_model.created_at.desc()).limit(50)
        )
    ).all()
    request_ids = [row.id for row in rows]
    decisions = (
        await db.scalars(
            select(decision_model).where(decision_model.request_id.in_(request_ids))
        )
    ).all() if request_ids else []
    decisions_by_request: dict[str, list] = {}
    for decision in decisions:
        decisions_by_request.setdefault(decision.request_id, []).append(decision)
    seen = set(
        (
            await db.scalars(
                select(receipt_model.request_id).where(receipt_model.user_id == actor_id)
            )
        ).all()
    )
    is_checker = bool(role_keys.intersection(eligible_roles))
    items = []
    for row in rows:
        row_decisions = decisions_by_request.get(row.id, [])
        already_decided = any(item.user_id == actor_id for item in row_decisions)
        if row.status == "pending" and row.maker_id != actor_id and is_checker and not already_decided:
            items.append({
                "request_id": row.id,
                "kind": "action",
                "title": f"{row.id[:8]} needs your approval",
                "detail": row.reason,
                "status": row.status,
                "created_at": row.created_at,
                "cta_label": "Review request",
                "counted": True,
                "seen": False,
            })
        elif row.maker_id == actor_id and row.status == "pending":
            items.append({
                "request_id": row.id,
                "kind": "waiting",
                "title": f"{row.id[:8]} is waiting for approval",
                "detail": row.reason,
                "status": row.status,
                "created_at": row.created_at,
                "cta_label": "View request",
                "counted": False,
                "seen": True,
            })
        elif row.maker_id == actor_id and row.status in {
            "approved", "applied", "rejected", "expired", "conflicted"
        }:
            items.append({
                "request_id": row.id,
                "kind": "decision",
                "title": f"{row.id[:8]} was {row.status}",
                "detail": row.reason,
                "status": row.status,
                "created_at": row.updated_at,
                "cta_label": "View outcome",
                "counted": row.id not in seen,
                "seen": row.id in seen,
            })
    order = {"action": 0, "decision": 1, "waiting": 2}
    items.sort(key=lambda item: (order[item["kind"]], -item["created_at"].timestamp()))
    return {"items": items, "unread_count": sum(item["counted"] for item in items)}


async def _mark_decision_notifications_seen(
    db,
    request_model,
    receipt_model,
    *,
    actor_id: str,
):
    closed = (
        await db.scalars(
            select(request_model).where(
                request_model.maker_id == actor_id,
                request_model.status.in_(("approved", "applied", "rejected", "expired", "conflicted")),
            )
        )
    ).all()
    existing = set(
        (
            await db.scalars(
                select(receipt_model.request_id).where(receipt_model.user_id == actor_id)
            )
        ).all()
    )
    now = datetime.now(UTC)
    for row in closed:
        if row.id not in existing:
            db.add(receipt_model(
                user_id=actor_id,
                request_id=row.id,
                seen_at=now,
                created_by=actor_id,
                updated_by=actor_id,
            ))
    await db.flush()
    return {"seen": len(closed)}


async def _approver_role_keys(db, actor_id: str, domain: Domain):
    if domain is Domain.TENANT:
        context = await tenant_policy_context(db)
        assignments = await tenant_assignments(db, actor_id)
    else:
        context = await platform_policy_context(db)
        assignments = await platform_assignments(db, actor_id)
    return {
        assignment.role_id
        for assignment in active_assignments(assignments, context.roles, domain)
    }


async def _history(db, version_model, page: int, size: int):
    if size not in PAGE_SIZES:
        raise HTTPException(422, "Page size must be 10, 25, or 50")
    total = await db.scalar(select(func.count()).select_from(version_model))
    rows = (
        await db.scalars(
            select(version_model)
            .order_by(version_model.version.desc())
            .offset((page - 1) * size)
            .limit(size)
        )
    ).all()
    return {
        "items": [
            {
                "id": row.id,
                "version": row.version,
                "author_id": row.author_id,
                "approver_ids": row.approver_ids,
                "reason": row.reason,
                "changes": row.changes,
                "break_glass": row.break_glass,
                "created_at": row.created_at,
            }
            for row in rows
        ],
        "page": page,
        "size": size,
        "total": total or 0,
        "pages": ((total or 0) + size - 1) // size,
    }


@router.get("/rbac/roles")
async def tenant_roles(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10),
    status: str | None = Query(default=None, pattern="^(draft|pending|published|inactive|archived)$"),
    search: str | None = None,
    actor: Actor = Depends(permit_tenant("access.tenant_role.read")),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        result = await _list_roles(
            db, TenantRole, TenantRoleGrant, TenantRoleAssignment, page, size, status, search
        )
        audit(db, actor.user_id, "rbac.roles.read", "tenant_role")
        return result


@router.post("/rbac/roles", status_code=201)
async def create_tenant_role(
    body: RoleCreate,
    actor: Actor = Depends(permit_tenant("access.tenant_role.create")),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        result = await _create_role(
            db,
            body,
            TenantRole,
            TenantRoleGrant,
            TenantRoleAssignment,
            Domain.TENANT,
            actor.user_id,
        )
        audit(db, actor.user_id, "rbac.role.create", "tenant_role", result["id"])
        return result


@router.get("/rbac/roles/{identifier}")
async def tenant_role_detail(
    identifier: str,
    actor: Actor = Depends(permit_tenant("access.tenant_role.read")),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        role = await require_role(db, TenantRole, identifier)
        result = await role_payload(db, role, TenantRoleGrant, TenantRoleAssignment)
        audit(db, actor.user_id, "rbac.role.read", "tenant_role", identifier)
        return result


@router.patch("/rbac/roles/{identifier}")
async def update_tenant_role(
    identifier: str,
    body: RoleUpdate,
    actor: Actor = Depends(
        permit_tenant("access.tenant_role.update", workflow_handles_approval=True)
    ),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        result = await _update_role(
            db,
            identifier,
            body,
            TenantRole,
            TenantRoleGrant,
            TenantRoleAssignment,
            actor.user_id,
        )
        audit(db, actor.user_id, "rbac.role.update", "tenant_role", identifier)
        return result


@router.delete("/rbac/roles/{identifier}")
async def delete_tenant_role(
    identifier: str,
    actor: Actor = Depends(
        permit_tenant("access.tenant_role.archive", workflow_handles_approval=True)
    ),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        result = await _delete_draft(
            db, identifier, TenantRole, TenantRoleGrant, actor.user_id
        )
        audit(db, actor.user_id, "rbac.role.delete", "tenant_role", identifier)
        return result


@router.put("/rbac/roles/{identifier}/grants")
async def tenant_role_grants(
    identifier: str,
    body: GrantSet,
    actor: Actor = Depends(
        permit_tenant(
            "access.tenant_role_permission_mapping.assign_permissions",
            workflow_handles_approval=True,
        )
    ),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        role = await require_role(db, TenantRole, identifier, lock=True)
        if role.version != body.version:
            raise HTTPException(409, "Role changed; refresh before editing")
        context = await tenant_policy_context(db)
        result = await replace_role_grants(
            db, role, body.grants, context, TenantRoleGrant, actor.user_id
        )
        result["role"] = await role_payload(
            db, role, TenantRoleGrant, TenantRoleAssignment
        )
        audit(
            db,
            actor.user_id,
            "rbac.role-grants.update",
            "tenant_role",
            identifier,
            changes=result["changes"],
            cleared_dependents=result["cleared_dependents"],
        )
        return result


@router.post("/rbac/roles/{identifier}/changes", status_code=202)
async def create_tenant_role_change(
    identifier: str,
    body: RoleChangeInput,
    actor: Actor = Depends(
        permit_tenant(
            "access.tenant_role_permission_mapping.assign_permissions",
            workflow_handles_approval=True,
        )
    ),
):
    if body.break_glass and (
        not actor.mfa_authenticated_at
        or time.time() - actor.mfa_authenticated_at > 300
    ):
        raise HTTPException(403, "Break-glass requires MFA within the last 5 minutes")
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        role = await require_role(db, TenantRole, identifier, lock=True)
        if role.version != body.version:
            raise HTTPException(409, "Role changed; refresh before submitting")
        context = await tenant_policy_context(db)
        row, diagnostics = await create_role_change_request(
            db,
            role=role,
            desired_grants=direct_grants(body.grants),
            publish=body.publish,
            reason=body.reason,
            acknowledge_conflicts=body.acknowledge_conflicts,
            break_glass=body.break_glass,
            maker_id=actor.user_id,
            context=context,
            request_model=TenantChangeRequest,
            policy_model=TenantApprovalPolicy,
            assignment_model=TenantRoleAssignment,
            grant_model=TenantRoleGrant,
            version_model=TenantPolicyVersion,
        )
        audit(
            db,
            actor.user_id,
            "rbac.change-request.create",
            "tenant_role",
            identifier,
            request_id=row.id,
            break_glass=body.break_glass,
        )
        return {
            **await request_payload(db, row, TenantChangeDecision),
            "diagnostics": diagnostics,
        }


@router.post("/rbac/roles/{identifier}/{action}")
async def tenant_role_lifecycle(
    identifier: str,
    action: str = Path(pattern="^(publish|deactivate|reactivate|archive|restore)$"),
    actor: Actor = Depends(tenant_role_lifecycle_actor),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        result = await _lifecycle(
            db,
            identifier,
            action,
            TenantRole,
            TenantRoleGrant,
            TenantRoleAssignment,
            actor.user_id,
        )
        audit(db, actor.user_id, f"rbac.role.{action}", "tenant_role", identifier)
        return result


@router.post("/rbac/assignments", status_code=201)
async def create_tenant_assignment(
    body: RoleAssignmentInput,
    actor: Actor = Depends(
        permit_tenant(
            "access.staff_role_assignment.assign_role",
            workflow_handles_approval=True,
        )
    ),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        result = await _assign_role(
            db,
            body,
            TenantRole,
            TenantRoleAssignment,
            StaffUser,
            Domain.TENANT,
            actor.user_id,
        )
        audit(
            db,
            actor.user_id,
            "rbac.role.assign",
            "staff",
            body.user_id,
            role_id=body.role_id,
        )
        return result


@router.delete("/rbac/assignments/{identifier}")
async def delete_tenant_assignment(
    identifier: str,
    actor: Actor = Depends(
        permit_tenant(
            "access.staff_role_assignment.unassign_role",
            workflow_handles_approval=True,
        )
    ),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        result = await _unassign_role(db, identifier, TenantRoleAssignment, TenantRole)
        audit(db, actor.user_id, "rbac.role.unassign", "assignment", identifier)
        return result


@router.get("/rbac/requests")
async def tenant_requests(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10),
    status: str | None = Query(
        default=None,
        pattern="^(pending|approved|applied|rejected|withdrawn|expired|conflicted)$",
    ),
    mine: bool = False,
    actor: Actor = Depends(permit_tenant("reports.pending_approval_item.read")),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        result = await _request_list(
            db,
            TenantChangeRequest,
            TenantChangeDecision,
            page=page,
            size=size,
            status=status,
            mine=mine,
            actor_id=actor.user_id,
        )
        audit(db, actor.user_id, "rbac.requests.read", "change_request")
        return result


@router.get("/rbac/notifications")
async def tenant_approval_notifications(
    actor: Actor = Depends(permit_tenant("reports.pending_approval_item.read")),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        policy = await load_approval_policy(db, TenantApprovalPolicy)
        result = await _approval_notifications(
            db,
            TenantChangeRequest,
            TenantChangeDecision,
            TenantChangeNotificationReceipt,
            actor_id=actor.user_id,
            role_keys=await _approver_role_keys(db, actor.user_id, Domain.TENANT),
            eligible_roles=policy.tenant_eligible_roles,
        )
        audit(db, actor.user_id, "rbac.notifications.read", "change_request")
        return result


@router.post("/rbac/notifications/seen")
async def mark_tenant_approval_notifications_seen(
    actor: Actor = Depends(permit_tenant("reports.pending_approval_item.read")),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        result = await _mark_decision_notifications_seen(
            db,
            TenantChangeRequest,
            TenantChangeNotificationReceipt,
            actor_id=actor.user_id,
        )
        audit(db, actor.user_id, "rbac.notifications.seen", "change_request")
        return result


@router.post("/rbac/requests/{identifier}/{action}")
async def tenant_request_decision(
    identifier: str,
    action: str = Path(pattern="^(approve|reject|withdraw)$"),
    body: RequestDecisionInput = RequestDecisionInput(),
    actor: Actor = Depends(
        permit_tenant("reports.pending_approval_item.read", workflow_handles_approval=True)
    ),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        row = await db.scalar(
            select(TenantChangeRequest)
            .where(TenantChangeRequest.id == identifier)
            .with_for_update()
        )
        if row is None:
            raise HTTPException(404, "Change request not found")
        await expire_requests(db, TenantChangeRequest)
        if action == "withdraw":
            await withdraw_request(db, row, actor.user_id)
        else:
            permission = f"reports.pending_approval_item.{action}"
            decision = await decide_tenant(db, actor.user_id, permission)
            if not decision.allowed:
                raise HTTPException(403, "Permission denied")
            await decide_request(
                db,
                request_row=row,
                decision_value=action,
                comment=body.comment,
                actor_id=actor.user_id,
                domain=Domain.TENANT,
                role_keys=await _approver_role_keys(db, actor.user_id, Domain.TENANT),
                request_model=TenantChangeRequest,
                decision_model=TenantChangeDecision,
                policy_model=TenantApprovalPolicy,
                role_model=TenantRole,
                grant_model=TenantRoleGrant,
                version_model=TenantPolicyVersion,
                rule_model=TenantFourEyesRule,
            )
        audit(
            db,
            actor.user_id,
            f"rbac.request.{action}",
            "change_request",
            identifier,
            comment=body.comment,
        )
        return await request_payload(db, row, TenantChangeDecision)


@router.get("/rbac/history")
async def tenant_history(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10),
    actor: Actor = Depends(permit_tenant("access.tenant_role.read")),
):
    async with organization_session(actor.organization) as db:
        db.info["actor"] = actor
        result = await _history(db, TenantPolicyVersion, page, size)
        audit(db, actor.user_id, "rbac.history.read", "policy_version")
        return result


@router.get("/platform/rbac/roles")
async def platform_roles(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10),
    status: str | None = Query(default=None, pattern="^(draft|pending|published|inactive|archived)$"),
    search: str | None = None,
    actor: PlatformActor = Depends(permit_platform("access.platform_role.read")),
):
    async with control_session() as db:
        result = await _list_roles(
            db,
            PlatformRole,
            PlatformRoleGrant,
            PlatformRoleAssignment,
            page,
            size,
            status,
            search,
        )
        platform_audit(db, actor.user_id, "platform-rbac.roles.read")
        return result


@router.post("/platform/rbac/roles", status_code=201)
async def create_platform_role(
    body: RoleCreate,
    actor: PlatformActor = Depends(permit_platform("access.platform_role.create")),
):
    async with control_session() as db:
        result = await _create_role(
            db,
            body,
            PlatformRole,
            PlatformRoleGrant,
            PlatformRoleAssignment,
            Domain.PLATFORM,
            actor.user_id,
        )
        platform_audit(
            db, actor.user_id, "platform-rbac.role.create", details={"role_id": result["id"]}
        )
        return result


@router.get("/platform/rbac/roles/{identifier}")
async def platform_role_detail(
    identifier: str,
    actor: PlatformActor = Depends(permit_platform("access.platform_role.read")),
):
    async with control_session() as db:
        role = await require_role(db, PlatformRole, identifier)
        result = await role_payload(db, role, PlatformRoleGrant, PlatformRoleAssignment)
        platform_audit(
            db, actor.user_id, "platform-rbac.role.read", details={"role_id": identifier}
        )
        return result


@router.patch("/platform/rbac/roles/{identifier}")
async def update_platform_role(
    identifier: str,
    body: RoleUpdate,
    actor: PlatformActor = Depends(
        permit_platform("access.platform_role.update", workflow_handles_approval=True)
    ),
):
    async with control_session() as db:
        result = await _update_role(
            db,
            identifier,
            body,
            PlatformRole,
            PlatformRoleGrant,
            PlatformRoleAssignment,
            actor.user_id,
        )
        platform_audit(
            db, actor.user_id, "platform-rbac.role.update", details={"role_id": identifier}
        )
        return result


@router.delete("/platform/rbac/roles/{identifier}")
async def delete_platform_role(
    identifier: str,
    actor: PlatformActor = Depends(
        permit_platform("access.platform_role.archive", workflow_handles_approval=True)
    ),
):
    async with control_session() as db:
        result = await _delete_draft(
            db, identifier, PlatformRole, PlatformRoleGrant, actor.user_id
        )
        platform_audit(
            db, actor.user_id, "platform-rbac.role.delete", details={"role_id": identifier}
        )
        return result


@router.put("/platform/rbac/roles/{identifier}/grants")
async def platform_role_grants(
    identifier: str,
    body: GrantSet,
    actor: PlatformActor = Depends(
        permit_platform(
            "access.platform_role_permission_mapping.assign_permissions",
            workflow_handles_approval=True,
        )
    ),
):
    async with control_session() as db:
        role = await require_role(db, PlatformRole, identifier, lock=True)
        if role.version != body.version:
            raise HTTPException(409, "Role changed; refresh before editing")
        context = await platform_policy_context(db)
        result = await replace_role_grants(
            db, role, body.grants, context, PlatformRoleGrant, actor.user_id
        )
        result["role"] = await role_payload(
            db, role, PlatformRoleGrant, PlatformRoleAssignment
        )
        platform_audit(
            db,
            actor.user_id,
            "platform-rbac.role-grants.update",
            details={
                "role_id": identifier,
                "changes": result["changes"],
                "cleared_dependents": result["cleared_dependents"],
            },
        )
        return result


@router.post("/platform/rbac/roles/{identifier}/changes", status_code=202)
async def create_platform_role_change(
    identifier: str,
    body: RoleChangeInput,
    actor: PlatformActor = Depends(
        permit_platform(
            "access.platform_role_permission_mapping.assign_permissions",
            workflow_handles_approval=True,
        )
    ),
):
    if body.break_glass and (
        not actor.mfa_authenticated_at
        or time.time() - actor.mfa_authenticated_at > 300
    ):
        raise HTTPException(403, "Break-glass requires MFA within the last 5 minutes")
    async with control_session() as db:
        role = await require_role(db, PlatformRole, identifier, lock=True)
        if role.version != body.version:
            raise HTTPException(409, "Role changed; refresh before submitting")
        context = await platform_policy_context(db)
        row, diagnostics = await create_role_change_request(
            db,
            role=role,
            desired_grants=direct_grants(body.grants),
            publish=body.publish,
            reason=body.reason,
            acknowledge_conflicts=body.acknowledge_conflicts,
            break_glass=body.break_glass,
            maker_id=actor.user_id,
            context=context,
            request_model=PlatformChangeRequest,
            policy_model=PlatformApprovalPolicy,
            assignment_model=PlatformRoleAssignment,
            grant_model=PlatformRoleGrant,
            version_model=PlatformPolicyVersion,
        )
        platform_audit(
            db,
            actor.user_id,
            "platform-rbac.change-request.create",
            details={"request_id": row.id, "role_id": role.id},
        )
        return {
            **await request_payload(db, row, PlatformChangeDecision),
            "diagnostics": diagnostics,
        }


@router.post("/platform/rbac/roles/{identifier}/{action}")
async def platform_role_lifecycle(
    identifier: str,
    action: str = Path(pattern="^(publish|deactivate|reactivate|archive|restore)$"),
    actor: PlatformActor = Depends(platform_role_lifecycle_actor),
):
    async with control_session() as db:
        result = await _lifecycle(
            db,
            identifier,
            action,
            PlatformRole,
            PlatformRoleGrant,
            PlatformRoleAssignment,
            actor.user_id,
        )
        platform_audit(
            db,
            actor.user_id,
            f"platform-rbac.role.{action}",
            details={"role_id": identifier},
        )
        return result


@router.post("/platform/rbac/assignments", status_code=201)
async def create_platform_assignment(
    body: RoleAssignmentInput,
    actor: PlatformActor = Depends(
        permit_platform(
            "access.platform_user_role_assignment.assign_role",
            workflow_handles_approval=True,
        )
    ),
):
    async with control_session() as db:
        result = await _assign_role(
            db,
            body,
            PlatformRole,
            PlatformRoleAssignment,
            PlatformUser,
            Domain.PLATFORM,
            actor.user_id,
        )
        platform_audit(
            db,
            actor.user_id,
            "platform-rbac.role.assign",
            details={"user_id": body.user_id, "role_id": body.role_id},
        )
        return result


@router.delete("/platform/rbac/assignments/{identifier}")
async def delete_platform_assignment(
    identifier: str,
    actor: PlatformActor = Depends(
        permit_platform(
            "access.platform_user_role_assignment.unassign_role",
            workflow_handles_approval=True,
        )
    ),
):
    async with control_session() as db:
        result = await _unassign_role(
            db, identifier, PlatformRoleAssignment, PlatformRole
        )
        platform_audit(
            db,
            actor.user_id,
            "platform-rbac.role.unassign",
            details={"assignment_id": identifier},
        )
        return result


@router.get("/platform/rbac/requests")
async def platform_requests(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10),
    status: str | None = Query(
        default=None,
        pattern="^(pending|approved|applied|rejected|withdrawn|expired|conflicted)$",
    ),
    mine: bool = False,
    actor: PlatformActor = Depends(permit_platform("access.platform_role.read")),
):
    async with control_session() as db:
        result = await _request_list(
            db,
            PlatformChangeRequest,
            PlatformChangeDecision,
            page=page,
            size=size,
            status=status,
            mine=mine,
            actor_id=actor.user_id,
        )
        platform_audit(db, actor.user_id, "platform-rbac.requests.read")
        return result


@router.get("/platform/rbac/notifications")
async def platform_approval_notifications(
    actor: PlatformActor = Depends(permit_platform("access.platform_role.read")),
):
    async with control_session() as db:
        policy = await load_approval_policy(db, PlatformApprovalPolicy)
        result = await _approval_notifications(
            db,
            PlatformChangeRequest,
            PlatformChangeDecision,
            PlatformChangeNotificationReceipt,
            actor_id=actor.user_id,
            role_keys=await _approver_role_keys(db, actor.user_id, Domain.PLATFORM),
            eligible_roles=policy.platform_eligible_roles,
        )
        platform_audit(db, actor.user_id, "platform-rbac.notifications.read")
        return result


@router.post("/platform/rbac/notifications/seen")
async def mark_platform_approval_notifications_seen(
    actor: PlatformActor = Depends(permit_platform("access.platform_role.read")),
):
    async with control_session() as db:
        result = await _mark_decision_notifications_seen(
            db,
            PlatformChangeRequest,
            PlatformChangeNotificationReceipt,
            actor_id=actor.user_id,
        )
        platform_audit(db, actor.user_id, "platform-rbac.notifications.seen")
        return result


@router.post("/platform/rbac/requests/{identifier}/{action}")
async def platform_request_decision(
    identifier: str,
    action: str = Path(pattern="^(approve|reject|withdraw)$"),
    body: RequestDecisionInput = RequestDecisionInput(),
    actor: PlatformActor = Depends(
        permit_platform("access.platform_role.update", workflow_handles_approval=True)
    ),
):
    async with control_session() as db:
        row = await db.scalar(
            select(PlatformChangeRequest)
            .where(PlatformChangeRequest.id == identifier)
            .with_for_update()
        )
        if row is None:
            raise HTTPException(404, "Change request not found")
        await expire_requests(db, PlatformChangeRequest)
        if action == "withdraw":
            await withdraw_request(db, row, actor.user_id)
        else:
            await decide_request(
                db,
                request_row=row,
                decision_value=action,
                comment=body.comment,
                actor_id=actor.user_id,
                domain=Domain.PLATFORM,
                role_keys=await _approver_role_keys(db, actor.user_id, Domain.PLATFORM),
                request_model=PlatformChangeRequest,
                decision_model=PlatformChangeDecision,
                policy_model=PlatformApprovalPolicy,
                role_model=PlatformRole,
                grant_model=PlatformRoleGrant,
                version_model=PlatformPolicyVersion,
                rule_model=PlatformFourEyesRule,
            )
        platform_audit(
            db,
            actor.user_id,
            f"platform-rbac.request.{action}",
            details={"request_id": identifier, "comment": body.comment},
        )
        return await request_payload(db, row, PlatformChangeDecision)


@router.get("/platform/rbac/history")
async def platform_history(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10),
    actor: PlatformActor = Depends(permit_platform("access.platform_role.read")),
):
    async with control_session() as db:
        result = await _history(db, PlatformPolicyVersion, page, size)
        platform_audit(db, actor.user_id, "platform-rbac.history.read")
        return result
