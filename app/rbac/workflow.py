from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import func, select

from app.rbac.bootstrap import APPROVAL_POLICY_ID, default_approval_policy
from app.rbac.management import clear_unmet_dependents
from app.rbac.policy import (
    ApprovalDecision,
    ApprovalPolicy,
    ChangeDecision,
    ChangePatch,
    ChangeRequest,
    Domain,
    FourEyesRule,
    FourEyesScope,
    Grant,
    GrantEffect,
    RequestStatus,
    RoleStatus,
    Scope,
    apply_decision,
    diff_grants,
    find_conflicts,
    governing_rule_for,
    glob_to_regex,
    validate_grants,
)


def approval_policy_from_settings(values: dict | None) -> ApprovalPolicy:
    settings = {**default_approval_policy(), **(values or {})}
    settings["tenant_eligible_roles"] = tuple(settings["tenant_eligible_roles"])
    settings["platform_eligible_roles"] = tuple(settings["platform_eligible_roles"])
    return ApprovalPolicy(**settings)


async def load_approval_policy(db, model) -> ApprovalPolicy:
    row = await db.get(model, APPROVAL_POLICY_ID)
    if row is None:
        raise RuntimeError("RBAC approval policy has not been seeded")
    return approval_policy_from_settings(row.settings)


def grant_json(grant: Grant | None):
    if grant is None:
        return None
    return {
        "effect": grant.effect.value,
        "scope": grant.scope.value,
        "conditions": {
            "step_up_mfa_minutes": grant.conditions.step_up_mfa_minutes,
            "requires_approval": grant.conditions.requires_approval,
            "expires_at": (
                grant.conditions.expires_at.isoformat()
                if grant.conditions.expires_at
                else None
            ),
            "ip_allow_list": list(grant.conditions.ip_allow_list),
        }
        if grant.conditions
        else {},
    }


def grant_from_json(values: dict | None):
    if values is None:
        return None
    from app.rbac.runtime import conditions_from_record

    return Grant(
        effect=GrantEffect(values["effect"]),
        scope=Scope(values["scope"]),
        conditions=conditions_from_record(values.get("conditions")),
    )


async def expire_requests(db, request_model) -> int:
    now = datetime.now(UTC)
    rows = (
        await db.scalars(
            select(request_model).where(
                request_model.status == RequestStatus.PENDING.value,
                request_model.expires_at <= now,
            )
        )
    ).all()
    for row in rows:
        row.status = RequestStatus.EXPIRED.value
        row.updated_by = "rbac-expiry"
    await db.flush()
    return len(rows)


async def create_runtime_action_request(
    db,
    *,
    permission_key: str,
    payload: dict,
    reason: str,
    maker_id: str,
    context,
    request_model,
    policy_model,
):
    if len(reason.strip()) < 8:
        raise HTTPException(422, "Change reason must be at least 8 characters")
    permission = context.permissions.get(permission_key)
    if permission is None or permission.retired or not permission.reviewed:
        raise HTTPException(403, "Permission is not active")
    rule = governing_rule_for(permission, context.rules)
    if rule is None:
        raise HTTPException(409, "The runtime action is not governed by maker-checker")
    existing = (
        await db.scalars(
            select(request_model).where(
                request_model.kind == "runtime-action",
                request_model.maker_id == maker_id,
                request_model.runtime_permission_key == permission_key,
                request_model.status.in_((RequestStatus.PENDING.value, RequestStatus.APPROVED.value)),
            )
        )
    ).all()
    for row in existing:
        if row.runtime_payload == payload:
            return row, False
    policy = await load_approval_policy(db, policy_model)
    eligible_roles = (
        policy.tenant_eligible_roles
        if permission.domain is Domain.TENANT
        else policy.platform_eligible_roles
    )
    scope_context = {
        key: payload[key]
        for key in ("organization_id", "tenant_id", "location_id", "patient_id", "invoice_id")
        if payload.get(key) is not None
    }
    row = request_model(
        domain=permission.domain.value,
        kind="runtime-action",
        status=RequestStatus.PENDING.value,
        maker_id=maker_id,
        reason=reason.strip(),
        patch=[],
        risk=int(permission.risk),
        affected_users=0,
        required_approvals=policy.approvers_needed,
        expires_at=datetime.now(UTC) + timedelta(hours=policy.expires_after_hours),
        runtime_permission_key=permission_key,
        runtime_payload=payload,
        governing_rule_id=rule.id,
        approval_context={
            "governing_rule_name": rule.name,
            "eligible_role_ids": list(eligible_roles),
            "scope": scope_context,
        },
        created_by=maker_id,
        updated_by=maker_id,
    )
    db.add(row)
    await db.flush()
    return row, True


def validate_governance_patch(kind: str, patch: dict):
    if kind == "approval-policy":
        approval_policy_from_settings(patch.get("settings"))
        return
    if kind != "four-eyes-rules":
        raise HTTPException(422, "Unsupported governance change")
    identifiers: set[str] = set()
    priorities: set[int] = set()
    for item in patch.get("rules", []):
        identifier = str(item.get("id", "")).strip()
        name = str(item.get("name", "")).strip()
        patterns = tuple(str(pattern).strip() for pattern in item.get("patterns", []))
        try:
            priority = int(item.get("priority", 0))
        except (TypeError, ValueError):
            raise HTTPException(422, "Rule priority must be an integer") from None
        if not identifier or len(identifier) > 80 or not name or not patterns:
            raise HTTPException(422, "Every maker-checker rule requires an id, name, and pattern")
        if identifier in identifiers or priority in priorities or priority <= 0:
            raise HTTPException(422, "Rule ids and positive priorities must be unique")
        try:
            FourEyesScope(item.get("scope"))
            for pattern in patterns:
                if pattern != "@restricted:archive":
                    glob_to_regex(pattern)
        except (TypeError, ValueError) as error:
            raise HTTPException(422, f"Invalid maker-checker rule: {error}") from None
        identifiers.add(identifier)
        priorities.add(priority)


async def create_governance_change_request(
    db,
    *,
    kind: str,
    patch: dict,
    reason: str,
    maker_id: str,
    domain: Domain,
    request_model,
    policy_model,
):
    if len(reason.strip()) < 8:
        raise HTTPException(422, "Change reason must be at least 8 characters")
    validate_governance_patch(kind, patch)
    existing = (
        await db.scalars(
            select(request_model).where(
                request_model.kind == kind,
                request_model.maker_id == maker_id,
                request_model.status == RequestStatus.PENDING.value,
            )
        )
    ).all()
    for row in existing:
        if row.patch == [patch]:
            return row, False
    policy = await load_approval_policy(db, policy_model)
    row = request_model(
        domain=domain.value,
        kind=kind,
        status=RequestStatus.PENDING.value,
        maker_id=maker_id,
        reason=reason.strip(),
        patch=[patch],
        risk=4,
        affected_users=0,
        required_approvals=policy.approvers_needed,
        expires_at=datetime.now(UTC) + timedelta(hours=policy.expires_after_hours),
        created_by=maker_id,
        updated_by=maker_id,
    )
    db.add(row)
    await db.flush()
    return row, True


async def authorize_runtime_action(
    db,
    *,
    request_id: str,
    permission_key: str,
    payload: dict,
    maker_id: str,
    request_model,
):
    row = await db.scalar(
        select(request_model)
        .where(request_model.id == request_id)
        .with_for_update()
    )
    if row is None:
        raise HTTPException(404, "Approval request not found")
    if row.kind != "runtime-action" or row.runtime_permission_key != permission_key:
        raise HTTPException(409, "Approval request does not govern this action")
    if row.maker_id != maker_id:
        raise HTTPException(403, "Only the maker can execute the approved action")
    if row.status != RequestStatus.APPROVED.value:
        raise HTTPException(409, "Approval request is not ready for execution")
    if row.expires_at <= datetime.now(UTC):
        row.status = RequestStatus.EXPIRED.value
        raise HTTPException(409, "Approval request has expired")
    if row.runtime_payload != payload:
        raise HTTPException(409, "Approved action payload has changed")
    return row


async def complete_runtime_action(row, result: dict | None = None):
    row.status = RequestStatus.APPLIED.value
    row.runtime_payload = {
        **row.runtime_payload,
        "application_result": result or {"status": "applied"},
    }
    row.updated_by = row.maker_id
    return row


async def apply_governance_request(
    db,
    *,
    request_row,
    policy_model,
    rule_model,
    version_model,
    approver_ids: list[str],
):
    patch = request_row.patch[0]
    if request_row.kind == "approval-policy":
        policy = await db.get(policy_model, APPROVAL_POLICY_ID)
        if policy is None:
            raise HTTPException(409, "Approval policy has not been seeded")
        policy.settings = {**default_approval_policy(), **patch["settings"]}
        policy.updated_by = request_row.maker_id
    elif request_row.kind == "four-eyes-rules":
        desired = {item["id"]: item for item in patch["rules"]}
        current = {row.id: row for row in (await db.scalars(select(rule_model))).all()}
        for identifier, row in current.items():
            if identifier not in desired:
                await db.delete(row)
            else:
                row.priority = -abs(int(desired[identifier]["priority"]))
        await db.flush()
        for identifier, item in desired.items():
            row = current.get(identifier)
            if row is None:
                row = rule_model(
                    id=identifier,
                    created_by=request_row.maker_id,
                    updated_by=request_row.maker_id,
                )
                db.add(row)
            row.name = item["name"].strip()
            row.scope = item["scope"]
            row.priority = int(item["priority"])
            row.patterns = list(item["patterns"])
            row.updated_by = request_row.maker_id
    else:
        raise HTTPException(409, "Unsupported governance request")
    next_version = (await db.scalar(select(func.max(version_model.version))) or 0) + 1
    db.add(
        version_model(
            version=next_version,
            author_id=request_row.maker_id,
            approver_ids=approver_ids,
            reason=request_row.reason,
            changes=[patch],
            break_glass=False,
            created_by=request_row.maker_id,
            updated_by=request_row.maker_id,
        )
    )
    request_row.status = RequestStatus.APPLIED.value
    await db.flush()
    return request_row


async def request_payload(db, row, decision_model):
    decisions = (
        await db.scalars(
            select(decision_model)
            .where(decision_model.request_id == row.id)
            .order_by(decision_model.decided_at)
        )
    ).all()
    return {
        "id": row.id,
        "domain": row.domain,
        "kind": row.kind,
        "status": row.status,
        "maker_id": row.maker_id,
        "reason": row.reason,
        "patch": row.patch,
        "risk": row.risk,
        "affected_users": row.affected_users,
        "required_approvals": row.required_approvals,
        "expires_at": row.expires_at,
        "break_glass": row.break_glass,
        "role_id": row.role_id,
        "role_version": row.role_version,
        "runtime_permission_key": row.runtime_permission_key,
        "runtime_payload": row.runtime_payload,
        "governing_rule_id": row.governing_rule_id,
        "approval_context": row.approval_context,
        "created_at": row.created_at,
        "decisions": [
            {
                "user_id": decision.user_id,
                "decision": decision.decision,
                "comment": decision.comment,
                "decided_at": decision.decided_at,
            }
            for decision in decisions
        ],
    }


def _policy_request(row, decisions, domain: Domain) -> ChangeRequest:
    patches = tuple(
        ChangePatch(
            role_id=row.role_id or item.get("role_id", ""),
            permission_key=item.get("permission_key"),
            new_grant=grant_from_json(item.get("new_grant")),
            publish=item.get("publish"),
        )
        for item in row.patch
    )
    return ChangeRequest(
        id=row.id,
        domain=domain,
        kind=row.kind,
        status=RequestStatus(row.status),
        maker_id=row.maker_id,
        reason=row.reason,
        created_at=row.created_at,
        expires_at=row.expires_at,
        required_approvals=row.required_approvals,
        patch=patches,
        decisions=[
            ChangeDecision(
                user_id=item.user_id,
                decision=ApprovalDecision(item.decision),
                comment=item.comment or None,
                decided_at=item.decided_at,
            )
            for item in decisions
        ],
        break_glass=row.break_glass,
        role_version=row.role_version,
    )


async def create_role_change_request(
    db,
    *,
    role,
    desired_grants: dict[str, Grant],
    publish: bool,
    reason: str,
    acknowledge_conflicts: bool,
    break_glass: bool,
    maker_id: str,
    context,
    request_model,
    policy_model,
    assignment_model,
    grant_model,
    version_model,
):
    if len(reason.strip()) < 8:
        raise HTTPException(422, "Change reason must be at least 8 characters")
    if role.locked:
        raise HTTPException(409, "Super Admin roles cannot be edited")
    candidate = replace(
        context.roles[role.id],
        grants=dict(desired_grants),
        status=RoleStatus.PUBLISHED if publish else context.roles[role.id].status,
    )
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
    conflicts = find_conflicts(candidate, context)
    if conflicts and not acknowledge_conflicts:
        raise HTTPException(422, {"message": "SoD acknowledgement required", "conflicts": conflicts})
    changes = diff_grants(context.roles[role.id].grants, candidate.grants)
    # The context entry was replaced above; compare to persistence for the true before-state.
    before = {
        row.permission_key: Grant(
            GrantEffect(row.effect), Scope(row.scope), grant_from_json(
                {"effect": row.effect, "scope": row.scope, "conditions": row.conditions}
            ).conditions,
        )
        for row in (await db.scalars(select(grant_model).where(grant_model.role_id == role.id))).all()
    }
    changes = diff_grants(before, candidate.grants)
    patch = [
        {
            "role_id": role.id,
            "permission_key": change.key,
            "new_grant": grant_json(change.after),
        }
        for change in changes
    ]
    if publish:
        patch.append({"role_id": role.id, "publish": True})
    if not patch:
        raise HTTPException(422, "No role changes were supplied")
    policy = await load_approval_policy(db, policy_model)
    changed_permissions = [
        context.permissions[change.key]
        for change in changes
        if change.after is not None and change.key in context.permissions
    ]
    risk = max((int(permission.risk) for permission in changed_permissions), default=1)
    affected_users = await db.scalar(
        select(func.count(func.distinct(assignment_model.user_id))).where(
            assignment_model.role_id == role.id
        )
    )
    row = request_model(
        domain=role.domain,
        kind="role-publication" if publish else "role-policy",
        status=RequestStatus.PENDING.value,
        maker_id=maker_id,
        reason=reason.strip(),
        patch=patch,
        risk=risk,
        affected_users=affected_users or 0,
        required_approvals=policy.approvers_needed,
        expires_at=datetime.now(UTC) + timedelta(hours=policy.expires_after_hours),
        break_glass=break_glass,
        role_id=role.id,
        role_version=role.version,
        created_by=maker_id,
        updated_by=maker_id,
    )
    db.add(row)
    await db.flush()
    if break_glass:
        if not policy.break_glass_enabled:
            raise HTTPException(409, "Break-glass is disabled")
        await apply_role_request(
            db,
            row,
            role,
            grant_model,
            version_model,
            approver_ids=[],
            preserve_pending=True,
        )
    return row, {"cleared_dependents": cleared, "conflicts": conflicts}


async def apply_role_request(
    db,
    request_row,
    role,
    grant_model,
    version_model,
    approver_ids: list[str],
    *,
    preserve_pending: bool = False,
):
    if role.version != request_row.role_version:
        request_row.status = RequestStatus.CONFLICTED.value
        request_row.updated_by = "rbac-conflict"
        return False
    current = {
        row.permission_key: row
        for row in (
            await db.scalars(select(grant_model).where(grant_model.role_id == role.id))
        ).all()
    }
    change_log = []
    for item in request_row.patch:
        key = item.get("permission_key")
        if key:
            before = current.get(key)
            after = item.get("new_grant")
            change_log.append(
                {
                    "permission_key": key,
                    "before": (
                        {"effect": before.effect, "scope": before.scope, "conditions": before.conditions}
                        if before
                        else None
                    ),
                    "after": after,
                }
            )
            if before:
                await db.delete(before)
            if after:
                db.add(
                    grant_model(
                        role_id=role.id,
                        permission_key=key,
                        effect=after["effect"],
                        scope=after["scope"],
                        conditions=after.get("conditions", {}),
                        created_by=request_row.maker_id,
                        updated_by=request_row.maker_id,
                    )
                )
        if item.get("publish"):
            role.status = RoleStatus.PUBLISHED.value
            change_log.append({"publish": True})
    role.version += 1
    role.updated_by = request_row.maker_id
    next_version = (
        await db.scalar(select(func.max(version_model.version))) or 0
    ) + 1
    db.add(
        version_model(
            version=next_version,
            author_id=request_row.maker_id,
            approver_ids=approver_ids,
            reason=request_row.reason,
            changes=change_log,
            break_glass=request_row.break_glass,
            created_by=request_row.maker_id,
            updated_by=request_row.maker_id,
        )
    )
    request_row.role_version = role.version
    if not preserve_pending:
        request_row.status = RequestStatus.APPLIED.value
    await db.flush()
    return True


async def decide_request(
    db,
    *,
    request_row,
    decision_value: str,
    comment: str,
    actor_id: str,
    domain: Domain,
    role_keys: set[str],
    request_model,
    decision_model,
    policy_model,
    role_model,
    grant_model,
    version_model,
    rule_model=None,
    allow_maker: bool = False,
):
    del request_model
    existing = (
        await db.scalars(
            select(decision_model).where(decision_model.request_id == request_row.id)
        )
    ).all()
    policy = await load_approval_policy(db, policy_model)
    model_request = _policy_request(request_row, existing, domain)
    try:
        decision = ChangeDecision(
            user_id=actor_id,
            decision=ApprovalDecision(decision_value),
            comment=comment or None,
        )
        apply_decision(
            model_request,
            decision,
            user_domain=domain,
            user_role_keys=role_keys,
            policy=policy,
            allow_maker=allow_maker,
        )
    except (PermissionError, ValueError) as error:
        raise HTTPException(409, str(error)) from None
    db.add(
        decision_model(
            request_id=request_row.id,
            user_id=actor_id,
            decision=decision_value,
            comment=comment.strip(),
            decided_at=decision.decided_at,
            created_by=actor_id,
            updated_by=actor_id,
        )
    )
    request_row.status = model_request.status.value
    request_row.updated_by = actor_id
    if (
        request_row.kind == "runtime-action"
        and model_request.status is RequestStatus.APPLIED
    ):
        request_row.status = RequestStatus.APPROVED.value
        await db.flush()
        return request_row
    if (
        request_row.kind in {"approval-policy", "four-eyes-rules"}
        and model_request.status is RequestStatus.APPLIED
    ):
        await apply_governance_request(
            db,
            request_row=request_row,
            policy_model=policy_model,
            rule_model=rule_model,
            version_model=version_model,
            approver_ids=[
                item.user_id
                for item in [*existing, decision]
                if ApprovalDecision(item.decision) is ApprovalDecision.APPROVE
            ],
        )
        return request_row
    if model_request.status is RequestStatus.APPLIED and not request_row.break_glass:
        role = await db.scalar(
            select(role_model).where(role_model.id == request_row.role_id).with_for_update()
        )
        if role is None:
            request_row.status = RequestStatus.CONFLICTED.value
        else:
            await apply_role_request(
                db,
                request_row,
                role,
                grant_model,
                version_model,
                [
                    item.user_id
                    for item in [*existing, decision]
                    if ApprovalDecision(item.decision) is ApprovalDecision.APPROVE
                ],
            )
    await db.flush()
    return request_row


async def withdraw_request(db, row, actor_id: str):
    if row.maker_id != actor_id:
        raise HTTPException(403, "Only the maker can withdraw this request")
    if row.status != RequestStatus.PENDING.value:
        raise HTTPException(409, "Only pending requests can be withdrawn")
    if row.break_glass:
        raise HTTPException(409, "Applied break-glass changes require review")
    row.status = RequestStatus.WITHDRAWN.value
    row.updated_by = actor_id
    await db.flush()
    return row
