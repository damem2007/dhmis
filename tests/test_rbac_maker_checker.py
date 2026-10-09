from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.database import tenant_session
from app.rbac.bootstrap import TENANT_SUPER_ADMIN_ROLE_ID, seed_tenant_super_admin
from app.rbac.models import (
    TenantApprovalPolicy,
    TenantChangeRequest,
    TenantRole,
    TenantRoleAssignment,
)
from app.rbac.runtime import tenant_policy_context
from app.rbac.workflow import (
    authorize_runtime_action,
    complete_runtime_action,
    create_runtime_action_request,
)


async def test_role_publication_maker_checker_flow(client, tenants):
    tenant = tenants[0]
    async with tenant_session(tenant["org"].schema_name) as db:
        await seed_tenant_super_admin(db, "test-maker-checker")
        db.add(
            TenantRoleAssignment(
                user_id=tenant["front"].id,
                role_id=TENANT_SUPER_ADMIN_ROLE_ID,
                level="Organization",
                created_by="test-maker-checker",
                updated_by="test-maker-checker",
            )
        )

    created = await client.post(
        "/v1/rbac/roles",
        headers=tenant["headers"],
        json={"name": "Refund operator"},
    )
    assert created.status_code == 201, created.text
    role = created.json()
    grant_payload = [
        {
            "permission_key": f"billing.payment.{action}",
            "effect": "allow",
            "scope": "Organization",
        }
        for action in ("read", "update", "refund")
    ]
    grants = await client.put(
        f"/v1/rbac/roles/{role['id']}/grants",
        headers=tenant["headers"],
        json={"version": role["version"], "grants": grant_payload},
    )
    assert grants.status_code == 200, grants.text
    version = grants.json()["role"]["version"]

    request = await client.post(
        f"/v1/rbac/roles/{role['id']}/changes",
        headers=tenant["headers"],
        json={
            "version": version,
            "grants": grant_payload,
            "publish": True,
            "reason": "Enable governed refund operations",
        },
    )
    assert request.status_code == 202, request.text
    request_id = request.json()["id"]
    assert request.json()["status"] == "pending"

    maker_notifications = await client.get(
        "/v1/rbac/notifications", headers=tenant["headers"]
    )
    assert maker_notifications.status_code == 200, maker_notifications.text
    assert maker_notifications.json()["unread_count"] == 0
    assert any(
        item["request_id"] == request_id and item["kind"] == "waiting"
        for item in maker_notifications.json()["items"]
    )
    checker_notifications = await client.get(
        "/v1/rbac/notifications", headers=tenant["front_headers"]
    )
    assert checker_notifications.status_code == 200, checker_notifications.text
    assert checker_notifications.json()["unread_count"] >= 1
    assert any(
        item["request_id"] == request_id and item["kind"] == "action"
        for item in checker_notifications.json()["items"]
    )

    self_approval = await client.post(
        f"/v1/rbac/requests/{request_id}/approve",
        headers=tenant["headers"],
        json={},
    )
    assert self_approval.status_code == 409
    assert "maker cannot approve" in self_approval.text

    approved = await client.post(
        f"/v1/rbac/requests/{request_id}/approve",
        headers=tenant["front_headers"],
        json={},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "applied"

    decided_notifications = await client.get(
        "/v1/rbac/notifications", headers=tenant["headers"]
    )
    assert decided_notifications.status_code == 200, decided_notifications.text
    assert any(
        item["request_id"] == request_id
        and item["kind"] == "decision"
        and not item["seen"]
        for item in decided_notifications.json()["items"]
    )
    seen = await client.post(
        "/v1/rbac/notifications/seen", headers=tenant["headers"], json={}
    )
    assert seen.status_code == 200, seen.text
    after_seen = await client.get(
        "/v1/rbac/notifications", headers=tenant["headers"]
    )
    assert any(
        item["request_id"] == request_id and item["seen"]
        for item in after_seen.json()["items"]
    )

    detail = await client.get(
        f"/v1/rbac/roles/{role['id']}",
        headers=tenant["headers"],
    )
    assert detail.status_code == 200
    assert detail.json()["status"] == "published"

    duplicate = await client.post(
        f"/v1/rbac/requests/{request_id}/approve",
        headers=tenant["front_headers"],
        json={},
    )
    assert duplicate.status_code == 409

    history = await client.get("/v1/rbac/history", headers=tenant["headers"])
    assert history.status_code == 200
    assert history.json()["total"] >= 1
    assert history.json()["items"][0]["reason"] == "Enable governed refund operations"
    async with tenant_session(tenant["org"].schema_name) as db:
        assignment = await db.scalar(
            select(TenantRoleAssignment).where(
                TenantRoleAssignment.user_id == tenant["front"].id,
                TenantRoleAssignment.role_id == TENANT_SUPER_ADMIN_ROLE_ID,
                TenantRoleAssignment.level == "Organization",
            )
        )
        if assignment is not None:
            await db.delete(assignment)


async def test_rejection_withdrawal_expiry_and_conflict_states(client, tenants):
    tenant = tenants[0]
    async with tenant_session(tenant["org"].schema_name) as db:
        await seed_tenant_super_admin(db, "test-request-states")
        existing = await db.scalar(
            select(TenantRoleAssignment).where(
                TenantRoleAssignment.user_id == tenant["front"].id,
                TenantRoleAssignment.role_id == TENANT_SUPER_ADMIN_ROLE_ID,
            )
        )
        if existing is None:
            db.add(
                TenantRoleAssignment(
                    user_id=tenant["front"].id,
                    role_id=TENANT_SUPER_ADMIN_ROLE_ID,
                    level="Organization",
                    created_by="test-request-states",
                    updated_by="test-request-states",
                )
            )

    async def new_request(name: str):
        created = await client.post(
            "/v1/rbac/roles", headers=tenant["headers"], json={"name": name}
        )
        role = created.json()
        grants = [
            {
                "permission_key": f"billing.payment.{action}",
                "effect": "allow",
                "scope": "Organization",
            }
            for action in ("read", "update", "refund")
        ]
        saved = await client.put(
            f"/v1/rbac/roles/{role['id']}/grants",
            headers=tenant["headers"],
            json={"version": role["version"], "grants": grants},
        )
        submitted = await client.post(
            f"/v1/rbac/roles/{role['id']}/changes",
            headers=tenant["headers"],
            json={
                "version": saved.json()["role"]["version"],
                "grants": grants,
                "publish": True,
                "reason": f"Govern {name} publication",
            },
        )
        return role["id"], submitted.json()["id"]

    _, rejected_id = await new_request("Rejected refund role")
    short = await client.post(
        f"/v1/rbac/requests/{rejected_id}/reject",
        headers=tenant["front_headers"],
        json={"comment": "no"},
    )
    assert short.status_code == 409
    rejected = await client.post(
        f"/v1/rbac/requests/{rejected_id}/reject",
        headers=tenant["front_headers"],
        json={"comment": "Policy conflict remains"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"

    _, withdrawn_id = await new_request("Withdrawn refund role")
    withdrawn = await client.post(
        f"/v1/rbac/requests/{withdrawn_id}/withdraw",
        headers=tenant["headers"],
        json={},
    )
    assert withdrawn.status_code == 200
    assert withdrawn.json()["status"] == "withdrawn"

    conflict_role_id, conflict_id = await new_request("Conflicted refund role")
    async with tenant_session(tenant["org"].schema_name) as db:
        role = await db.get(TenantRole, conflict_role_id)
        role.version += 1
    conflicted = await client.post(
        f"/v1/rbac/requests/{conflict_id}/approve",
        headers=tenant["front_headers"],
        json={},
    )
    assert conflicted.status_code == 200
    assert conflicted.json()["status"] == "conflicted"

    _, expired_id = await new_request("Expired refund role")
    async with tenant_session(tenant["org"].schema_name) as db:
        row = await db.get(TenantChangeRequest, expired_id)
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    listed = await client.get(
        "/v1/rbac/requests?status=expired",
        headers=tenant["headers"],
    )
    assert listed.status_code == 200
    assert expired_id in {item["id"] for item in listed.json()["items"]}


async def test_runtime_action_is_approved_before_it_is_applied(client, tenants):
    tenant = tenants[0]
    payload = {
        "invoice_id": "invoice-runtime-test",
        "payment_id": "payment-runtime-test",
        "amount_cents": 2500,
        "reason": "Correct duplicated patient payment",
        "idempotency_key": "runtime-refund-test",
    }
    async with tenant_session(tenant["org"].schema_name) as db:
        await seed_tenant_super_admin(db, "test-runtime-action")
        existing = await db.scalar(
            select(TenantRoleAssignment).where(
                TenantRoleAssignment.user_id == tenant["front"].id,
                TenantRoleAssignment.role_id == TENANT_SUPER_ADMIN_ROLE_ID,
            )
        )
        if existing is None:
            db.add(
                TenantRoleAssignment(
                    user_id=tenant["front"].id,
                    role_id=TENANT_SUPER_ADMIN_ROLE_ID,
                    level="Organization",
                    created_by="test-runtime-action",
                    updated_by="test-runtime-action",
                )
            )
            await db.flush()
        request, created = await create_runtime_action_request(
            db,
            permission_key="billing.payment.refund",
            payload=payload,
            reason=payload["reason"],
            maker_id=tenant["user"].id,
            context=await tenant_policy_context(db),
            request_model=TenantChangeRequest,
            policy_model=TenantApprovalPolicy,
        )
        request_id = request.id
        assert created and request.status == "pending"
        assert request.governing_rule_id
        assert "tenant-super-admin" in request.approval_context["eligible_role_ids"]
        duplicate, duplicate_created = await create_runtime_action_request(
            db,
            permission_key="billing.payment.refund",
            payload=payload,
            reason=payload["reason"],
            maker_id=tenant["user"].id,
            context=await tenant_policy_context(db),
            request_model=TenantChangeRequest,
            policy_model=TenantApprovalPolicy,
        )
        assert not duplicate_created and duplicate.id == request_id
        try:
            await create_runtime_action_request(
                db,
                permission_key="billing.payment.read",
                payload=payload,
                reason=payload["reason"],
                maker_id=tenant["user"].id,
                context=await tenant_policy_context(db),
                request_model=TenantChangeRequest,
                policy_model=TenantApprovalPolicy,
            )
            assert False, "non-governed actions must not create approval requests"
        except Exception as error:
            assert getattr(error, "status_code", None) == 409

    self_approval = await client.post(
        f"/v1/rbac/requests/{request_id}/approve",
        headers=tenant["headers"],
        json={},
    )
    assert self_approval.status_code == 409

    approved = await client.post(
        f"/v1/rbac/requests/{request_id}/approve",
        headers=tenant["front_headers"],
        json={},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"

    async with tenant_session(tenant["org"].schema_name) as db:
        try:
            await authorize_runtime_action(
                db,
                request_id=request_id,
                permission_key="billing.payment.refund",
                payload={**payload, "amount_cents": 2600},
                maker_id=tenant["user"].id,
                request_model=TenantChangeRequest,
            )
            assert False, "changed payload must not consume an approval"
        except Exception as error:
            assert getattr(error, "status_code", None) == 409
        row = await authorize_runtime_action(
            db,
            request_id=request_id,
            permission_key="billing.payment.refund",
            payload=payload,
            maker_id=tenant["user"].id,
            request_model=TenantChangeRequest,
        )
        await complete_runtime_action(row, {"resource_id": "refund-runtime-test"})

    async with tenant_session(tenant["org"].schema_name) as db:
        applied = await db.get(TenantChangeRequest, request_id)
        assert applied.status == "applied"
        assert applied.runtime_payload["application_result"]["resource_id"] == "refund-runtime-test"


async def test_approval_policy_change_is_maker_checker_governed(client, tenants):
    tenant = tenants[0]
    async with tenant_session(tenant["org"].schema_name) as db:
        await seed_tenant_super_admin(db, "test-policy-change")
        existing = await db.scalar(
            select(TenantRoleAssignment).where(
                TenantRoleAssignment.user_id == tenant["front"].id,
                TenantRoleAssignment.role_id == TENANT_SUPER_ADMIN_ROLE_ID,
            )
        )
        if existing is None:
            db.add(
                TenantRoleAssignment(
                    user_id=tenant["front"].id,
                    role_id=TENANT_SUPER_ADMIN_ROLE_ID,
                    level="Organization",
                    created_by="test-policy-change",
                    updated_by="test-policy-change",
                )
            )

    current = await client.get("/v1/rbac/policy?size=10", headers=tenant["headers"])
    assert current.status_code == 200, current.text
    assert current.json()["rules"]["total"] == 12
    settings = current.json()["settings"]
    settings["expires_after_hours"] = 48
    submitted = await client.put(
        "/v1/rbac/policy",
        headers=tenant["headers"],
        json={"settings": settings, "reason": "Shorten approval expiry to two days"},
    )
    assert submitted.status_code == 202, submitted.text
    assert submitted.json()["status"] == "pending"

    unchanged = await client.get("/v1/rbac/policy", headers=tenant["headers"])
    assert unchanged.json()["settings"]["expires_after_hours"] == 72

    self_approval = await client.post(
        f"/v1/rbac/requests/{submitted.json()['id']}/approve",
        headers=tenant["headers"],
        json={},
    )
    assert self_approval.status_code == 409
    approved = await client.post(
        f"/v1/rbac/requests/{submitted.json()['id']}/approve",
        headers=tenant["front_headers"],
        json={},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "applied"

    changed = await client.get("/v1/rbac/policy", headers=tenant["headers"])
    assert changed.json()["settings"]["expires_after_hours"] == 48
