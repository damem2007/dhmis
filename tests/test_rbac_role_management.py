from app.core.database import tenant_session
from app.rbac.bootstrap import seed_tenant_super_admin
from app.rbac.runtime import decide_tenant


async def test_tenant_role_lifecycle_grants_assignment_and_isolation(client, tenants):
    tenant = tenants[0]
    async with tenant_session(tenant["org"].schema_name) as db:
        await seed_tenant_super_admin(db, "test-role-management")

    created = await client.post(
        "/v1/rbac/roles",
        headers=tenant["headers"],
        json={"name": "Reporting reader", "description": "Reads the role dashboard."},
    )
    assert created.status_code == 201, created.text
    role = created.json()
    assert role["status"] == "draft"

    duplicate = await client.post(
        "/v1/rbac/roles",
        headers=tenant["headers"],
        json={"name": "reporting READER"},
    )
    assert duplicate.status_code == 409

    grants = await client.put(
        f"/v1/rbac/roles/{role['id']}/grants",
        headers=tenant["headers"],
        json={
            "version": role["version"],
            "grants": [
                {
                    "permission_key": "reports.role_dashboard.read",
                    "effect": "allow",
                    "scope": "Organization",
                }
            ],
        },
    )
    assert grants.status_code == 200, grants.text
    assert grants.json()["role"]["permission_count"] == 1

    published = await client.post(
        f"/v1/rbac/roles/{role['id']}/publish",
        headers=tenant["headers"],
    )
    assert published.status_code == 200, published.text
    assert published.json()["status"] == "published"

    immutable = await client.patch(
        f"/v1/rbac/roles/{role['id']}",
        headers=tenant["headers"],
        json={"name": "Changed published role", "version": published.json()["version"]},
    )
    assert immutable.status_code == 409

    assigned = await client.post(
        "/v1/rbac/assignments",
        headers=tenant["headers"],
        json={
            "user_id": tenant["front"].id,
            "role_id": role["id"],
            "level": "Organization",
        },
    )
    assert assigned.status_code == 201, assigned.text

    async with tenant_session(tenant["org"].schema_name) as db:
        decision = await decide_tenant(
            db,
            tenant["front"].id,
            "reports.role_dashboard.read",
        )
        assert decision.allowed

    archive_while_held = await client.post(
        f"/v1/rbac/roles/{role['id']}/archive",
        headers=tenant["headers"],
    )
    assert archive_while_held.status_code == 409

    unassigned = await client.delete(
        f"/v1/rbac/assignments/{assigned.json()['id']}",
        headers=tenant["headers"],
    )
    assert unassigned.status_code == 200

    archived = await client.post(
        f"/v1/rbac/roles/{role['id']}/archive",
        headers=tenant["headers"],
    )
    assert archived.status_code == 200, archived.text
    assert archived.json()["status"] == "archived"

    restored = await client.post(
        f"/v1/rbac/roles/{role['id']}/restore",
        headers=tenant["headers"],
    )
    assert restored.status_code == 200
    assert restored.json()["status"] == "inactive"

    other_tenant = tenants[1]
    async with tenant_session(other_tenant["org"].schema_name) as db:
        await seed_tenant_super_admin(db, "test-cross-tenant-role-read")
    missing = await client.get(
        f"/v1/rbac/roles/{role['id']}",
        headers=other_tenant["headers"],
    )
    assert missing.status_code == 404


async def test_grant_validation_clears_dependents_and_rejects_wrong_domain(client, tenants):
    tenant = tenants[0]
    async with tenant_session(tenant["org"].schema_name) as db:
        await seed_tenant_super_admin(db, "test-grant-validation")

    created = await client.post(
        "/v1/rbac/roles",
        headers=tenant["headers"],
        json={"name": "Refund draft"},
    )
    role = created.json()
    initial = await client.put(
        f"/v1/rbac/roles/{role['id']}/grants",
        headers=tenant["headers"],
        json={
            "version": role["version"],
            "grants": [
                {
                    "permission_key": f"billing.payment.{action}",
                    "effect": "allow",
                    "scope": "Organization",
                }
                for action in ("read", "update", "refund")
            ],
        },
    )
    assert initial.status_code == 200, initial.text

    lowered = await client.put(
        f"/v1/rbac/roles/{role['id']}/grants",
        headers=tenant["headers"],
        json={
            "version": initial.json()["role"]["version"],
            "grants": [
                {
                    "permission_key": "billing.payment.refund",
                    "effect": "allow",
                    "scope": "Organization",
                }
            ],
        },
    )
    assert lowered.status_code == 200, lowered.text
    assert lowered.json()["cleared_dependents"] == ["billing.payment.refund"]
    assert lowered.json()["role"]["permission_count"] == 0

    wrong_domain = await client.put(
        f"/v1/rbac/roles/{role['id']}/grants",
        headers=tenant["headers"],
        json={
            "version": lowered.json()["role"]["version"],
            "grants": [
                {
                    "permission_key": "access.platform_user.read",
                    "effect": "allow",
                    "scope": "Organization",
                }
            ],
        },
    )
    assert wrong_domain.status_code == 422
    issue = wrong_domain.json()["detail"]["issues"][0]
    assert issue["code"] == "unknown_permission"
