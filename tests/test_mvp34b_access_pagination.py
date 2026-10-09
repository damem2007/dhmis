from uuid import uuid4

from sqlalchemy import select

from app.billing.models import Invoice
from app.claims.models import Claim
from app.core.audit import AuditEvent
from app.core.database import tenant_session
from app.core.repository import add
from app.identity.models import StaffLocationAssignment, StaffUser
from app.identity.passwords import hash_password
from app.identity.service import issue_token
from app.organizations.models import Location


async def test_location_roles_are_effective_without_permission_union(client, tenants):
    tenant = tenants[0]
    async with tenant_session(tenant["org"].schema_name) as db:
        second = await add(db, Location, {"name": "MVP 3.4-B second location"}, "test")
        worker = await add(
            db,
            StaffUser,
            {
                "name": "MVP 3.4-B scoped staff",
                "email": "mvp34b-scoped@example.test",
                "role": "front-desk",
                "password_hash": hash_password("Verification-password-2026!"),
                "mfa_enabled": True,
                "location_ids": [tenant["location"].id],
            },
            "test",
        )
        db.add(
            StaffLocationAssignment(
                user_id=worker.id,
                location_id=tenant["location"].id,
                scope="location",
                role="front-desk",
                active=True,
                created_by="test",
                updated_by="test",
            )
        )
        await db.flush()

    changed = await client.put(
        f"/v1/organization/staff/{worker.id}",
        headers=tenant["headers"],
        json={
            "active": True,
            "assignments": [
                {
                    "scope": "location",
                    "location_id": tenant["location"].id,
                    "role": "front-desk",
                },
                {"scope": "location", "location_id": second.id, "role": "billing"},
            ],
        },
    )
    assert changed.status_code == 200, changed.text

    async with tenant_session(tenant["org"].schema_name) as db:
        worker = await db.get(StaffUser, worker.id)
        token = await issue_token(db, worker, tenant["org"])
        access_event = await db.scalar(
            select(AuditEvent)
            .where(AuditEvent.action == "access.update", AuditEvent.resource_id == worker.id)
            .order_by(AuditEvent.created_at.desc())
        )
        assert any(change["to"] == "billing" for change in access_event.details["changes"])

    headers = {"Authorization": f"Bearer {token}"}
    first = await client.get(
        "/v1/auth/me",
        headers={**headers, "X-DHMIS-Location": tenant["location"].id},
    )
    second_role = await client.get(
        "/v1/auth/me", headers={**headers, "X-DHMIS-Location": second.id}
    )
    assert first.status_code == second_role.status_code == 200
    assert first.json()["role"] == "front-desk"
    assert "scheduling" in first.json()["permissions"]
    assert "claims" not in first.json()["permissions"]
    assert second_role.json()["role"] == "billing"
    assert "claims" in second_role.json()["permissions"]
    assert "scheduling" not in second_role.json()["permissions"]
    outside = await client.get(
        "/v1/auth/me",
        headers={**headers, "X-DHMIS-Location": str(uuid4())},
    )
    assert outside.status_code == 403

    page = await client.get(
        "/v1/organization/access/query",
        headers=tenant["headers"],
        params={
            "kind": "staff",
            "page": 1,
            "page_size": 10,
            "role": "billing",
            "location_id": second.id,
        },
    )
    assert page.status_code == 200, page.text
    assert page.json()["page_size"] == 10
    assert any(item["id"] == worker.id for item in page.json()["items"])

    replaced = await client.put(
        f"/v1/organization/staff/{worker.id}",
        headers=tenant["headers"],
        json={
            "active": True,
            "assignments": [
                {
                    "scope": "location",
                    "location_id": tenant["location"].id,
                    "role": "front-desk",
                },
                {"scope": "location", "location_id": second.id, "role": "accounting"},
            ],
        },
    )
    assert replaced.status_code == 200, replaced.text
    assert {
        "scope": "location",
        "location_id": second.id,
        "from": "billing",
        "to": "accounting",
    } in replaced.json()["changes"]


async def test_invitation_and_claim_worklists_are_server_paginated(client, tenants):
    tenant = tenants[0]
    email = "mvp34b-invite@example.test"
    invitation = await client.post(
        "/v1/organization/invites",
        headers=tenant["headers"],
        json={
            "name": "MVP 3.4-B invite",
            "email": email,
            "assignments": [
                {
                    "scope": "location",
                    "location_id": tenant["location"].id,
                    "role": "hygienist",
                }
            ],
        },
    )
    assert invitation.status_code == 201, invitation.text
    duplicate = await client.post(
        "/v1/organization/invites",
        headers=tenant["headers"],
        json={
            "name": "Duplicate pending scope",
            "email": email,
            "assignments": [
                {
                    "scope": "location",
                    "location_id": tenant["location"].id,
                    "role": "dentist",
                }
            ],
        },
    )
    assert duplicate.status_code == 409
    invite_page = await client.get(
        "/v1/organization/access/query",
        headers=tenant["headers"],
        params={"kind": "invitation", "page_size": 10, "search": email},
    )
    assert invite_page.status_code == 200, invite_page.text
    assert invite_page.json()["total"] == 1
    assert invite_page.json()["items"][0]["assignments"][0]["role"] == "hygienist"

    async with tenant_session(tenant["org"].schema_name) as db:
        invoice = await add(
            db,
            Invoice,
            {
                "patient_id": tenant["patient"].id,
                "location_id": tenant["location"].id,
                "provider_id": tenant["user"].id,
                "lines": [],
                "total_cents": 10000,
                "paid_cents": 0,
            },
            "test",
        )
        for number in range(12):
            await add(
                db,
                Claim,
                {
                    "invoice_id": invoice.id,
                    "location_id": tenant["location"].id,
                    "network": "mvp34b-test",
                    "status": "submitted",
                    "reference": f"MVP34B-{number}",
                    "submitted_cents": 10000,
                },
                "test",
            )

    first = await client.get(
        "/v1/claims/query",
        headers=tenant["headers"],
        params={"page": 1, "page_size": 10, "network": "mvp34b-test"},
    )
    second = await client.get(
        "/v1/claims/query",
        headers=tenant["headers"],
        params={"page": 2, "page_size": 10, "network": "mvp34b-test"},
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["total"] == second.json()["total"] == 12
    assert len(first.json()["items"]) == 10
    assert len(second.json()["items"]) == 2
    assert {item["id"] for item in first.json()["items"]}.isdisjoint(
        {item["id"] for item in second.json()["items"]}
    )

    revoked = await client.post(
        f"/v1/organization/invites/{invitation.json()['invite_id']}/revoke",
        headers=tenant["headers"],
    )
    assert revoked.status_code == 200, revoked.text
    audit_page = await client.get(
        "/v1/organization/audit/query",
        headers=tenant["headers"],
        params={"page": 1, "page_size": 10, "action": "invite.revoke"},
    )
    assert audit_page.status_code == 200, audit_page.text
    assert audit_page.json()["total"] >= 1
    assert all(item["action"] == "invite.revoke" for item in audit_page.json()["items"])
    exported = await client.get(
        "/v1/organization/audit/export",
        headers=tenant["headers"],
        params={"action": "invite.revoke"},
    )
    assert exported.status_code == 200, exported.text
    assert "invite.revoke" in exported.text
