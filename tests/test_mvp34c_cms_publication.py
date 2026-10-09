import asyncio

from sqlalchemy import select

from app.core.audit import AuditEvent
from app.core.database import tenant_session
from app.rbac.bootstrap import TENANT_SUPER_ADMIN_ROLE_ID
from app.rbac.models import TenantRoleAssignment


async def ensure_checker(tenant):
    async with tenant_session(tenant["org"].schema_name) as db:
        existing = await db.scalar(
            select(TenantRoleAssignment).where(
                TenantRoleAssignment.user_id == tenant["front"].id,
                TenantRoleAssignment.role_id == TENANT_SUPER_ADMIN_ROLE_ID,
                TenantRoleAssignment.level == "Organization",
            )
        )
        if existing is None:
            db.add(
                TenantRoleAssignment(
                    user_id=tenant["front"].id,
                    role_id=TENANT_SUPER_ADMIN_ROLE_ID,
                    level="Organization",
                    created_by="cms-publication-test",
                    updated_by="cms-publication-test",
                )
            )


async def remove_checker(tenant):
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


async def publish_with_checker(client, tenant, revision_id, payload):
    response = await client.post(
        f"/v1/cms/revisions/{revision_id}/publish",
        headers=tenant["headers"],
        json=payload,
    )
    if response.status_code == 202:
        request_id = response.json()["request"]["id"]
        await ensure_checker(tenant)
        approved = await client.post(
            f"/v1/rbac/requests/{request_id}/approve",
            headers=tenant["front_headers"],
            json={},
        )
        assert approved.status_code == 200, approved.text
        response = await client.post(
            f"/v1/cms/revisions/{revision_id}/publish",
            headers=tenant["headers"],
            json={**payload, "approval_request_id": request_id},
        )
    return response


async def test_draft_preview_blockers_and_atomic_publication(client, tenants):
    tenant = tenants[0]
    initial_public = await client.get(f"/v1/public/tenants/{tenant['org'].slug}")
    assert initial_public.status_code == 200
    assert initial_public.json()["cms_source"] == "provisioned-default"

    draft = await client.get("/v1/cms/revisions/draft", headers=tenant["headers"])
    assert draft.status_code == 200, draft.text
    payload = draft.json()
    payload["content"]["headline"] = "Unpublished MVP 3.4-C headline"
    payload["content"]["media"] = [
        {
            "key": "hero",
            "kind": "hero",
            "file_name": "clinic-hero.jpg",
            "file_url": "",
            "mime_type": "image/jpeg",
            "alt_text": "",
            "consent": {
                "confirmed": False,
                "confirmed_by": "",
                "confirmed_at": "",
                "source": "",
                "document_reference": "",
            },
            "visible": True,
        }
    ]
    saved = await client.put(
        f"/v1/cms/revisions/{payload['id']}",
        headers=tenant["headers"],
        json={
            "content": payload["content"],
            "applicability": payload["applicability"],
            "expected_updated_at": payload["updated_at"],
        },
    )
    assert saved.status_code == 200, saved.text
    uploaded = await client.post(
        f"/v1/cms/revisions/{payload['id']}/media",
        headers=tenant["headers"],
        json={
            "key": "hero",
            "kind": "hero",
            "file_name": "clinic-hero.png",
            "mime_type": "image/png",
            "content_base64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
            "alt_text": "",
            "consent": {
                "confirmed": False,
                "confirmed_by": "",
                "confirmed_at": "",
                "source": "",
                "document_reference": "",
            },
            "visible": True,
            "expected_updated_at": saved.json()["updated_at"],
        },
    )
    assert uploaded.status_code == 200, uploaded.text
    preflight = await client.post(
        f"/v1/cms/revisions/{payload['id']}/preflight", headers=tenant["headers"]
    )
    assert preflight.status_code == 200, preflight.text
    codes = [item["code"] for item in preflight.json()["blockers"]]
    assert codes.count("media.alt.required") == 1
    assert codes.count("media.consent.required") == 1
    assert "media.file.required" not in codes

    public_before = await client.get(f"/v1/public/tenants/{tenant['org'].slug}")
    assert public_before.json()["content"]["headline"] != "Unpublished MVP 3.4-C headline"
    token = await client.post(
        f"/v1/cms/revisions/{payload['id']}/preview-token", headers=tenant["headers"]
    )
    assert token.status_code == 200, token.text
    preview = await client.get(token.json()["path"])
    assert preview.status_code == 200, preview.text
    assert preview.json()["content"]["headline"] == "Unpublished MVP 3.4-C headline"
    assert preview.json()["cms_source"] == "preview"
    preview_media_url = preview.json()["content"]["media"][0]["file_url"]
    preview_media = await client.get(preview_media_url)
    assert preview_media.status_code == 200
    assert preview_media.headers["content-type"] == "image/png"
    assert (await client.get(f"/v1/public/tenants/{tenant['org'].slug}/media/hero")).status_code == 404
    assert (await client.get("/v1/cms/preview/not-a-token")).status_code == 401

    blocked = await client.post(
        f"/v1/cms/revisions/{payload['id']}/publish",
        headers=tenant["headers"],
        json={
            "idempotency_key": "blocked-publication-1",
            "expected_updated_at": preflight.json()["revision_updated_at"],
            "confirmed_scope": "organization",
            "confirmed_location_ids": [],
        },
    )
    assert blocked.status_code == 422, blocked.text
    assert (
        await client.get(f"/v1/public/tenants/{tenant['org'].slug}")
    ).json()["content"]["headline"] != "Unpublished MVP 3.4-C headline"

    refreshed = await client.get("/v1/cms/revisions/draft", headers=tenant["headers"])
    fixed = refreshed.json()
    fixed["content"]["media"][0]["alt_text"] = "Reception area with accessible entrance"
    fixed["content"]["media"][0]["consent"] = {
        "confirmed": True,
        "confirmed_by": "Clinic content owner",
        "confirmed_at": "2026-10-02T12:00:00Z",
        "source": "written-consent-record",
        "document_reference": "CONSENT-TEST-001",
    }
    fixed_save = await client.put(
        f"/v1/cms/revisions/{fixed['id']}",
        headers=tenant["headers"],
        json={
            "content": fixed["content"],
            "applicability": fixed["applicability"],
            "expected_updated_at": fixed["updated_at"],
        },
    )
    assert fixed_save.status_code == 200, fixed_save.text
    valid = await client.post(
        f"/v1/cms/revisions/{fixed['id']}/preflight", headers=tenant["headers"]
    )
    assert valid.status_code == 200 and valid.json()["valid"], valid.text
    stale = await client.post(
        f"/v1/cms/revisions/{fixed['id']}/publish",
        headers=tenant["headers"],
        json={
            "idempotency_key": "valid-publication-1",
            "expected_updated_at": fixed_save.json()["updated_at"],
            "confirmed_scope": "organization",
            "confirmed_location_ids": [],
        },
    )
    assert stale.status_code == 409
    wrong_scope = await client.post(
        f"/v1/cms/revisions/{fixed['id']}/publish",
        headers=tenant["headers"],
        json={
            "idempotency_key": "valid-publication-1",
            "expected_updated_at": valid.json()["revision_updated_at"],
            "confirmed_scope": "location",
            "confirmed_location_ids": [tenant["location"].id],
        },
    )
    assert wrong_scope.status_code == 409
    published = await publish_with_checker(
        client,
        tenant,
        fixed["id"],
        {
            "idempotency_key": "valid-publication-1",
            "expected_updated_at": valid.json()["revision_updated_at"],
            "confirmed_scope": "organization",
            "confirmed_location_ids": [],
        },
    )
    assert published.status_code == 200, published.text
    repeated = await client.post(
        f"/v1/cms/revisions/{fixed['id']}/publish",
        headers=tenant["headers"],
        json={
            "idempotency_key": "valid-publication-1",
            "expected_updated_at": valid.json()["revision_updated_at"],
            "confirmed_scope": "organization",
            "confirmed_location_ids": [],
        },
    )
    assert repeated.status_code == 200
    assert repeated.json()["id"] == published.json()["id"]
    public_after = await client.get(f"/v1/public/tenants/{tenant['org'].slug}")
    assert public_after.json()["content"]["headline"] == "Unpublished MVP 3.4-C headline"
    assert public_after.json()["cms_source"] == "published"
    assert "consent" not in public_after.text
    published_media = await client.get(
        f"/v1/public/tenants/{tenant['org'].slug}/media/hero"
    )
    assert published_media.status_code == 200
    assert published_media.content == preview_media.content

    next_draft = await client.get("/v1/cms/revisions/draft", headers=tenant["headers"])
    next_payload = next_draft.json()
    next_payload["content"]["headline"] = "Draft must remain private"
    assert (
        await client.put(
            f"/v1/cms/revisions/{next_payload['id']}",
            headers=tenant["headers"],
            json={
                "content": next_payload["content"],
                "applicability": next_payload["applicability"],
                "expected_updated_at": next_payload["updated_at"],
            },
        )
    ).status_code == 200
    assert (
        await client.get(f"/v1/public/tenants/{tenant['org'].slug}")
    ).json()["content"]["headline"] == "Unpublished MVP 3.4-C headline"

    async with tenant_session(tenant["org"].schema_name) as db:
        blocked_event = await db.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "publish.blocked", AuditEvent.resource_id == fixed["id"]
            )
        )
        publish_event = await db.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "publish", AuditEvent.resource_id == fixed["id"]
            )
        )
        assert blocked_event is not None
        assert publish_event.details["policy_versions"]["jurisdiction"] == "CA:1"
    await client.post("/v1/rbac/notifications/seen", headers=tenant["headers"], json={})
    await remove_checker(tenant)


async def test_rollback_and_location_publication_are_explicit_actions(client, tenants):
    tenant = tenants[0]
    revisions = await client.get("/v1/cms/revisions", headers=tenant["headers"])
    original = next(item for item in revisions.json() if item["status"] == "published")
    draft = next(item for item in revisions.json() if item["status"] == "draft")
    preflight = await client.post(
        f"/v1/cms/revisions/{draft['id']}/preflight", headers=tenant["headers"]
    )
    assert preflight.status_code == 200 and preflight.json()["valid"]
    second_publication = await publish_with_checker(
        client,
        tenant,
        draft["id"],
        {
            "idempotency_key": "second-publication",
            "expected_updated_at": preflight.json()["revision_updated_at"],
            "confirmed_scope": "organization",
            "confirmed_location_ids": [],
        },
    )
    assert second_publication.status_code == 200, second_publication.text
    assert (
        await client.get(f"/v1/public/tenants/{tenant['org'].slug}")
    ).json()["content"]["headline"] == "Draft must remain private"

    rollback = await client.post(
        f"/v1/cms/revisions/{original['id']}/rollback",
        headers=tenant["headers"],
        json={
            "idempotency_key": "rollback-to-original",
            "expected_updated_at": original["updated_at"],
            "confirmed_scope": "organization",
            "confirmed_location_ids": [],
        },
    )
    assert rollback.status_code == 200, rollback.text
    assert rollback.json()["base_revision_id"] == original["id"]
    restored_headline = original["content"]["headline"]
    assert (
        await client.get(f"/v1/public/tenants/{tenant['org'].slug}")
    ).json()["content"]["headline"] == restored_headline

    location_draft = await client.get("/v1/cms/revisions/draft", headers=tenant["headers"])
    location_payload = location_draft.json()
    location_payload["content"]["headline"] = "Location-only publication"
    location_payload["applicability"] = {
        "scope": "location",
        "location_ids": [tenant["location"].id],
    }
    saved = await client.put(
        f"/v1/cms/revisions/{location_payload['id']}",
        headers=tenant["headers"],
        json={
            "content": location_payload["content"],
            "applicability": location_payload["applicability"],
            "expected_updated_at": location_payload["updated_at"],
        },
    )
    assert saved.status_code == 200, saved.text
    checked = await client.post(
        f"/v1/cms/revisions/{location_payload['id']}/preflight", headers=tenant["headers"]
    )
    assert checked.status_code == 200 and checked.json()["valid"]
    location_publish = await publish_with_checker(
        client,
        tenant,
        location_payload["id"],
        {
            "idempotency_key": "location-publication",
            "expected_updated_at": checked.json()["revision_updated_at"],
            "confirmed_scope": "location",
            "confirmed_location_ids": [tenant["location"].id],
        },
    )
    assert location_publish.status_code == 200, location_publish.text
    organization_view = await client.get(f"/v1/public/tenants/{tenant['org'].slug}")
    location_view = await client.get(
        f"/v1/public/tenants/{tenant['org'].slug}",
        params={"location_id": tenant["location"].id},
    )
    assert organization_view.json()["content"]["headline"] == restored_headline
    assert location_view.json()["content"]["headline"] == "Location-only publication"
    assert location_view.json()["cms_revision_id"] == location_publish.json()["id"]

    other_tenant = tenants[1]
    cross_tenant_revision = await client.post(
        f"/v1/cms/revisions/{location_payload['id']}/preview-token",
        headers=other_tenant["headers"],
    )
    assert cross_tenant_revision.status_code == 404
    other_public = await client.get(f"/v1/public/tenants/{other_tenant['org'].slug}")
    assert other_public.status_code == 200
    assert other_public.json()["content"]["headline"] != "Location-only publication"

    concurrent_draft = await client.get(
        "/v1/cms/revisions/draft", headers=tenant["headers"]
    )
    concurrent_check = await client.post(
        f"/v1/cms/revisions/{concurrent_draft.json()['id']}/preflight",
        headers=tenant["headers"],
    )
    assert concurrent_check.status_code == 200 and concurrent_check.json()["valid"]
    concurrent_body = {
        "idempotency_key": "concurrent-location-publication",
        "expected_updated_at": concurrent_check.json()["revision_updated_at"],
        "confirmed_scope": "location",
        "confirmed_location_ids": [tenant["location"].id],
    }
    pending_concurrent = await client.post(
        f"/v1/cms/revisions/{concurrent_draft.json()['id']}/publish",
        headers=tenant["headers"],
        json=concurrent_body,
    )
    assert pending_concurrent.status_code == 202, pending_concurrent.text
    request_id = pending_concurrent.json()["request"]["id"]
    await ensure_checker(tenant)
    approved = await client.post(
        f"/v1/rbac/requests/{request_id}/approve",
        headers=tenant["front_headers"],
        json={},
    )
    assert approved.status_code == 200, approved.text
    concurrent_body = {**concurrent_body, "approval_request_id": request_id}
    concurrent_results = await asyncio.gather(
        *[
            client.post(
                f"/v1/cms/revisions/{concurrent_draft.json()['id']}/publish",
                headers=tenant["headers"],
                json=concurrent_body,
            )
            for _ in range(2)
        ]
    )
    assert [result.status_code for result in concurrent_results] == [200, 200]
    assert len({result.json()["id"] for result in concurrent_results}) == 1

    async with tenant_session(tenant["org"].schema_name) as db:
        rollback_event = await db.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "publish.rollback",
                AuditEvent.resource_id == rollback.json()["id"],
            )
        )
        assert rollback_event.details["restored_from"] == original["id"]
    await client.post("/v1/rbac/notifications/seen", headers=tenant["headers"], json={})
    await remove_checker(tenant)
