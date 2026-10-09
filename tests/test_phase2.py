import base64
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select, text

from app.core.database import tenant_session
from app.documents.models import Document
from app.integrations.registry import provider_options
from app.messaging.models import Message


async def patient_session(client, tenant):
    invitation = await client.post(
        "/v1/portal/invites",
        headers=tenant["headers"],
        json={"patient_id": tenant["patient"].id, "email": "patient@example.test"},
    )
    assert invitation.status_code == 201, invitation.text
    accepted = await client.post(
        "/v1/portal/auth/accept",
        json={
            "organization_id": tenant["org"].id,
            "token": invitation.json()["token"],
            "password": "Patient-password-2026!",
        },
    )
    assert accepted.status_code == 200, accepted.text
    logged_in = await client.post(
        "/v1/portal/auth/login",
        json={
            "organization_id": tenant["org"].id,
            "email": "patient@example.test",
            "password": "Patient-password-2026!",
        },
    )
    assert logged_in.status_code == 200, logged_in.text
    return {"Authorization": "Bearer " + logged_in.json()["access_token"]}


async def test_patient_identity_audience_family_scope_and_revocation(client, tenants):
    tenant = tenants[0]
    headers = await patient_session(client, tenant)
    assert (await client.get("/v1/portal/me", headers=headers)).status_code == 200
    assert (await client.get("/v1/portal/me", headers=tenant["headers"])).status_code == 401
    assert (await client.get("/v1/patients", headers=headers)).status_code == 401

    dependent = await client.post(
        "/v1/patients",
        headers=tenant["headers"],
        json={
            "first_name": "Portal",
            "last_name": "Dependent",
            "birth_date": "2015-03-04",
            "email": "dependent@example.test",
            "phone": "604-555-0110",
            "location_id": tenant["location"].id,
        },
    )
    assert dependent.status_code == 201, dependent.text
    linked = await client.post(
        "/v1/patients/guardian-links",
        headers=tenant["headers"],
        json={
            "guardian_id": tenant["patient"].id,
            "dependent_id": dependent.json()["id"],
            "relationship": "Parent",
        },
    )
    assert linked.status_code == 201, linked.text
    unrelated = await client.post(
        "/v1/patients",
        headers=tenant["headers"],
        json={
            "first_name": "Outside",
            "last_name": "Family",
            "birth_date": "1992-05-06",
            "email": "outside@example.test",
            "phone": "604-555-0111",
            "location_id": tenant["location"].id,
        },
    )
    profiles = await client.get("/v1/portal/profiles", headers=headers)
    assert {row["id"] for row in profiles.json()} == {
        tenant["patient"].id,
        dependent.json()["id"],
    }
    denied = await client.get(
        "/v1/portal/statements/" + unrelated.json()["id"], headers=headers
    )
    assert denied.status_code == 403

    logged_out = await client.post("/v1/portal/auth/logout", headers=headers)
    assert logged_out.status_code == 200
    assert (await client.get("/v1/portal/me", headers=headers)).status_code == 401


async def test_portal_shared_scheduling_billing_forms_and_messages(client, tenants):
    tenant = tenants[1]
    headers = await patient_session(client, tenant)
    start = (datetime.now(timezone.utc) + timedelta(days=40)).replace(
        hour=17, minute=0, second=0, microsecond=0
    )
    booking = {
        "patient_id": tenant["patient"].id,
        "provider_id": tenant["user"].id,
        "location_id": tenant["location"].id,
        "chair": "Op 1",
        "starts_at": start.isoformat(),
        "ends_at": (start + timedelta(minutes=30)).isoformat(),
        "procedure": "Portal exam",
    }
    created = await client.post("/v1/portal/appointments", headers=headers, json=booking)
    assert created.status_code == 201, created.text
    conflict = await client.post("/v1/appointments", headers=tenant["headers"], json=booking)
    assert conflict.status_code == 409
    cancelled = await client.post(
        "/v1/portal/appointments/" + created.json()["id"] + "/cancel",
        headers=headers,
        json={"reason": "Portal verification"},
    )
    assert cancelled.json()["status"] == "cancelled"

    invoice = await client.post(
        "/v1/billing/invoices",
        headers=tenant["headers"],
        json={"patient_id": tenant["patient"].id, "service_ids": [tenant["service"].id]},
    )
    plan = await client.post(
        f"/v1/portal/invoices/{invoice.json()['id']}/payment-plan",
        headers=headers,
        json={
            "installments": 3,
            "first_due": (datetime.now(timezone.utc) + timedelta(days=10)).date().isoformat(),
        },
    )
    assert plan.status_code == 201, plan.text
    assert len(plan.json()["installments"]) == 3
    payment = await client.post(
        f"/v1/portal/invoices/{invoice.json()['id']}/payments",
        headers=headers,
        json={"amount_cents": 2000, "idempotency_key": str(uuid4())},
    )
    assert payment.status_code == 200, payment.text
    statement = await client.get(
        "/v1/portal/statements/" + tenant["patient"].id, headers=headers
    )
    assert statement.status_code == 200

    template = await client.post(
        "/v1/forms/templates",
        headers=tenant["headers"],
        json={
            "title": "Medical intake",
            "version": "1",
            "fields": [{"name": "medications", "label": "Medications", "type": "text"}],
        },
    )
    assert template.status_code == 201, template.text
    submission = await client.post(
        "/v1/portal/forms/" + template.json()["id"],
        headers=headers,
        json={"patient_id": tenant["patient"].id, "responses": {"medications": "None"}},
    )
    assert submission.status_code == 201, submission.text
    assert submission.json()["template_version"] == "1"

    consent = await client.post(
        "/v1/consents",
        headers=tenant["headers"],
        json={"patient_id": tenant["patient"].id, "title": "Portal treatment consent"},
    )
    signed = await client.post(
        "/v1/portal/consents/" + consent.json()["id"] + "/sign", headers=headers
    )
    assert signed.status_code == 200, signed.text
    assert signed.json()["status"] == "simulated"
    assert signed.json()["certificate"]["sandbox"] is True

    thread = await client.post(
        "/v1/portal/threads",
        headers=headers,
        json={
            "patient_id": tenant["patient"].id,
            "subject": "Post-visit question",
            "body": "Is mild sensitivity expected?",
        },
    )
    assert thread.status_code == 201, thread.text
    staff_view = await client.get("/v1/messages/" + thread.json()["id"], headers=tenant["headers"])
    assert staff_view.json()["messages"][0]["body"] == "Is mild sensitivity expected?"
    async with tenant_session(tenant["org"].schema_name) as db:
        stored = await db.scalar(select(Message).where(Message.thread_id == thread.json()["id"]))
        assert "sensitivity" not in stored.body_cipher


async def test_documents_cms_public_booking_and_provider_seam(client, tenants):
    tenant = tenants[0]
    payload = b"synthetic dental image"
    document = await client.post(
        "/v1/documents",
        headers=tenant["headers"],
        json={
            "patient_id": tenant["patient"].id,
            "category": "image",
            "filename": "verification.webp",
            "mime_type": "image/webp",
            "content_base64": base64.b64encode(payload).decode(),
            "description": "Before image",
            "comparison_group": "case-1",
        },
    )
    assert document.status_code == 201, document.text
    downloaded = await client.get(
        "/v1/documents/file/" + document.json()["id"], headers=tenant["headers"]
    )
    assert downloaded.content == payload
    async with tenant_session(tenant["org"].schema_name) as db:
        assert (await db.get(Document, document.json()["id"])).content == payload

    content = {
        "headline": "Care that fits your life",
        "introduction": "Book from the clinic's current service catalog.",
        "contact_email": "hello@example.test",
        "contact_phone": "604-555-0100",
        "logo_url": "",
    }
    assert (
        await client.put("/v1/cms", headers=tenant["headers"], json=content)
    ).status_code == 200
    storefront = await client.get("/v1/public/organizations/" + tenant["org"].id)
    assert storefront.status_code == 200
    service = next(row for row in storefront.json()["services"] if row["id"] == tenant["service"].id)
    assert service["fee_cents"] == 10000
    assert set(service) == {"id", "code", "name", "fee_cents", "icon", "description", "fee_mode"}

    availability = await client.get(
        f"/v1/public/organizations/{tenant['org'].id}/availability",
        params={
            "location_id": tenant["location"].id,
            "provider_id": tenant["user"].id,
            "day": (datetime.now(timezone.utc) + timedelta(days=50)).date().isoformat(),
        },
    )
    assert availability.status_code == 200, availability.text
    assert availability.json()
    slot = availability.json()[0]
    public_booking = await client.post(
        f"/v1/public/organizations/{tenant['org'].id}/appointments",
        json={
            "first_name": "Public",
            "last_name": "Booking",
            "birth_date": "1991-02-03",
            "email": "public-booking@example.test",
            "phone": "604-555-0102",
            "location_id": tenant["location"].id,
            "provider_id": tenant["user"].id,
            "chair": "Op 1",
            "starts_at": slot["starts_at"],
            "ends_at": slot["ends_at"],
            "procedure": "Public consultation",
        },
    )
    assert public_booking.status_code == 201, public_booking.text

    hidden = provider_options(include_live=False)
    selectable = provider_options(include_live=True)
    assert "smtp" not in hidden["email_provider"]
    assert {"smtp", "mailjet"}.issubset(selectable["email_provider"])
    assert set(hidden["payment_gateway"]) == {"sandbox", "sandbox-decline", "sandbox-timeout"}


async def test_phase2_migration_is_current(tenants):
    for tenant in tenants:
        async with tenant_session(tenant["org"].schema_name) as db:
            assert await db.scalar(text("SELECT version_num FROM alembic_version")) == "0019"
            assert await db.scalar(text("SELECT to_regclass('patient_sessions')")) == "patient_sessions"
