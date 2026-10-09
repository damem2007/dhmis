import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.billing.models import LedgerEntry
from app.core.audit import AuditEvent
from app.core.config import settings
from app.core.database import tenant_session
from app.identity.security import totp
from app.notifications.models import OutboxMessage
from app.organizations.provisioning import migrate_schema
from app.patients.models import Patient


async def invoice(client, tenant):
    response = await client.post(
        "/v1/billing/invoices",
        headers=tenant["headers"],
        json={"patient_id": tenant["patient"].id, "service_ids": [tenant["service"].id]},
    )
    assert response.status_code == 201, response.text
    return response.json()


async def test_authentication_and_staff_audience(client, tenants):
    t = tenants[0]
    assert (await client.get("/v1/patients")).status_code == 401
    response = await client.post(
        "/v1/auth/staff/login",
        json={
            "organization_id": t["org"].id,
            "email": "admin@example.test",
            "password": "Verification-password-2026!",
        },
    )
    assert response.status_code == 200
    bad = await client.post(
        "/v1/auth/staff/login",
        json={"organization_id": t["org"].id, "email": "admin@example.test", "password": "wrong"},
    )
    assert bad.status_code == 401
    assert response.json()["mfa_required"] is True
    challenge = {
        "organization_id": t["org"].id,
        "challenge_token": response.json()["challenge_token"],
        "code": totp(t["secret"]),
    }
    verified = await client.post("/v1/auth/mfa/verify", json=challenge)
    assert verified.status_code == 200, verified.text
    assert (await client.post("/v1/auth/mfa/verify", json=challenge)).status_code == 401
    payload = jwt.decode(
        verified.json()["access_token"],
        settings().jwt_secret.get_secret_value(),
        algorithms=["HS256"],
        audience="dhmis-staff",
    )
    payload["aud"] = "dhmis-patient"
    forged = jwt.encode(payload, settings().jwt_secret.get_secret_value(), algorithm="HS256")
    assert (
        await client.get("/v1/patients", headers={"Authorization": "Bearer " + forged})
    ).status_code == 401


async def test_patient_persistence_and_tenant_boundary(client, tenants):
    a, b = tenants
    result = await client.post(
        "/v1/patients",
        headers=a["headers"],
        json={
            "first_name": "Persisted",
            "last_name": "Verification",
            "birth_date": "2000-01-01",
            "phone": "604-555-0198",
            "location_id": a["location"].id,
        },
    )
    assert result.status_code == 201
    identifier = result.json()["id"]
    async with tenant_session(a["org"].schema_name) as db:
        assert (await db.get(Patient, identifier)).first_name == "Persisted"
    async with tenant_session(b["org"].schema_name) as db:
        assert await db.get(Patient, identifier) is None
    response = await client.get(f"/v1/clinical/{identifier}", headers=b["headers"])
    assert response.status_code == 404
    response = await client.post(
        "/v1/patients",
        headers=a["headers"],
        json={
            "first_name": "Invalid",
            "last_name": "Location",
            "birth_date": "2000-01-01",
            "phone": "604-555-0198",
            "location_id": b["location"].id,
        },
    )
    assert response.status_code == 404


async def test_role_denial_is_persisted(client, tenants):
    t = tenants[0]
    response = await client.get(
        "/v1/billing/invoices", headers=t["front_headers"]
    )
    assert response.status_code == 403
    async with tenant_session(t["org"].schema_name) as db:
        assert await db.scalar(select(AuditEvent).where(AuditEvent.action == "access.denied"))


async def test_concurrent_booking_reschedule_cancel_and_outbox(client, tenants):
    t = tenants[0]
    start = (datetime.now(timezone.utc) + timedelta(days=30)).replace(
        hour=17, minute=0, second=0, microsecond=0
    )
    body = {
        "patient_id": t["patient"].id,
        "provider_id": t["user"].id,
        "location_id": t["location"].id,
        "chair": "Op 1",
        "starts_at": start.isoformat(),
        "ends_at": (start + timedelta(minutes=45)).isoformat(),
        "procedure": "Verification booking",
    }
    responses = await asyncio.gather(
        *[client.post("/v1/appointments", headers=t["headers"], json=body) for _ in range(2)]
    )
    assert sorted(r.status_code for r in responses) == [201, 409]
    booking = next(r.json() for r in responses if r.status_code == 201)
    body.update(
        starts_at=(start + timedelta(hours=2)).isoformat(), ends_at=(start + timedelta(hours=3)).isoformat()
    )
    assert (
        await client.put("/v1/appointments/" + booking["id"], headers=t["headers"], json=body)
    ).status_code == 200
    assert (
        await client.post(
            "/v1/appointments/" + booking["id"] + "/cancel",
            headers=t["headers"],
            json={"reason": "Verification complete"},
        )
    ).json()["status"] == "cancelled"
    async with tenant_session(t["org"].schema_name) as db:
        assert len((await db.scalars(select(OutboxMessage))).all()) >= 2


async def test_invoice_payment_replay_and_overpayment(client, tenants):
    t = tenants[0]
    record = await invoice(client, t)
    path = "/v1/billing/invoices/" + record["id"] + "/payments"
    body = {"amount_cents": 2500, "idempotency_key": str(uuid4())}
    first, repeat = await asyncio.gather(
        *[client.post(path, headers=t["headers"], json=body) for _ in range(2)]
    )
    assert first.status_code == repeat.status_code == 200
    assert first.json()["id"] == repeat.json()["id"]
    changed = await client.post(path, headers=t["headers"], json={**body, "amount_cents": 1000})
    assert changed.status_code == 409
    too_much = await client.post(
        path, headers=t["headers"], json={"amount_cents": 10001, "idempotency_key": str(uuid4())}
    )
    assert too_much.status_code == 422
    async with tenant_session(t["org"].schema_name) as db:
        entries = (await db.scalars(select(LedgerEntry).where(LedgerEntry.invoice_id == record["id"]))).all()
        assert sum(e.amount_cents for e in entries) == 7500


async def test_claim_reconciliation_is_idempotent(client, tenants):
    t = tenants[0]
    record = await invoice(client, t)
    response = await client.post(
        "/v1/claims",
        headers=t["headers"],
        json={"invoice_id": record["id"], "plan_id": t["plan"].id, "idempotency_key": str(uuid4())},
    )
    assert response.status_code == 201
    claim = response.json()
    assert (
        await client.post("/v1/claims/" + claim["id"] + "/reconcile", headers=t["headers"], json={})
    ).status_code == 409
    assert (
        await client.post("/v1/claims/" + claim["id"] + "/adjudicate", headers=t["headers"], json={})
    ).json()["covered_cents"] == 8000
    for _ in range(2):
        response = await client.post(
            "/v1/claims/" + claim["id"] + "/reconcile", headers=t["headers"], json={}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "paid"
    async with tenant_session(t["org"].schema_name) as db:
        entries = (await db.scalars(select(LedgerEntry).where(LedgerEntry.invoice_id == record["id"]))).all()
        assert sum(e.amount_cents for e in entries) == 2000
        assert len(entries) == 2


async def test_charting_and_draft_perio(client, tenants):
    t = tenants[0]
    response = await client.post(
        "/v1/clinical/entries",
        headers=t["headers"],
        json={
            "patient_id": t["patient"].id,
            "tooth": 14,
            "surface": "occlusal",
            "condition": "Test observation",
            "notes": "Synthetic verification record",
        },
    )
    assert response.status_code == 201
    invalid = await client.post(
        "/v1/clinical/perio",
        headers=t["headers"],
        json={"patient_id": t["patient"].id, "dentition": ["14"], "measurements": {"14": [2, 3]}},
    )
    assert invalid.status_code == 422
    response = await client.post(
        "/v1/clinical/perio",
        headers=t["headers"],
        json={
            "patient_id": t["patient"].id,
            "dentition": ["14"],
            "measurements": {
                "14": {
                    "depths": [2, 3, 2, 3, 2, 3],
                    "bleeding": [False] * 6,
                    "recession": [0] * 6,
                    "furcation": 0,
                    "mobility": 0,
                }
            },
        },
    )
    assert response.status_code == 201
    assert response.json()["status"] == "draft"
    chart = await client.get("/v1/clinical/" + t["patient"].id, headers=t["headers"])
    assert len(chart.json()["entries"]) >= 1


async def test_consent_simulation_persists(client, tenants):
    t = tenants[0]
    response = await client.post(
        "/v1/consents",
        headers=t["headers"],
        json={"patient_id": t["patient"].id, "title": "Verification consent"},
    )
    assert response.status_code == 201
    response = await client.post(
        "/v1/consents/" + response.json()["id"] + "/simulate-signature", headers=t["headers"], json={}
    )
    assert response.status_code == 200
    assert response.json()["certificate"]["sandbox"] is True
    assert response.json()["status"] == "simulated"


async def test_audit_cannot_be_updated(client, tenants):
    t = tenants[0]
    await client.get("/v1/patients", headers=t["headers"])
    with pytest.raises(DBAPIError):
        async with tenant_session(t["org"].schema_name) as db:
            await db.execute(text("UPDATE audit_events SET action = :action"), {"action": "tamper"})


async def test_migrations_can_be_reapplied(tenants):
    t = tenants[0]
    await migrate_schema(t["org"].schema_name)
    async with tenant_session(t["org"].schema_name) as db:
        assert await db.scalar(text("SELECT version_num FROM alembic_version")) == "0019"
        assert await db.get(Patient, t["patient"].id)


async def test_dashboard_uses_saved_records(client, tenants):
    t = tenants[0]
    response = await client.get("/v1/dashboard", headers=t["headers"])
    assert response.status_code == 200
    assert response.json()["patient_count"] >= 1
    assert isinstance(response.json()["balance_cents"], int)
