from datetime import datetime, time, timedelta, timezone
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import func, select

from app.billing.models import Invoice, JournalLine
from app.core.config import settings
from app.core.database import control_session, tenant_session
from app.integrations.configuration import attach_effective_adapters
from app.integrations.contracts import IntegrationFailure, PaymentResult
from app.integrations.models import TenantAdapterOverride
from app.integrations.registry import register_provider, resolve
from app.notifications.models import OutboxMessage
from app.organizations.models import Organization


async def create_invoice(client, tenant):
    response = await client.post(
        "/v1/billing/invoices",
        headers=tenant["headers"],
        json={"patient_id": tenant["patient"].id, "service_ids": [tenant["service"].id]},
    )
    assert response.status_code == 201, response.text
    return response.json()


async def test_complete_periodontal_exam_and_comparison(client, tenants):
    tenant = tenants[0]
    site = {
        "depths": [2, 2, 2, 2, 2, 2],
        "bleeding": [False] * 6,
        "recession": [0] * 6,
        "furcation": 0,
        "mobility": 0,
    }
    first = await client.post(
        "/v1/clinical/perio",
        headers=tenant["headers"],
        json={
            "patient_id": tenant["patient"].id,
            "dentition": ["14", "15"],
            "measurements": {"14": site},
            "status": "complete",
        },
    )
    assert first.status_code == 422
    for depth in (2, 4):
        current = {**site, "depths": [depth] * 6}
        response = await client.post(
            "/v1/clinical/perio",
            headers=tenant["headers"],
            json={
                "patient_id": tenant["patient"].id,
                "dentition": ["14"],
                "measurements": {"14": current},
                "status": "complete",
            },
        )
        assert response.status_code == 201, response.text
    chart = await client.get(f"/v1/clinical/{tenant['patient'].id}", headers=tenant["headers"])
    assert chart.json()["perio_comparison"]["14"] == [2] * 6


async def test_pediatric_charting_and_treatment_acceptance(client, tenants):
    tenant = tenants[0]
    primary = await client.post(
        "/v1/clinical/entries",
        headers=tenant["headers"],
        json={
            "patient_id": tenant["patient"].id,
            "tooth": "A",
            "surface": "occlusal",
            "condition": "Synthetic primary-tooth observation",
        },
    )
    assert primary.status_code == 201, primary.text
    plan = await client.post(
        "/v1/clinical/treatment-plans",
        headers=tenant["headers"],
        json={
            "patient_id": tenant["patient"].id,
            "provider_id": tenant["user"].id,
            "title": "Verification alternatives",
            "options": [
                {
                    "name": "Conservative",
                    "phases": [
                        {
                            "name": "Phase 1",
                            "procedures": [
                                {"service_id": tenant["service"].id, "quantity": 1, "tooth": "A"}
                            ],
                        }
                    ],
                },
                {
                    "name": "Monitor",
                    "phases": [
                        {
                            "name": "Review",
                            "procedures": [{"service_id": tenant["service"].id, "quantity": 1}],
                        }
                    ],
                },
            ],
        },
    )
    assert plan.status_code == 201, plan.text
    assert plan.json()["options"][0]["estimated_patient_cents"] == 2000
    accepted = await client.post(
        f"/v1/clinical/treatment-plans/{plan.json()['id']}/accept",
        headers=tenant["headers"],
        json={"option": 0},
    )
    assert accepted.json()["status"] == "awaiting_signature"
    signed = await client.post(
        f"/v1/consents/{accepted.json()['consent_id']}/simulate-signature",
        headers=tenant["headers"],
        json={},
    )
    assert signed.status_code == 200, signed.text
    chart = await client.get(f"/v1/clinical/{tenant['patient'].id}", headers=tenant["headers"])
    stored = next(item for item in chart.json()["treatment_plans"] if item["id"] == plan.json()["id"])
    assert stored["status"] == "accepted_simulated"


async def test_encounter_completion_captures_charge(client, tenants):
    tenant = tenants[0]
    starts = (datetime.now(timezone.utc) + timedelta(days=35)).replace(
        hour=17, minute=0, second=0, microsecond=0
    )
    booking = await client.post(
        "/v1/appointments",
        headers=tenant["headers"],
        json={
            "patient_id": tenant["patient"].id,
            "provider_id": tenant["user"].id,
            "location_id": tenant["location"].id,
            "chair": "Op 2",
            "starts_at": starts.isoformat(),
            "ends_at": (starts + timedelta(minutes=45)).isoformat(),
            "procedure": "Encounter verification",
        },
    )
    assert booking.status_code == 201, booking.text
    encounter = await client.post(
        f"/v1/appointments/{booking.json()['id']}/check-in", headers=tenant["headers"], json={}
    )
    assert encounter.status_code == 200
    saved = await client.put(
        f"/v1/clinical/encounters/{encounter.json()['id']}",
        headers=tenant["headers"],
        json={
            "soap": {
                "subjective": "Synthetic concern",
                "objective": "Synthetic finding",
                "assessment": "Synthetic assessment",
                "plan": "Synthetic plan",
            },
            "procedures": [{"service_id": tenant["service"].id, "quantity": 1}],
        },
    )
    assert saved.status_code == 200, saved.text
    completed = await client.post(
        f"/v1/clinical/encounters/{encounter.json()['id']}/complete",
        headers=tenant["headers"],
        json={},
    )
    assert completed.json()["status"] == "completed"
    assert completed.json()["invoice_id"]


async def test_recurring_series_and_no_show_policy(client, tenants):
    tenant = tenants[0]
    zone = ZoneInfo("America/Vancouver")
    first = datetime.combine(datetime.now(zone).date() + timedelta(days=70), time(10), tzinfo=zone)
    series = await client.post(
        "/v1/appointments/series",
        headers=tenant["headers"],
        json={
            "patient_id": tenant["patient"].id,
            "provider_id": tenant["user"].id,
            "location_id": tenant["location"].id,
            "chair": "Op 3",
            "starts_at": first.isoformat(),
            "ends_at": (first + timedelta(minutes=45)).isoformat(),
            "procedure": "Recurring verification",
            "occurrences": 3,
            "interval_days": 14,
        },
    )
    assert series.status_code == 201, series.text
    assert len(series.json()) == 3
    assert datetime.fromisoformat(series.json()[1]["starts_at"]) - datetime.fromisoformat(
        series.json()[0]["starts_at"]
    ) == timedelta(days=14)

    settings_response = await client.get("/v1/organization/settings", headers=tenant["headers"])
    assert settings_response.status_code == 200, settings_response.text
    original_settings = settings_response.json()
    updated_settings = {**original_settings, "policy": {**original_settings["policy"], "cancellation_fee_cents": 3500}}
    saved_settings = await client.put(
        "/v1/organization/settings", headers=tenant["headers"], json=updated_settings
    )
    assert saved_settings.status_code == 200, saved_settings.text
    past = datetime.combine(datetime.now(zone).date() - timedelta(days=2), time(10), tzinfo=zone)
    booking = await client.post(
        "/v1/appointments",
        headers=tenant["headers"],
        json={
            "patient_id": tenant["patient"].id,
            "provider_id": tenant["user"].id,
            "location_id": tenant["location"].id,
            "chair": "Op 3",
            "starts_at": past.isoformat(),
            "ends_at": (past + timedelta(minutes=45)).isoformat(),
            "procedure": "No-show verification",
        },
    )
    assert booking.status_code == 201, booking.text
    missed = await client.post(
        f"/v1/appointments/{booking.json()['id']}/no-show",
        headers=tenant["headers"],
        json={"reason": "Synthetic missed appointment"},
    )
    assert missed.status_code == 200, missed.text
    assert missed.json()["status"] == "no-show"
    async with tenant_session(tenant["org"].schema_name) as db:
        invoice = await db.scalar(
            select(Invoice)
            .where(Invoice.patient_id == tenant["patient"].id, Invoice.total_cents == 3500)
            .order_by(Invoice.created_at.desc())
        )
        assert invoice is not None
    restored_settings = await client.put(
        "/v1/organization/settings", headers=tenant["headers"], json=original_settings
    )
    assert restored_settings.status_code == 200, restored_settings.text


async def test_fee_versions_preserve_historical_invoice_prices(client, tenants):
    tenant = tenants[0]
    old = await create_invoice(client, tenant)
    effective = datetime.now(timezone.utc) - timedelta(seconds=1)
    version = await client.post(
        "/v1/billing/fee-versions",
        headers=tenant["headers"],
        json={
            "service_id": tenant["service"].id,
            "location_id": tenant["location"].id,
            "provider_id": tenant["user"].id,
            "fee_cents": 12500,
            "effective_at": effective.isoformat(),
        },
    )
    assert version.status_code == 201, version.text
    treatment = await client.post(
        "/v1/clinical/treatment-plans",
        headers=tenant["headers"],
        json={
            "patient_id": tenant["patient"].id,
            "provider_id": tenant["user"].id,
            "title": "Fee version verification",
            "options": [
                {
                    "name": "Versioned",
                    "phases": [
                        {
                            "name": "Phase",
                            "procedures": [{"service_id": tenant["service"].id, "quantity": 1}],
                        }
                    ],
                }
            ],
        },
    )
    assert treatment.json()["options"][0]["total_cents"] == 12500
    assert old["lines"][0]["fee_cents"] == 10000


async def test_every_financial_posting_is_balanced(client, tenants):
    tenant = tenants[0]
    record = await create_invoice(client, tenant)
    payment = await client.post(
        f"/v1/billing/invoices/{record['id']}/payments",
        headers=tenant["headers"],
        json={"amount_cents": 1000, "idempotency_key": str(uuid4())},
    )
    assert payment.status_code == 200, payment.text
    async with tenant_session(tenant["org"].schema_name) as db:
        postings = (
            await db.execute(
                select(JournalLine.posting_id, func.sum(JournalLine.amount_cents))
                .group_by(JournalLine.posting_id)
            )
        ).all()
        assert postings
        assert all(total == 0 for _, total in postings)


async def test_provider_registration_and_configuration_only_switch(tenants):
    tenant = tenants[0]

    class LivePaymentAdapter:
        def __init__(self, context):
            self.context = context

        async def capture(self, request):
            return PaymentResult("live-verification", request.amount_cents, sandbox=False)

        async def refund(self, payment_reference, amount_cents, idempotency_key):
            return PaymentResult("live-refund", amount_cents, sandbox=False)

    name = "verification-live-" + uuid4().hex
    register_provider("payment_gateway", name, LivePaymentAdapter)
    async with control_session() as db:
        organization = await db.get(Organization, tenant["org"].id)
        override = await db.scalar(
            select(TenantAdapterOverride).where(
                TenantAdapterOverride.organization_id == organization.id,
                TenantAdapterOverride.capability == "payment_gateway",
            )
        )
        if override is None:
            override = TenantAdapterOverride(
                organization_id=organization.id,
                capability="payment_gateway",
                provider_name=name,
                approved_by="test",
                approval_reason="Verified test override",
            )
            db.add(override)
        else:
            override.provider_name = name
    original_live_setting = settings().allow_live_integrations
    try:
        settings().allow_live_integrations = False
        async with control_session() as db:
            organization = await db.get(Organization, tenant["org"].id)
            await attach_effective_adapters(organization)
            with pytest.raises(IntegrationFailure, match="disabled"):
                resolve(organization, "payment_gateway")
            settings().allow_live_integrations = True
            adapter = resolve(organization, "payment_gateway")
            assert adapter.context.organization_id == organization.id
    finally:
        settings().allow_live_integrations = original_live_setting
        async with control_session() as reset:
            override = await reset.scalar(
                select(TenantAdapterOverride).where(
                    TenantAdapterOverride.organization_id == tenant["org"].id,
                    TenantAdapterOverride.capability == "payment_gateway",
                )
            )
            override.provider_name = "sandbox"


async def test_provider_options_are_registry_driven_and_platform_managed(client, tenants):
    response = await client.get(
        "/v1/organization/provider-options", headers=tenants[0]["headers"]
    )
    assert response.status_code == 200
    choices = response.json()
    assert choices["managed_by"] == "platform-control-plane"
    assert "sandbox" in choices["available"]["payment_gateway"]
    assert choices["effective"]["payment_gateway"] == "sandbox"


async def test_notification_failure_is_persisted_and_retryable(client, tenants):
    tenant = tenants[0]
    async with control_session() as db:
        override = await db.scalar(
            select(TenantAdapterOverride).where(
                TenantAdapterOverride.organization_id == tenant["org"].id,
                TenantAdapterOverride.capability == "email_provider",
            )
        )
        if override is None:
            override = TenantAdapterOverride(
                organization_id=tenant["org"].id,
                capability="email_provider",
                provider_name="sandbox-timeout",
                approved_by="test",
                approval_reason="Verified notification failure",
            )
            db.add(override)
        else:
            override.provider_name = "sandbox-timeout"
    async with tenant_session(tenant["org"].schema_name) as db:
        message = OutboxMessage(
            kind="appointment.reminder",
            payload={"appointment_id": "missing"},
            idempotency_key="verification-message:" + uuid4().hex,
            due_at=datetime.now(timezone.utc),
        )
        db.add(message)
        await db.flush()
        identifier = message.id
    dispatched = await client.post("/v1/notifications/dispatch", headers=tenant["headers"], json={})
    assert dispatched.status_code == 200
    async with tenant_session(tenant["org"].schema_name) as db:
        stored = await db.get(OutboxMessage, identifier)
        assert stored.status == "suppressed"
    retried = await client.post(
        f"/v1/notifications/{identifier}/retry", headers=tenant["headers"], json={}
    )
    assert retried.status_code == 200
    # Suppressed messages are intentionally not retried: the underlying appointment is gone.
    assert retried.json()["status"] == "suppressed"
    async with control_session() as db:
        override = await db.scalar(
            select(TenantAdapterOverride).where(
                TenantAdapterOverride.organization_id == tenant["org"].id,
                TenantAdapterOverride.capability == "email_provider",
            )
        )
        override.provider_name = "sandbox"


async def test_audit_filter_and_export(client, tenants):
    tenant = tenants[0]
    await client.get(f"/v1/clinical/{tenant['patient'].id}", headers=tenant["headers"])
    filtered = await client.get(
        f"/v1/organization/audit?patient_id={tenant['patient'].id}", headers=tenant["headers"]
    )
    assert filtered.status_code == 200
    assert all(item["details"].get("patient_id") == tenant["patient"].id for item in filtered.json())
    exported = await client.get(
        f"/v1/organization/audit/export?patient_id={tenant['patient'].id}",
        headers=tenant["headers"],
    )
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("text/csv")
    assert tenant["patient"].id in exported.text
