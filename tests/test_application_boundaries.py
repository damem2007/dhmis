import re
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.core.database import control_session, tenant_session
from app.core.repository import add
from app.integrations.models import TenantAdapterOverride
from app.notifications.models import OutboxMessage
from app.organizations.configuration import tenant_settings
from app.organizations.models import Location, Organization
from app.organizations.tenant_resolution import normalize_slug


def future_booking(tenant, patient_id):
    start = (datetime.now(timezone.utc) + timedelta(days=60)).replace(
        hour=17, minute=0, second=0, microsecond=0
    )
    return {
        "patient_id": patient_id,
        "provider_id": tenant["user"].id,
        "location_id": tenant["location"].id,
        "chair": "Op 1",
        "starts_at": start.isoformat(),
        "ends_at": (start + timedelta(minutes=30)).isoformat(),
        "procedure": "Architecture verification",
    }


def test_reserved_platform_routes_are_not_tenant_slugs():
    with pytest.raises(ValueError):
        normalize_slug("admin")
    assert normalize_slug("Maple Clinic") == "maple-clinic"


async def test_tenant_settings_are_runtime_source_without_control_plane_mutation(client, tenants):
    tenant = tenants[0]
    async with control_session() as db:
        organization = await db.get(Organization, tenant["org"].id)
        legacy = {
            "visibility": organization.visibility,
            "branding": dict(organization.branding),
            "policy": dict(organization.policy),
            "jurisdiction_policy": dict(organization.jurisdiction_policy),
        }
    response = await client.put(
        "/v1/organization/settings",
        headers=tenant["headers"],
        json={
            "visibility": "location",
            "branding": {"--sage": "#126b49"},
            "policy": {
                "cancellation_notice_hours": 36,
                "cancellation_fee_cents": 2500,
                "buffer_minutes": 10,
                "reminder_hours": 48,
            },
            "jurisdiction_policy": {"retention_days": 3650},
        },
    )
    assert response.status_code == 200, response.text
    async with tenant_session(tenant["org"].schema_name) as db:
        runtime = await tenant_settings(db)
        assert runtime.visibility == "location"
        assert runtime.policy["cancellation_fee_cents"] == 2500
        assert runtime.migration_state["legacy_control_backfilled"] is True
    async with control_session() as db:
        organization = await db.get(Organization, tenant["org"].id)
        assert organization.visibility == legacy["visibility"]
        assert organization.branding == legacy["branding"]
        assert organization.policy == legacy["policy"]
        assert organization.jurisdiction_policy == legacy["jurisdiction_policy"]
    async with tenant_session(tenant["org"].schema_name) as db:
        runtime = await tenant_settings(db)
        runtime.visibility = legacy["visibility"]
        runtime.branding = legacy["branding"]
        runtime.policy = legacy["policy"]
        runtime.jurisdiction_policy = legacy["jurisdiction_policy"]


async def test_adapter_override_requires_platform_approval(client, tenants):
    tenant = tenants[0]
    requested = await client.post(
        "/v1/organization/integration-requests",
        headers=tenant["headers"],
        json={
            "capability": "email_provider",
            "provider_name": "sandbox-timeout",
            "reason": "Verify controlled provider customization approval",
        },
    )
    assert requested.status_code == 201, requested.text
    before = await client.get("/v1/organization/provider-options", headers=tenant["headers"])
    assert before.json()["effective"]["email_provider"] == "sandbox"
    approved = await client.put(
        f"/v1/platform/integration-requests/{requested.json()['id']}",
        headers={"X-Bootstrap-Key": settings().bootstrap_key.get_secret_value()},
        json={
            "status": "approved",
            "reason": "Approved in automated architecture-boundary verification",
        },
    )
    assert approved.status_code == 200, approved.text
    after = await client.get("/v1/organization/provider-options", headers=tenant["headers"])
    assert after.json()["effective"]["email_provider"] == "sandbox-timeout"
    async with control_session() as db:
        override = await db.scalar(
            select(TenantAdapterOverride).where(
                TenantAdapterOverride.organization_id == tenant["org"].id,
                TenantAdapterOverride.capability == "email_provider",
            )
        )
        override.provider_name = "sandbox"


async def test_role_dashboard_reconciles_and_enforces_scope_and_export(client, tenants):
    tenant = tenants[0]
    dashboard = await client.get(
        "/v1/analytics/dashboard", params={"period": "ytd"}, headers=tenant["headers"]
    )
    assert dashboard.status_code == 200, dashboard.text
    payload = dashboard.json()
    assert payload["role_profile"] == "organization-executive"
    assert payload["freshness"]["catalogue_version"] == "1.0"
    production = next(item for item in payload["metrics"] if item["key"] == "production")
    async with tenant_session(tenant["org"].schema_name) as db:
        from app.billing.models import Invoice

        invoices = (await db.scalars(select(Invoice))).all()
        expected = sum(row.total_cents + row.adjustment_cents for row in invoices)
        other_location = await add(db, Location, {"name": "Out of scope"}, "test")
    assert production["value"] == expected
    denied_scope = await client.get(
        "/v1/analytics/dashboard",
        params={"period": "today", "location_id": other_location.id},
        headers=tenant["front_headers"],
    )
    assert denied_scope.status_code == 403
    denied_export = await client.get(
        "/v1/analytics/worklists/visits/export",
        headers=tenant["front_headers"],
    )
    assert denied_export.status_code == 403
    denied_metric = await client.get(
        "/v1/analytics/worklists/production", headers=tenant["front_headers"]
    )
    assert denied_metric.status_code == 403
    allowed_export = await client.get(
        "/v1/analytics/worklists/visits/export", headers=tenant["headers"]
    )
    assert allowed_export.status_code == 200


async def test_slug_domain_resolution_and_authenticated_tenant_agreement(client, tenants):
    first, second = tenants
    resolved = await client.get("/v1/tenants/resolve", params={"slug": first["org"].slug})
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["organization_id"] == first["org"].id

    matching = await client.get(
        "/v1/auth/me",
        headers={**first["headers"], "X-DHMIS-Tenant": first["org"].slug},
    )
    assert matching.status_code == 200
    mismatch = await client.get(
        "/v1/auth/me",
        headers={**first["headers"], "X-DHMIS-Tenant": second["org"].slug},
    )
    assert mismatch.status_code == 403
    assert (
        await client.get("/v1/platform/organizations", headers=first["headers"])
    ).status_code == 401

    hostname = f"clinic-{first['org'].id[:8]}.example.test"
    async with control_session() as db:
        organization = await db.get(Organization, first["org"].id)
        previous = list(organization.domains)
        organization.domains = [{"hostname": hostname, "surface": "public"}]
    try:
        domain = await client.get("/v1/tenants/resolve", params={"hostname": hostname})
        assert domain.status_code == 200, domain.text
        assert domain.json()["organization_id"] == first["org"].id
        assert domain.json()["source"] == "custom-domain"
        assert domain.json()["surface"] == "public"
    finally:
        async with control_session() as db:
            organization = await db.get(Organization, first["org"].id)
            organization.domains = previous


async def test_front_office_is_optional_and_booking_is_independent(client, tenants):
    tenant = tenants[0]
    async with control_session() as db:
        organization = await db.get(Organization, tenant["org"].id)
        prior = (
            organization.front_office_enabled,
            organization.booking_enabled,
            organization.patient_portal_enabled,
        )
        organization.front_office_enabled = False
        organization.booking_enabled = True
        organization.patient_portal_enabled = True
    try:
        storefront = await client.get(f"/v1/public/tenants/{tenant['org'].slug}")
        assert storefront.status_code == 404
        booking = await client.get(f"/v1/booking/tenants/{tenant['org'].slug}")
        assert booking.status_code == 200, booking.text
        portal = await client.get(
            "/v1/tenants/resolve",
            params={"slug": tenant["org"].slug, "surface": "portal"},
        )
        assert portal.status_code == 200
        back_office = await client.get(
            "/v1/auth/me",
            headers={**tenant["headers"], "X-DHMIS-Tenant": tenant["org"].slug},
        )
        assert back_office.status_code == 200
    finally:
        async with control_session() as db:
            organization = await db.get(Organization, tenant["org"].id)
            (
                organization.front_office_enabled,
                organization.booking_enabled,
                organization.patient_portal_enabled,
            ) = prior


async def test_access_lifecycle_templates_and_widget_manifest(client, tenants):
    tenant = tenants[0]
    access = await client.get("/v1/organization/access", headers=tenant["headers"])
    assert access.status_code == 200, access.text
    assert "password_hash" not in access.text
    assert "mfa_secret" not in access.text

    invitation = await client.post(
        "/v1/organization/invites",
        headers=tenant["headers"],
        json={
            "name": "Access Verification",
            "email": f"access-{tenant['org'].id[:8]}@example.test",
            "role": "front-desk",
            "location_ids": [tenant["location"].id],
        },
    )
    assert invitation.status_code == 201, invitation.text
    renewed = await client.post(
        f"/v1/organization/invites/{invitation.json()['invite_id']}/resend",
        headers=tenant["headers"],
    )
    assert renewed.status_code == 200, renewed.text
    revoked = await client.post(
        f"/v1/organization/invites/{renewed.json()['invite_id']}/revoke",
        headers=tenant["headers"],
    )
    assert revoked.status_code == 200, revoked.text

    templates = await client.get(
        "/v1/organization/communication-templates", headers=tenant["headers"]
    )
    assert templates.status_code == 200
    assert "appointment-reminder" in templates.json()
    test_message = await client.post(
        "/v1/organization/communication-templates/appointment-reminder/test",
        headers=tenant["headers"],
    )
    assert test_message.status_code == 202, test_message.text

    settings_response = await client.get(
        "/v1/organization/settings", headers=tenant["headers"]
    )
    settings_payload = settings_response.json()
    settings_payload["public_content"] = {
        "contact_phone": "+1 604 555 0199",
        "contact_email": "clinic@example.test",
        "address": "100 Dental Way",
    }
    settings_payload["booking_widget"] = {
        "accent_color": "#126b49",
        "default_location_id": tenant["location"].id,
        "allowed_location_ids": [tenant["location"].id],
        "allowed_service_ids": [tenant["service"].id],
        "allowed_provider_ids": [tenant["user"].id],
        "allowed_origins": ["https://clinic.example.test"],
    }
    configured = await client.put(
        "/v1/organization/settings", headers=tenant["headers"], json=settings_payload
    )
    assert configured.status_code == 200, configured.text
    widget = await client.get(f"/v1/tenants/{tenant['org'].slug}/widget-config")
    assert widget.status_code == 200, widget.text
    assert widget.json()["tenant"]["slug"] == tenant["org"].slug
    assert [row["id"] for row in widget.json()["services"]] == [tenant["service"].id]


async def test_appointment_verification_is_generic_and_creates_patient_session(client, tenants):
    tenant, other = tenants
    email = f"activation-{tenant['org'].id[:8]}@example.test"
    patient = await client.post(
        "/v1/patients",
        headers=tenant["headers"],
        json={
            "first_name": "Activation",
            "last_name": "Verification",
            "birth_date": "1990-01-01",
            "email": email,
            "location_id": tenant["location"].id,
        },
    )
    assert patient.status_code == 201, patient.text
    appointment = await client.post(
        "/v1/appointments",
        headers=tenant["headers"],
        json=future_booking(tenant, patient.json()["id"]),
    )
    assert appointment.status_code == 201, appointment.text

    wrong = await client.post(
        "/v1/portal/auth/verification/request",
        json={
            "tenant_slug": tenant["org"].slug,
            "appointment_reference": appointment.json()["id"],
            "email": "unknown@example.test",
        },
    )
    correct = await client.post(
        "/v1/portal/auth/verification/request",
        json={
            "tenant_slug": tenant["org"].slug,
            "appointment_reference": appointment.json()["id"],
            "email": email,
        },
    )
    assert wrong.status_code == correct.status_code == 202
    assert set(wrong.json()) == set(correct.json()) == {"status", "challenge_token"}

    async with tenant_session(tenant["org"].schema_name) as db:
        message = await db.scalar(
            select(OutboxMessage)
            .where(OutboxMessage.kind == "patient.verification")
            .order_by(OutboxMessage.created_at.desc())
        )
        code = re.search(r"\b\d{6}\b", message.payload["body"]).group()
    verified = await client.post(
        "/v1/portal/auth/verification/verify",
        json={
            "tenant_slug": tenant["org"].slug,
            "challenge_token": correct.json()["challenge_token"],
            "code": code,
        },
    )
    assert verified.status_code == 200, verified.text
    patient_headers = {
        "Authorization": "Bearer " + verified.json()["access_token"],
        "X-DHMIS-Tenant": tenant["org"].slug,
    }
    assert (await client.get("/v1/portal/me", headers=patient_headers)).status_code == 200
    assert (await client.get("/v1/patients", headers=patient_headers)).status_code == 401
    mismatch_headers = {
        **patient_headers,
        "X-DHMIS-Tenant": other["org"].slug,
    }
    assert (await client.get("/v1/portal/me", headers=mismatch_headers)).status_code == 403
