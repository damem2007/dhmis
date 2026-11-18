"""Regression contracts for plan-authoring and domain-routing boundaries."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.integrations.contracts import DomainDnsProvider
from app.integrations.registry import CONTRACTS, REGISTRY
from app.organizations.admin import (
    Onboarding,
    PlanCombinationInput,
    PlatformPlanInput,
    _create_domain_request,
    _custom_backoffice_hostname,
    _preflight_plan_configuration,
    _validate_onboarding_plan_options,
)
from app.organizations.models import OrganizationDomainHost


def onboarding(**overrides):
    payload = {
        "name": "Manual Test Clinic",
        "slug": "manual-test-clinic",
        "location_name": "Manual Test Location",
        "admin_name": "Manual Test Admin",
        "admin_email": "manual-test@example.test",
        "plan_code": "manual-test-plan",
    }
    payload.update(overrides)
    return Onboarding(**payload)


def test_custom_domain_requires_a_hostname():
    with pytest.raises(ValueError, match="custom hostname"):
        onboarding(domain_mode="custom")


def test_custom_domain_is_not_allowed_for_backoffice_only_plan():
    body = onboarding(domain_mode="custom", custom_domain_hostname="www.example.test")
    with pytest.raises(HTTPException, match="custom domain"):
        _validate_onboarding_plan_options(body, SimpleNamespace(id="plan"), set())


def test_custom_backoffice_derives_from_www_public_hostname():
    assert _custom_backoffice_hostname("www.example.test") == "admin.example.test"
    assert _custom_backoffice_hostname("clinic.example.test") == "admin.clinic.example.test"


class FakeControlSession:
    """Minimal unit-of-work used to assert domain records before DB persistence."""

    def __init__(self):
        self.records = []

    def add(self, record):
        self.records.append(record)

    async def flush(self):
        return None


@pytest.mark.asyncio
async def test_custom_domain_persists_managed_backoffice_fallback_host():
    db = FakeControlSession()
    organization = SimpleNamespace(id="organization-1", slug="manual-test-clinic")

    request = await _create_domain_request(
        db,
        organization=organization,
        mode="custom",
        patient_facing=True,
        custom_hostname="www.customer.example",
        actor_id="platform-operator",
    )

    hosts = [record for record in db.records if isinstance(record, OrganizationDomainHost)]
    by_role = {host.role: host for host in hosts}
    assert request.status == "pending_verification"
    assert by_role["public"].hostname == "www.customer.example"
    assert by_role["back_office"].hostname == "admin.customer.example"
    assert by_role["managed_back_office"].hostname == "admin.manual-test-clinic.dhmis.test"
    assert by_role["managed_back_office"].routing_status == "active"
    assert by_role["managed_back_office"].canonical is False


def test_dns_automation_is_an_explicit_provider_contract_without_a_builtin_vendor():
    class FakeDomainDnsProvider:
        async def can_manage_zone(self, hostname: str) -> bool:
            return hostname == "www.customer.example"

        async def upsert_txt_record(self, *, hostname: str, value: str, idempotency_key: str) -> dict:
            return {"status": "created"}

    assert "domain_dns_provider" in CONTRACTS
    assert isinstance(FakeDomainDnsProvider(), DomainDnsProvider)
    assert REGISTRY["domain_dns_provider"] == {}


def test_widget_plan_preflight_requires_booking_capability():
    body = PlatformPlanInput(
        code="widget-only",
        name="Widget only",
        entitlements=[{"key": "module.appointment_widget", "enabled": True}],
    )
    with pytest.raises(HTTPException, match="requires Online Appointment Booking"):
        _preflight_plan_configuration(body)


def test_selectable_plan_is_private_and_uses_reviewed_features():
    body = PlatformPlanInput(
        code="curated",
        name="Curated",
        configuration_mode="selectable",
        public_available=False,
        entitlements=[
            {"key": "experience.tenant_website", "enabled": True},
            {"key": "capability.appointment_booking", "enabled": True},
        ],
        combinations=[
            PlanCombinationInput(
                code="website-booking",
                name="Website and booking",
                feature_keys=["experience.tenant_website", "capability.appointment_booking"],
                price_cents=25000,
            )
        ],
    )
    result = _preflight_plan_configuration(body)
    assert result["configuration_mode"] == "selectable"


def test_selectable_plan_can_never_be_public():
    body = PlatformPlanInput(
        code="bad-curated",
        name="Bad curated",
        configuration_mode="selectable",
        public_available=True,
        entitlements=[],
        combinations=[PlanCombinationInput(code="bo", name="Back Office", feature_keys=[], price_cents=0)],
    )
    with pytest.raises(HTTPException, match="cannot be public"):
        _preflight_plan_configuration(body)
