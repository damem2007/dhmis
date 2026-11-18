"""Contract tests for plan-governed Platform Admin onboarding options."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.organizations.admin import _validate_onboarding_plan_options


def onboarding_options(
    *,
    tenant_website: bool = False,
    appointment_booking: bool = False,
    portal: bool = False,
    widget_origin: str | None = None,
):
    return SimpleNamespace(
        front_office_enabled=tenant_website,
        booking_enabled=appointment_booking,
        patient_portal_enabled=portal,
        booking_widget_origin=widget_origin,
    )


def test_widget_request_requires_selected_plan():
    with pytest.raises(HTTPException) as error:
        _validate_onboarding_plan_options(
            onboarding_options(widget_origin="https://clinic.example"),
            None,
            set(),
        )

    assert error.value.status_code == 422
    assert error.value.detail["code"] == "PLAN_REQUIRED"


def test_widget_request_requires_widget_entitlement():
    plan = SimpleNamespace(id="plan-1")
    with pytest.raises(HTTPException) as error:
        _validate_onboarding_plan_options(
            onboarding_options(widget_origin="https://clinic.example"),
            plan,
            {"module.patient_portal"},
        )

    assert error.value.detail["feature"] == "module.appointment_widget"


def test_patient_portal_requires_portal_entitlement():
    with pytest.raises(HTTPException) as error:
        _validate_onboarding_plan_options(
            onboarding_options(portal=True),
            SimpleNamespace(id="plan-1"),
            {"module.appointment_widget"},
        )

    assert error.value.detail["feature"] == "module.patient_portal"


def test_tenant_website_requires_website_entitlement():
    with pytest.raises(HTTPException) as error:
        _validate_onboarding_plan_options(
            onboarding_options(tenant_website=True),
            SimpleNamespace(id="plan-1"),
            set(),
        )

    assert error.value.detail["feature"] == "experience.tenant_website"


def test_online_booking_requires_booking_entitlement():
    with pytest.raises(HTTPException) as error:
        _validate_onboarding_plan_options(
            onboarding_options(appointment_booking=True),
            SimpleNamespace(id="plan-1"),
            set(),
        )

    assert error.value.detail["feature"] == "capability.appointment_booking"


def test_widget_request_requires_online_booking_to_be_enabled():
    with pytest.raises(HTTPException) as error:
        _validate_onboarding_plan_options(
            onboarding_options(widget_origin="https://clinic.example"),
            SimpleNamespace(id="plan-1"),
            {"module.appointment_widget", "capability.appointment_booking"},
        )

    assert error.value.detail["code"] == "APPOINTMENT_BOOKING_REQUIRED"


def test_entitled_plan_accepts_portal_and_widget_request():
    _validate_onboarding_plan_options(
        onboarding_options(portal=True, appointment_booking=True, widget_origin="https://clinic.example"),
        SimpleNamespace(id="plan-1"),
        {"module.patient_portal", "module.appointment_widget", "capability.appointment_booking"},
    )

