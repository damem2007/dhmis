from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import text

from app.core.database import tenant_session
from app.identity.models import StaffUser
from app.identity.service import issue_token


def booking(tenant, start):
    return {
        "patient_id": tenant["patient"].id,
        "provider_id": tenant["user"].id,
        "location_id": tenant["location"].id,
        "chair": "Op 1",
        "starts_at": start.isoformat(),
        "ends_at": (start + timedelta(minutes=45)).isoformat(),
        "procedure": "Phase 3 surgery verification",
    }


async def test_phase3_care_surgery_reporting_and_operations(client, tenants):
    tenant = tenants[0]
    async with tenant_session(tenant["org"].schema_name) as db:
        user = await db.get(StaffUser, tenant["user"].id)
        headers = {"Authorization": "Bearer " + await issue_token(db, user, tenant["org"])}
    today = date.today()
    valid_credential = await client.post(
        "/v1/operations/credentials",
        headers=headers,
        json={
            "provider_id": tenant["user"].id,
            "location_id": tenant["location"].id,
            "credential_type": "Phase 3 clinical licence",
            "credential_number": "VERIFY-VALID",
            "jurisdiction": "BC",
            "issued_on": (today - timedelta(days=30)).isoformat(),
            "expires_on": (today + timedelta(days=365)).isoformat(),
            "alert_lead_days": 60,
            "required": True,
        },
    )
    assert valid_credential.status_code == 201, valid_credential.text
    assert valid_credential.json()["state"] == "valid"

    patient = await client.put(
        f"/v1/patients/{tenant['patient'].id}",
        headers=headers,
        json={
            "first_name": tenant["patient"].first_name,
            "last_name": tenant["patient"].last_name,
            "birth_date": tenant["patient"].birth_date.isoformat(),
            "phone": tenant["patient"].phone,
            "location_id": tenant["location"].id,
            "allergies": ["Penicillin"],
            "medical_history": "Synthetic hypertension history",
        },
    )
    assert patient.status_code == 200, patient.text
    rule = await client.post(
        "/v1/prescriptions/safety-rules",
        headers=headers,
        json={
            "medication": "Amoxicillin",
            "conflicts": ["Penicillin"],
            "severity": "block",
            "message": "Synthetic penicillin-family interaction",
        },
    )
    assert rule.status_code == 201, rule.text
    prescription = {
        "patient_id": tenant["patient"].id,
        "prescriber_id": tenant["user"].id,
        "medication": "Amoxicillin",
        "dosage": "500 mg",
        "route": "oral",
        "frequency": "three times daily",
        "duration_days": 7,
        "instructions": "Synthetic verification only",
    }
    flagged = await client.post("/v1/prescriptions", headers=headers, json=prescription)
    assert flagged.status_code == 409
    issued = await client.post(
        "/v1/prescriptions",
        headers=headers,
        json={**prescription, "override_reason": "Verified synthetic override for test workflow"},
    )
    assert issued.status_code == 201, issued.text
    assert len(issued.json()["safety_flags"]) >= 1
    assert any(
        flag["type"] == "interaction" and "Penicillin" in flag.get("matched", [])
        for flag in issued.json()["safety_flags"]
    )
    assert (
        await client.get(f"/v1/prescriptions/{issued.json()['id']}/print", headers=headers)
    ).status_code == 200

    due = datetime.now(timezone.utc) - timedelta(days=1)
    lab = await client.post(
        "/v1/care-coordination/labs",
        headers=headers,
        json={
            "patient_id": tenant["patient"].id,
            "provider_id": tenant["user"].id,
            "case_type": "Histopathology",
            "laboratory": "Synthetic Dental Lab",
            "due_at": due.isoformat(),
            "notes": "Verification sample",
        },
    )
    referral = await client.post(
        "/v1/care-coordination/referrals",
        headers=headers,
        json={
            "patient_id": tenant["patient"].id,
            "provider_id": tenant["user"].id,
            "direction": "outbound",
            "specialty": "Oral surgery",
            "organization_name": "Synthetic Specialist",
            "due_at": due.isoformat(),
            "reason": "Verification referral",
        },
    )
    assert lab.status_code == referral.status_code == 201
    timeline = await client.get(
        f"/v1/care-coordination/timeline/{tenant['patient'].id}", headers=headers
    )
    assert timeline.status_code == 200
    assert timeline.json()["lab_cases"][0]["overdue"] is True
    for status in ("in_progress", "received", "completed"):
        moved = await client.post(
            f"/v1/care-coordination/labs/{lab.json()['id']}/transition",
            headers=headers,
            json={"status": status, "note": "Verification transition"},
        )
        assert moved.status_code == 200, moved.text

    starts_at = (datetime.now(timezone.utc) + timedelta(days=7)).replace(
        hour=17, minute=0, second=0, microsecond=0
    )
    appointment = await client.post(
        "/v1/appointments", headers=headers, json=booking(tenant, starts_at)
    )
    assert appointment.status_code == 201, appointment.text
    encounter = await client.post(
        f"/v1/appointments/{appointment.json()['id']}/check-in", headers=headers
    )
    assert encounter.status_code == 200, encounter.text
    saved = await client.put(
        f"/v1/clinical/encounters/{encounter.json()['id']}",
        headers=headers,
        json={
            "soap": {key: "Synthetic surgery note" for key in ("subjective", "objective", "assessment", "plan")},
            "procedures": [{"service_id": tenant["service"].id, "quantity": 1}],
        },
    )
    assert saved.status_code == 200, saved.text
    admission = await client.post(
        "/v1/day-surgery/admissions",
        headers=headers,
        json={"encounter_id": encounter.json()["id"], "procedure_name": "Synthetic extraction"},
    )
    assert admission.status_code == 201, admission.text
    incomplete = await client.put(
        f"/v1/day-surgery/admissions/{admission.json()['id']}/preop",
        headers=headers,
        json={"checklist": {"identity_confirmed": True}},
    )
    assert incomplete.status_code == 422
    checklist = {
        item: True
        for item in (
            "identity_confirmed", "consent_verified", "medical_history_reviewed",
            "allergies_reviewed", "fasting_confirmed", "escort_confirmed",
        )
    }
    base = f"/v1/day-surgery/admissions/{admission.json()['id']}"
    assert (await client.put(base + "/preop", headers=headers, json={"checklist": checklist})).status_code == 200
    assert (await client.post(base + "/start", headers=headers)).status_code == 200
    assert (
        await client.post(
            base + "/anesthesia",
            headers=headers,
            json={"agent": "Synthetic agent", "dose": "1 unit", "route": "local", "vitals": {"pulse": 70}},
        )
    ).status_code == 200
    assert (
        await client.put(
            base + "/recovery", headers=headers, json={"recovery_notes": "Stable synthetic recovery record"}
        )
    ).status_code == 200
    discharged = await client.post(
        base + "/discharge",
        headers=headers,
        json={"discharge_summary": "Discharged with synthetic written instructions"},
    )
    assert discharged.status_code == 200, discharged.text
    chart = await client.get(f"/v1/clinical/{tenant['patient'].id}", headers=headers)
    closed = next(row for row in chart.json()["encounters"] if row["id"] == encounter.json()["id"])
    assert closed["status"] == "completed"
    assert closed["invoice_id"]

    payment = await client.post(
        f"/v1/billing/invoices/{closed['invoice_id']}/payments",
        headers=headers,
        json={"amount_cents": 1000, "idempotency_key": str(uuid4())},
    )
    assert payment.status_code == 200, payment.text
    report = await client.get(
        "/v1/reports/performance",
        headers=headers,
        params={
            "start": (today - timedelta(days=1)).isoformat(),
            "end": (today + timedelta(days=8)).isoformat(),
            "provider_id": tenant["user"].id,
            "location_id": tenant["location"].id,
        },
    )
    assert report.status_code == 200, report.text
    assert report.json()["production_cents"] >= 10000
    assert report.json()["collections_cents"] >= 1000
    assert report.json()["appointment_minutes"] >= 45
    assert report.json()["completed_encounters"] >= 1

    location = await client.put(
        f"/v1/operations/locations/{tenant['location'].id}",
        headers=headers,
        json={
            "name": tenant["location"].name,
            "timezone": tenant["location"].timezone,
            "chairs": tenant["location"].chairs,
            "opening_hour": tenant["location"].opening_hour,
            "closing_hour": tenant["location"].closing_hour,
            "branding": {"--sage": "#52796f"},
            "policy": {"buffer_minutes": 5, "reminder_hours": 12},
        },
    )
    assert location.status_code == 200, location.text
    assert location.json()["policy"]["buffer_minutes"] == 5

    expired = await client.post(
        "/v1/operations/credentials",
        headers=headers,
        json={
            "provider_id": tenant["user"].id,
            "credential_type": "Phase 3 expired permit",
            "credential_number": "VERIFY-EXPIRED",
            "jurisdiction": "BC",
            "issued_on": (today - timedelta(days=365)).isoformat(),
            "expires_on": (today - timedelta(days=1)).isoformat(),
            "required": True,
        },
    )
    assert expired.json()["state"] == "expired"
    blocked = await client.post(
        "/v1/appointments",
        headers=headers,
        json=booking(tenant, starts_at + timedelta(days=14)),
    )
    assert blocked.status_code == 409
    alerts = await client.get("/v1/operations/credential-alerts", headers=headers)
    assert any(item["id"] == expired.json()["id"] for item in alerts.json())


async def test_phase3_migration_is_current(tenants):
    for tenant in tenants:
        async with tenant_session(tenant["org"].schema_name) as db:
            assert await db.scalar(text("SELECT version_num FROM alembic_version")) == "0019"
            assert await db.scalar(text("SELECT to_regclass('prescriptions')")) == "prescriptions"
            assert await db.scalar(text("SELECT to_regclass('day_surgery_admissions')")) == "day_surgery_admissions"
