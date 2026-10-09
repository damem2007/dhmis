from uuid import uuid4


async def portal_account(client, tenant):
    patient = await client.post(
        "/v1/patients",
        headers=tenant["headers"],
        json={
            "first_name": "Portal",
            "last_name": "Pagination",
            "birth_date": "1991-06-12",
            "email": f"portal-{uuid4().hex[:8]}@example.test",
            "phone": "604-555-0168",
            "location_id": tenant["location"].id,
        },
    )
    assert patient.status_code == 201, patient.text
    email = patient.json()["email"]
    invitation = await client.post(
        "/v1/portal/invites",
        headers=tenant["headers"],
        json={"patient_id": patient.json()["id"], "email": email},
    )
    assert invitation.status_code == 201, invitation.text
    accepted = await client.post(
        "/v1/portal/auth/accept",
        json={
            "organization_id": tenant["org"].id,
            "token": invitation.json()["token"],
            "password": "Portal-password-2026!",
        },
    )
    assert accepted.status_code == 200, accepted.text

    async def login(password="Portal-password-2026!"):
        response = await client.post(
            "/v1/portal/auth/login",
            json={
                "organization_id": tenant["org"].id,
                "email": email,
                "password": password,
            },
        )
        assert response.status_code == 200, response.text
        return {"Authorization": "Bearer " + response.json()["access_token"]}

    return patient.json(), email, login


async def test_portal_activity_account_security_and_templates(client, tenants):
    tenant = tenants[0]
    summary = await client.get(
        "/v1/analytics/organization-summary?period=month", headers=tenant["headers"]
    )
    assert summary.status_code == 200, summary.text
    assert tenant["location"].id in {row["id"] for row in summary.json()["locations"]}
    assert tenant["user"].id in {row["id"] for row in summary.json()["providers"]}
    assert (
        await client.get(
            "/v1/analytics/organization-summary?period=month", headers=tenant["front_headers"]
        )
    ).status_code == 403

    patient, email, login = await portal_account(client, tenant)
    first_headers = await login()
    second_headers = await login()

    me = await client.get("/v1/portal/me", headers=second_headers)
    assert me.status_code == 200
    assert me.json()["email"] == email

    sessions = await client.get("/v1/portal/auth/sessions", headers=second_headers)
    assert sessions.status_code == 200
    assert len(sessions.json()) == 2
    assert sum(row["current"] for row in sessions.json()) == 1

    revoked = await client.post(
        "/v1/portal/auth/sessions/revoke-others", headers=second_headers
    )
    assert revoked.json() == {"revoked": 1}
    assert (await client.get("/v1/portal/me", headers=first_headers)).status_code == 401

    for index in range(6):
        created = await client.post(
            "/v1/portal/threads",
            headers=second_headers,
            json={
                "patient_id": patient["id"],
                "subject": f"Question {index}",
                "body": "A secure portal message for pagination.",
            },
        )
        assert created.status_code == 201, created.text
    first_page = await client.get(
        "/v1/portal/activity?page=1&page_size=5&kind=message", headers=second_headers
    )
    second_page = await client.get(
        "/v1/portal/activity?page=2&page_size=5&kind=message", headers=second_headers
    )
    assert first_page.status_code == second_page.status_code == 200
    assert first_page.json()["total"] == 6
    assert len(first_page.json()["items"]) == 5
    assert len(second_page.json()["items"]) == 1
    assert {row["id"] for row in first_page.json()["items"]}.isdisjoint(
        {row["id"] for row in second_page.json()["items"]}
    )

    wrong = await client.post(
        "/v1/portal/auth/password",
        headers=second_headers,
        json={"current_password": "incorrect", "new_password": "New-portal-password-2026!"},
    )
    assert wrong.status_code == 400
    changed = await client.post(
        "/v1/portal/auth/password",
        headers=second_headers,
        json={
            "current_password": "Portal-password-2026!",
            "new_password": "New-portal-password-2026!",
        },
    )
    assert changed.status_code == 200
    assert (await client.get("/v1/portal/me", headers=second_headers)).status_code == 401
    assert await login("New-portal-password-2026!")

    saved = await client.put(
        "/v1/organization/communication-templates/follow-up",
        headers=tenant["headers"],
        json={
            "name": "Visit follow-up",
            "channel": "email",
            "subject": "A note from {{clinic_name}}",
            "body": "Hi {{patient_first_name}}, contact {{clinic_phone}} with questions.",
            "active": True,
        },
    )
    assert saved.status_code == 200, saved.text
    invalid = await client.put(
        "/v1/organization/communication-templates/follow-up",
        headers=tenant["headers"],
        json={**saved.json(), "body": "Unsupported {{appointment_room}}"},
    )
    assert invalid.status_code == 422
    queued = await client.post(
        "/v1/organization/communication-templates/follow-up/test",
        headers=tenant["headers"],
    )
    assert queued.status_code == 202
    assert queued.json() == {"status": "queued"}
