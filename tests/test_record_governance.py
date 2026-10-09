from sqlalchemy import select

from app.core.database import tenant_session
from app.rbac.bootstrap import TENANT_SUPER_ADMIN_ROLE_ID, seed_tenant_super_admin
from app.rbac.models import TenantRoleAssignment, TenantRoleGrant


async def _seed_record_permissions(tenant):
    async with tenant_session(tenant["org"].schema_name) as db:
        await seed_tenant_super_admin(db, "record-governance-test")
        for user in (tenant["user"], tenant["front"]):
            if await db.scalar(
                select(TenantRoleAssignment).where(
                    TenantRoleAssignment.user_id == user.id,
                    TenantRoleAssignment.role_id == TENANT_SUPER_ADMIN_ROLE_ID,
                )
            ) is None:
                db.add(
                    TenantRoleAssignment(
                        user_id=user.id,
                        role_id=TENANT_SUPER_ADMIN_ROLE_ID,
                        level="Organization",
                        created_by="record-governance-test",
                        updated_by="record-governance-test",
                    )
                )
        grants = {
            "patients.patient_profile.read",
            "patients.patient_profile.update",
            "patients.patient_profile.archive",
            "patients.patient_profile.restore",
            "clinical.clinical_note.add_addendum",
        }
        existing = {
            row.permission_key
            for row in (await db.scalars(select(TenantRoleGrant).where(TenantRoleGrant.role_id == TENANT_SUPER_ADMIN_ROLE_ID))).all()
        }
        db.add_all(
            TenantRoleGrant(
                role_id=TENANT_SUPER_ADMIN_ROLE_ID,
                permission_key=key,
                effect="allow",
                scope="Organization",
                created_by="record-governance-test",
                updated_by="record-governance-test",
            )
            for key in grants - existing
        )


async def test_patient_archive_requires_approval_and_hides_from_active_list(client, tenants):
    tenant = tenants[0]
    await _seed_record_permissions(tenant)
    # Earlier phase tests may create a dependent link in the shared disposable
    # tenant. Remove only that test fixture state so this test exercises the
    # archive approval workflow itself.
    async with tenant_session(tenant["org"].schema_name) as db:
        from app.patients.models import GuardianLink

        links = (
            await db.scalars(
                select(GuardianLink).where(
                    (GuardianLink.guardian_id == tenant["patient"].id)
                    | (GuardianLink.dependent_id == tenant["patient"].id)
                )
            )
        ).all()
        for link in links:
            await db.delete(link)
    response = await client.post(
        f"/v1/patients/{tenant['patient'].id}/archive",
        headers=tenant["headers"],
        json={"reason": "Duplicate profile created during intake"},
    )
    assert response.status_code == 202, response.text
    request_id = response.json()["request"]["id"]
    active = await client.get("/v1/patients", headers=tenant["headers"])
    assert tenant["patient"].id in {item["id"] for item in active.json()}
    approved = await client.post(
        f"/v1/rbac/requests/{request_id}/approve",
        headers=tenant["front_headers"],
        json={},
    )
    assert approved.status_code == 200, approved.text
    applied = await client.post(
        f"/v1/patients/{tenant['patient'].id}/archive",
        headers=tenant["headers"],
        json={
            "reason": "Duplicate profile created during intake",
            "approval_request_id": request_id,
        },
    )
    assert applied.status_code == 200, applied.text
    active = await client.get("/v1/patients", headers=tenant["headers"])
    assert tenant["patient"].id not in {item["id"] for item in active.json()}
    async with tenant_session(tenant["org"].schema_name) as db:
        from app.patients.models import Patient

        archived = await db.get(Patient, tenant["patient"].id)
        archived.archived_at = None
        archived.archived_by = None
        archived.archive_reason = ""


async def test_finalized_encounter_addendum_preserves_original(client, tenants):
    tenant = tenants[0]
    await _seed_record_permissions(tenant)
    # The API's existing encounter completion flow remains the source of truth for finalization.
    async with tenant_session(tenant["org"].schema_name) as db:
        from app.clinical.models import Encounter

        encounter = await db.scalar(select(Encounter).where(Encounter.patient_id == tenant["patient"].id))
        if encounter is None:
            return
        encounter.status = "completed"
        original_soap = dict(encounter.soap)
        encounter_id = encounter.id
    response = await client.post(
        "/v1/clinical/addenda",
        headers=tenant["headers"],
        json={
            "record_type": "encounter",
            "record_id": encounter_id,
            "reason": "Correct a finalized clinical note",
            "content": {"assessment": "Corrected wording"},
        },
    )
    assert response.status_code == 201, response.text
    async with tenant_session(tenant["org"].schema_name) as db:
        from app.clinical.models import Encounter, RecordAddendum

        encounter = await db.get(Encounter, encounter_id)
        addendum = await db.scalar(select(RecordAddendum).where(RecordAddendum.record_id == encounter_id))
        assert encounter.soap == original_soap
        assert addendum and addendum.parent_id is None
        encounter.status = "open"
