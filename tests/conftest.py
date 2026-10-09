import base64
import secrets
from datetime import date
from uuid import uuid4

import httpx
import pytest_asyncio

from app.billing.models import Service
from app.claims.models import InsurancePlan
from app.core.database import engine, tenant_session
from app.core.repository import add
from app.identity.models import StaffLocationAssignment, StaffUser
from app.identity.passwords import hash_password
from app.identity.security import vault
from app.identity.service import issue_token
from app.main import app
from app.organizations.models import Location
from app.organizations.provisioning import activate, migrate_schema, provision
from app.rbac.bootstrap import seed_tenant_super_admin
from app.patients.models import Patient


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def tenants():
    await migrate_schema("dhmis_control")
    records = []
    for label in ("A", "B"):
        org = await provision(f"DHMIS Phase 1 verification {label} {uuid4().hex[:8]}")
        secret = base64.b32encode(secrets.token_bytes(20)).decode()
        async with tenant_session(org.schema_name) as db:
            location = await add(db, Location, {"name": f"Verification {label}"}, "test")
            user = await add(
                db,
                StaffUser,
                {
                    "name": f"Test Admin {label}",
                    "email": "admin@example.test",
                    "role": "admin",
                    "password_hash": hash_password("Verification-password-2026!"),
                    "mfa_enabled": True,
                    "mfa_secret": vault().seal(secret),
                    "location_ids": [],
                },
                "test",
            )
            front = await add(
                db,
                StaffUser,
                {
                    "name": "Test Reception",
                    "email": "front@example.test",
                    "role": "front-desk",
                    "password_hash": hash_password("Verification-password-2026!"),
                    "mfa_enabled": True,
                    "mfa_secret": vault().seal(secret),
                    "location_ids": [location.id],
                },
                "test",
            )
            db.add_all(
                [
                    StaffLocationAssignment(
                        user_id=user.id,
                        location_id=None,
                        scope="organization",
                        role="admin",
                        active=True,
                        created_by="test",
                        updated_by="test",
                    ),
                    StaffLocationAssignment(
                        user_id=front.id,
                        location_id=location.id,
                        scope="location",
                        role="front-desk",
                        active=True,
                        created_by="test",
                        updated_by="test",
                    ),
                ]
            )
            await db.flush()
            patient = await add(
                db,
                Patient,
                {
                    "first_name": "Verification",
                    "last_name": label,
                    "birth_date": date(1990, 1, 1),
                    "location_id": location.id,
                    "phone": "604-555-0199",
                },
                "test",
            )
            service = await add(
                db, Service, {"code": "TEST-EXAM", "name": "Verification exam", "fee_cents": 10000}, "test"
            )
            plan = await add(
                db,
                InsurancePlan,
                {
                    "patient_id": patient.id,
                    "location_id": location.id,
                    "payer_name": "Fictional Verification Payer",
                    "member_id": "TEST-0001",
                    "priority": 1,
                    "coverage_pct": 80,
                    "maximum_cents": 200000,
                },
                "test",
            )
            # The runtime authorization model is canonical RBAC. Seed the
            # tenant-super-admin role assignments after creating the fixture
            # users so tests exercise the same fresh-tenant bootstrap path as
            # the application instead of relying on legacy module fallbacks.
            await seed_tenant_super_admin(
                db, "test-fixture-bootstrap", sync_legacy=False
            )
            headers = {
                "Authorization": "Bearer "
                + await issue_token(db, user, org, ttl_seconds=86400)
            }
            front_headers = {
                "Authorization": "Bearer "
                + await issue_token(db, front, org, ttl_seconds=86400)
            }
        org = await activate(org.id)
        records.append(
            {
                "org": org,
                "user": user,
                "front": front,
                "patient": patient,
                "location": location,
                "service": service,
                "plan": plan,
                "secret": secret,
                "headers": headers,
                "front_headers": front_headers,
            }
        )
    yield records
    await engine.dispose()


@pytest_asyncio.fixture
async def client():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield client
