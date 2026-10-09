"""Idempotent development seed: all demo data is persisted in PostgreSQL."""

from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select, text

from app.billing.models import Invoice, LedgerEntry, Service
from app.clinical.models import ChartEntry
from app.consents.models import Consent
from app.core.audit import audit
from app.core.config import settings
from app.core.database import organization_session
from app.core.repository import add
from app.identity.models import StaffLocationAssignment, StaffUser
from app.identity.passwords import hash_password
from app.identity.service import Actor
from app.integrations.configuration import attach_effective_adapters
from app.organizations.configuration import tenant_settings
from app.organizations.models import Location
from app.patients.models import Patient
from app.scheduling.schemas import Booking
from app.scheduling.service import book

DEMO_ORG_ID = "d1100000-0000-4000-8000-000000000001"


async def seed(org):
    if org.slug.startswith("tenant-"):
        from app.core.database import control_session

        async with control_session() as control:
            stored = await control.get(type(org), org.id)
            stored.slug = "dhmis-demo"
        org.slug = "dhmis-demo"
    adapter_names = await attach_effective_adapters(org)
    async with organization_session(org) as db:
        runtime_settings = await tenant_settings(db)
        await db.execute(text("SELECT pg_advisory_xact_lock(726430120)"))
        if await db.scalar(select(StaffUser).where(StaffUser.email == "admin@dhmis.test")):
            return {"organization_id": org.id, "email": "admin@dhmis.test", "seeded": False}
        location = await add(db, Location, {"name": "DHMIS Demo Clinic · Vancouver"}, "seed")
        user = await add(
            db,
            StaffUser,
            {
                "name": "Dr. Alex Chen",
                "email": "admin@dhmis.test",
                "role": "admin",
                "password_hash": hash_password(settings().demo_password.get_secret_value()),
            },
            "seed",
        )
        dentist = await add(
            db,
            StaffUser,
            {
                "name": "Dr. Jordan Lee",
                "email": "dentist@dhmis.test",
                "role": "dentist",
                "password_hash": hash_password(settings().demo_password.get_secret_value()),
                "location_ids": [location.id],
            },
            "seed",
        )
        db.add_all(
            [
                StaffLocationAssignment(
                    user_id=user.id,
                    location_id=None,
                    scope="organization",
                    role="admin",
                    active=True,
                    created_by="seed",
                    updated_by="seed",
                ),
                StaffLocationAssignment(
                    user_id=dentist.id,
                    location_id=location.id,
                    scope="location",
                    role="dentist",
                    active=True,
                    created_by="seed",
                    updated_by="seed",
                ),
            ]
        )
        await db.flush()
        actor = Actor(
            user.id,
            org,
            user.name,
            user.role,
            settings=runtime_settings,
            adapter_names=adapter_names,
            assignment_scope="organization",
        )
        people = []
        for first, last, dob in [
            ("Avery", "Sample", date(1988, 3, 12)),
            ("Morgan", "Example", date(1994, 8, 4)),
            ("Taylor", "Demo", date(1979, 1, 22)),
        ]:
            people.append(
                await add(
                    db,
                    Patient,
                    {
                        "first_name": first,
                        "last_name": last,
                        "birth_date": dob,
                        "email": first.lower() + "@example.test",
                        "phone": "604-555-0100",
                        "location_id": location.id,
                    },
                    user.id,
                )
            )
        zone = ZoneInfo("America/Vancouver")
        start = datetime.combine(datetime.now(zone).date(), time(9), tzinfo=zone)
        for index, patient in enumerate(people):
            await book(
                db,
                actor,
                Booking(
                    patient_id=patient.id,
                    location_id=location.id,
                    provider_id=dentist.id,
                    chair="Op 1",
                    starts_at=start + timedelta(hours=index),
                    ends_at=start + timedelta(hours=index, minutes=45),
                    procedure=["Hygiene and exam", "Treatment consultation", "Restoration review"][index],
                ),
            )
        services = []
        for code, name, fee in [
            ("DEMO-EXAM", "Comprehensive exam", 12000),
            ("DEMO-HYG", "Hygiene visit", 18000),
            ("DEMO-REST", "Restoration consultation", 9500),
        ]:
            services.append(
                await add(
                    db,
                    Service,
                    {
                        "code": code,
                        "name": name,
                        "fee_cents": fee,
                        "description": "Illustrative demo fee — not a clinical coding reference",
                    },
                    user.id,
                )
            )
        service = services[0]
        invoice = await add(
            db,
            Invoice,
            {
                "patient_id": people[0].id,
                "location_id": location.id,
                "total_cents": service.fee_cents,
                "lines": [
                    {
                        "service_id": service.id,
                        "code": service.code,
                        "name": service.name,
                        "fee_cents": service.fee_cents,
                    }
                ],
            },
            user.id,
        )
        await add(
            db,
            LedgerEntry,
            {
                "patient_id": people[0].id,
                "location_id": location.id,
                "invoice_id": invoice.id,
                "kind": "charge",
                "amount_cents": service.fee_cents,
                "idempotency_key": "charge:" + invoice.id,
            },
            user.id,
        )
        await add(
            db,
            ChartEntry,
            {
                "patient_id": people[0].id,
                "location_id": location.id,
                "tooth": "14",
                "surface": "occlusal",
                "condition": "Observation",
                "notes": "Fictional training record.",
            },
            user.id,
        )
        await add(
            db,
            Consent,
            {"patient_id": people[0].id, "location_id": location.id, "title": "Demo treatment consent"},
            user.id,
        )
        audit(db, user.id, "seed", "development", org.id, synthetic=True)
    return {"organization_id": org.id, "email": "admin@dhmis.test", "seeded": True}
