"""Load deterministic synthetic patient data into the Smile development tenant.

This is an explicit development/test utility. It is intentionally separate from
Alembic migrations and is never imported by the application at startup.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import date, timedelta
from uuid import uuid4

from sqlalchemy import func, select

from app.claims.models import InsurancePlan
from app.core.database import control_session, dispose_engines, tenant_session
from app.organizations.models import Location, Organization
from app.patients.models import Patient

SYNTHETIC_EMAIL_PREFIX = "loadtest+smile-"
SYNTHETIC_EMAIL_DOMAIN = "@synthetic.dhmis.local"


# Parse the command-line options for the one-off data load.
def parse_args() -> argparse.Namespace:
    """Return validated options for the development data load."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--count",
        type=int,
        default=5000,
        help="Target number of synthetic patients in the Smile tenant (default: 5000).",
    )
    parser.add_argument(
        "--with-insurance",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Create one synthetic insurance plan per generated patient (default: enabled).",
    )
    return parser.parse_args()


# Build deterministic, non-clinical patient values for the load test.
def patient_values(index: int, location_id: str) -> dict[str, object]:
    """Return a synthetic patient record that is safe to rerun."""

    sequence = f"{index:05d}"
    return {
        "id": str(uuid4()),
        "first_name": "Load",
        "last_name": f"Test {sequence}",
        "birth_date": date(1970, 1, 1) + timedelta(days=index % 14000),
        "email": f"{SYNTHETIC_EMAIL_PREFIX}{sequence}{SYNTHETIC_EMAIL_DOMAIN}",
        "phone": f"+155500{index:05d}",
        "allergies": [],
        "location_id": location_id,
        "medical_history": "",
        "dental_history": "",
        "alerts": [],
        "created_by": "development-load-test",
        "updated_by": "development-load-test",
    }


# Create related insurance records for the generated patient identifiers.
def insurance_values(patient: dict[str, object], location_id: str) -> dict[str, object]:
    """Return a synthetic insurance plan linked to one generated patient."""

    return {
        "id": str(uuid4()),
        "patient_id": patient["id"],
        "location_id": location_id,
        "payer_name": "Synthetic Coverage",
        "member_id": f"SYN-{patient['id']}",
        "priority": 1,
        "coverage_pct": 80,
        "maximum_cents": 200000,
        "used_cents": 0,
        "created_by": "development-load-test",
        "updated_by": "development-load-test",
    }


# Seed Smile with synthetic patients without touching migrations or startup code.
async def seed(count: int, with_insurance: bool) -> dict[str, int | str]:
    """Fill the Smile tenant up to ``count`` synthetic patients and report totals."""

    if count < 1:
        raise ValueError("--count must be at least 1")

    async with control_session() as control_db:
        organization = await control_db.scalar(select(Organization).where(Organization.slug == "smile"))
        if organization is None:
            raise RuntimeError("The Smile tenant was not found in the control database")

    async with tenant_session(organization.schema_name, organization.database_alias) as db:
        locations = (
            await db.scalars(select(Location).where(Location.active.is_(True)).order_by(Location.created_at))
        ).all()
        if not locations:
            raise RuntimeError("The Smile tenant has no active location for synthetic patients")

        existing = (
            await db.scalars(select(Patient).where(Patient.email.like(f"{SYNTHETIC_EMAIL_PREFIX}%")))
        ).all()
        existing_by_email = {row.email for row in existing}
        target = min(count, 99999)
        missing = target - len(existing_by_email)
        if missing <= 0:
            related_count = 0
            if with_insurance:
                related_count = await db.scalar(
                    select(func.count())
                    .select_from(InsurancePlan)
                    .join(Patient, InsurancePlan.patient_id == Patient.id)
                    .where(Patient.email.like(f"{SYNTHETIC_EMAIL_PREFIX}%"))
                )
            return {
                "tenant": organization.slug,
                "target": target,
                "inserted_patients": 0,
                "synthetic_patients": len(existing_by_email),
                "insurance_records": int(related_count or 0),
            }

        next_index = 1
        patient_rows: list[dict[str, object]] = []
        while len(patient_rows) < missing:
            email = f"{SYNTHETIC_EMAIL_PREFIX}{next_index:05d}{SYNTHETIC_EMAIL_DOMAIN}"
            next_index += 1
            if email in existing_by_email:
                continue
            location = locations[len(patient_rows) % len(locations)]
            patient_rows.append(patient_values(next_index - 1, location.id))

        db.add_all(Patient(**row) for row in patient_rows)
        await db.flush()

        insurance_inserted = 0
        if with_insurance:
            insurance_rows = [insurance_values(row, row["location_id"]) for row in patient_rows]
            db.add_all(InsurancePlan(**row) for row in insurance_rows)
            insurance_inserted = len(insurance_rows)

        return {
            "tenant": organization.slug,
            "target": target,
            "inserted_patients": len(patient_rows),
            "synthetic_patients": len(existing_by_email) + len(patient_rows),
            "insurance_records": insurance_inserted,
        }


# Run the explicit development seed command and release database pools.
async def main() -> None:
    """Execute the one-off Smile load and print a machine-readable summary."""

    args = parse_args()
    result = await seed(args.count, args.with_insurance)
    print(result)
    await dispose_engines()


if __name__ == "__main__":
    asyncio.run(main())
