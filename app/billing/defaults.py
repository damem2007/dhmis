"""Default clinic service catalogue shared by migrations and provisioning."""

from sqlalchemy import select

from app.billing.models import Service


DEFAULT_SERVICES = (
    ("CHECKUP-CLEAN", "Check-up & clean", "Exam, scale and polish, with X-rays as needed.", 13500),
    ("FILLINGS", "Fillings", "Tooth-coloured repairs for cavities and chips.", 18000),
    ("EMERGENCY", "Emergency visit", "Pain, swelling or a broken tooth. Same-day slots.", 9500),
    ("WHITENING", "Whitening", "In-clinic or take-home options.", 32000),
    ("CHILDREN-DENTISTRY", "Children’s dentistry", "Gentle first visits and preventive care.", 8500),
    ("CONSULTATION", "Consultation", "Talk through a treatment plan and costs.", 0),
)


async def ensure_default_services(db, actor="tenant-defaults"):
    """Seed defaults for an empty catalogue without changing tenant data."""
    existing = set((await db.scalars(select(Service.code))).all())
    # A non-empty catalogue is tenant-owned. The read-path backfill is only
    # for legacy schemas that never received the bootstrap migration; it must
    # not recreate services a clinic intentionally removed.
    if existing:
        return
    for code, name, description, fee_cents in DEFAULT_SERVICES:
        db.add(
            Service(
                code=code,
                name=name,
                description=description,
                fee_cents=fee_cents,
                created_by=actor,
                updated_by=actor,
            )
        )
    await db.flush()
