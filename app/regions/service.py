from fastapi import HTTPException
from sqlalchemy import select

from app.regions.models import PlatformRegion


REGION_DEFAULTS = {
    "CA": {
        "name": "Canada",
        "jurisdiction_provider": "canada",
        "claims_route": "Sandbox1_CDAnet",
        "locale": "en-CA",
        "currency": "CAD",
        "tax_defaults": {"tax_rate_basis_points": 0},
        "residency_defaults": {"data_residency": "CA"},
    },
    "US": {
        "name": "United States",
        "jurisdiction_provider": "united-states",
        "claims_route": "Sandbox1_ANSI_X12_835",
        "locale": "en-US",
        "currency": "USD",
        "tax_defaults": {"tax_rate_basis_points": 0},
        "residency_defaults": {"data_residency": "US"},
    },
}


async def ensure_region_registry(db, actor_id: str = "region-bootstrap"):
    rows = {row.code: row for row in (await db.scalars(select(PlatformRegion))).all()}
    for code, values in REGION_DEFAULTS.items():
        row = rows.get(code)
        if row is None:
            db.add(PlatformRegion(code=code, enabled=True, created_by=actor_id, updated_by=actor_id, **values))
    await db.flush()


async def enabled_region(db, code: str) -> PlatformRegion:
    row = await db.scalar(select(PlatformRegion).where(PlatformRegion.code == code.upper()))
    if row is None:
        raise HTTPException(422, "Unsupported region")
    if not row.enabled:
        raise HTTPException(409, "Region is disabled for new assignments")
    return row
