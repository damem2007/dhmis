from datetime import date, timedelta

from fastapi import HTTPException
from sqlalchemy import select

from app.operations.models import ProviderCredential


async def credential_state(db, provider_id: str):
    rows = (
        await db.scalars(
            select(ProviderCredential).where(
                ProviderCredential.provider_id == provider_id,
                ProviderCredential.required,
            )
        )
    ).all()
    today = date.today()
    return [
        (
            row,
            "expired"
            if row.expires_on < today
            else "expiring"
            if row.expires_on <= today + timedelta(days=row.alert_lead_days)
            else "valid",
        )
        for row in rows
    ]


async def require_current_credentials(db, provider_id: str):
    states = await credential_state(db, provider_id)
    expired = [row for row, state in states if state == "expired"]
    if expired:
        raise HTTPException(409, "Provider has an expired required credential")

