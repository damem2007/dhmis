from datetime import date
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select

from app.core.audit import audit
from app.core.database import control_session
from app.core.repository import add, required, serialize
from app.identity.models import StaffUser
from app.identity.service import db_session, permit
from app.integrations.contracts import IntegrationFailure
from app.integrations.models import PlatformAdapterDefault
from app.integrations.registry import resolve_registered
from app.operations.models import ProviderCredential
from app.operations.service import credential_state
from app.organizations.models import Location

router = APIRouter(prefix="/operations", tags=["Practice operations"])


class CredentialInput(BaseModel):
    provider_id: str
    location_id: str | None = None
    credential_type: str = Field(min_length=2, max_length=120)
    credential_number: str = Field(min_length=2, max_length=160)
    jurisdiction: str = Field(min_length=2, max_length=80)
    issued_on: date
    expires_on: date
    alert_lead_days: int = Field(default=60, ge=1, le=365)
    required: bool = True

    @model_validator(mode="after")
    def valid_dates(self):
        if self.expires_on <= self.issued_on:
            raise ValueError("Credential expiry must follow its issue date")
        return self


class LocationInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    address: str = Field(default="", max_length=500)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    osm_place_id: str = Field(default="", max_length=120)
    timezone: str = Field(min_length=2, max_length=60)
    chairs: list[str] = Field(min_length=1, max_length=100)
    opening_hour: int = Field(ge=0, le=23)
    closing_hour: int = Field(ge=1, le=24)
    branding: dict[str, str] = Field(default_factory=dict)
    policy: dict[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def valid_location(self):
        if self.closing_hour <= self.opening_hour:
            raise ValueError("Closing hour must follow opening hour")
        if len(set(self.chairs)) != len(self.chairs) or any(not chair.strip() for chair in self.chairs):
            raise ValueError("Operatories must have unique non-empty names")
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as error:
            raise ValueError("Unknown timezone") from error
        if set(self.policy) - {
            "buffer_minutes",
            "cancellation_notice_hours",
            "cancellation_fee_cents",
            "reminder_hours",
        }:
            raise ValueError("Unknown location policy")
        if any(value < 0 or value > 10080 for value in self.policy.values()):
            raise ValueError("Invalid location policy value")
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("Latitude and longitude must be supplied together")
        return self


def credential_result(row, state):
    return {**serialize(row), "state": state}


@router.get("/credentials")
async def credentials(
    provider_id: str | None = Query(default=None),
    db=Depends(db_session),
    actor=Depends(permit("operations")),
):
    if provider_id:
        await required(db, StaffUser, provider_id)
        rows = await credential_state(db, provider_id)
    else:
        records = (await db.scalars(select(ProviderCredential))).all()
        rows = []
        for record in records:
            state = next(
                value
                for row, value in await credential_state(db, record.provider_id)
                if row.id == record.id
            )
            rows.append((record, state))
    audit(db, actor.user_id, "read", "provider_credentials")
    return [credential_result(row, state) for row, state in rows]


@router.get("/credential-alerts")
async def credential_alerts(db=Depends(db_session), actor=Depends(permit("operations"))):
    records = (await db.scalars(select(ProviderCredential))).all()
    alerts = []
    for provider_id in {record.provider_id for record in records}:
        alerts.extend(
            credential_result(row, state)
            for row, state in await credential_state(db, provider_id)
            if state in ("expiring", "expired")
        )
    audit(db, actor.user_id, "read", "credential_alerts", count=len(alerts))
    return alerts


@router.get("/geocode/search")
async def search_location(
    q: str = Query(min_length=3, max_length=180),
    region: str = Query(default="CA", min_length=2, max_length=2, pattern="^[A-Za-z]{2}$"),
    detail: bool = Query(default=False),
    actor=Depends(permit("settings")),
):
    """Search the tenant's configured geocoding provider for a location address."""

    del actor
    async with control_session() as control:
        defaults = (
            await control.scalars(
                select(PlatformAdapterDefault).where(
                    PlatformAdapterDefault.capability == "geocoding_provider",
                    PlatformAdapterDefault.active,
                    PlatformAdapterDefault.region.in_(["*", region.upper()]),
                )
            )
        ).all()
    selected = next((row for row in defaults if row.region == region.upper()), None) or next(
        (row for row in defaults if row.region == "*"), None
    )
    if selected is None:
        raise HTTPException(503, "No geocoding provider is configured")
    try:
        provider = resolve_registered(
            "geocoding_provider",
            selected.provider_name,
            region=region.upper(),
            enforce_live=False,
        )
        search = getattr(provider, "search_addresses", provider.search) if detail else provider.search
        return await search(q, region.upper(), limit=5)
    except IntegrationFailure as error:
        raise HTTPException(502, str(error)) from error


@router.post("/credentials", status_code=201)
async def create_credential(
    body: CredentialInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    await required(db, StaffUser, body.provider_id)
    if body.location_id:
        await required(db, Location, body.location_id)
    row = await add(db, ProviderCredential, body.model_dump(), actor.user_id)
    state = (await credential_state(db, row.provider_id))
    current = next(value for credential, value in state if credential.id == row.id)
    audit(db, actor.user_id, "create", "provider_credentials", row.id)
    return credential_result(row, current)


@router.post("/locations", status_code=201)
async def create_location(
    body: LocationInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    row = await add(db, Location, body.model_dump(), actor.user_id)
    audit(db, actor.user_id, "create", "locations", row.id)
    await db.flush()
    return serialize(row)


@router.put("/locations/{identifier}")
async def update_location(
    identifier: str,
    body: LocationInput,
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    row = await required(db, Location, identifier, lock=True)
    for key, value in body.model_dump().items():
        setattr(row, key, value)
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "configure", "locations", row.id)
    await db.flush()
    return serialize(row)
