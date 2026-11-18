"""Timezone selection for tenant communications.

Message timestamps are rendered for the recipient rather than for the worker
that happens to send the message.  A staff member or pending invite can carry
an ordered ``location_ids`` list; its first active location is therefore the
authoritative display timezone.  Organization-scoped recipients fall back to
the tenant's first active location, which is the tenant's initial/primary
location in the current data model.
"""

from datetime import UTC, datetime, time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select

from app.identity.models import StaffLocationAssignment
from app.organizations.models import Location

DEFAULT_TIMEZONE = "America/Vancouver"


async def recipient_timezone(db, recipient=None, *, location_id: str | None = None) -> str:
    """Return the timezone for a recipient's first assigned active location.

    ``location_ids`` is intentionally consulted first because it retains the
    assignment order supplied for both staff users and pending invitations.
    When a recipient is tenant-scoped (or has no active location), the first
    active tenant location is the existing primary-location fallback.
    """

    candidate_ids = [location_id] if location_id else list(getattr(recipient, "location_ids", []) or [])
    for candidate_id in candidate_ids:
        location = await db.get(Location, candidate_id)
        if location is not None and location.active and _valid_timezone(location.timezone):
            return location.timezone

    recipient_id = getattr(recipient, "id", None)
    if recipient_id:
        assigned_location = await db.scalar(
            select(Location)
            .join(StaffLocationAssignment, StaffLocationAssignment.location_id == Location.id)
            .where(
                StaffLocationAssignment.user_id == recipient_id,
                StaffLocationAssignment.scope == "location",
                StaffLocationAssignment.active.is_(True),
                Location.active.is_(True),
            )
            .order_by(StaffLocationAssignment.assigned_at.asc(), Location.id.asc())
            .limit(1)
        )
        if assigned_location is not None and _valid_timezone(assigned_location.timezone):
            return assigned_location.timezone

    location = await db.scalar(
        select(Location)
        .where(Location.active.is_(True))
        .order_by(Location.created_at.asc(), Location.id.asc())
        .limit(1)
    )
    if location is not None and _valid_timezone(location.timezone):
        return location.timezone
    return DEFAULT_TIMEZONE


def format_recipient_datetime(value: datetime | int | float, timezone_name: str) -> str:
    """Render an instant in a validated IANA timezone, with its zone label."""

    instant = datetime.fromtimestamp(value, UTC) if isinstance(value, (int, float)) else value
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=UTC)
    zone = ZoneInfo(timezone_name) if _valid_timezone(timezone_name) else ZoneInfo(DEFAULT_TIMEZONE)
    return instant.astimezone(zone).strftime("%B %-d, %Y at %-I:%M %p %Z")


def local_delivery_time(day, timezone_name: str, *, hour: int = 9) -> datetime:
    """Return the UTC instant corresponding to a tenant-local delivery time."""

    zone = ZoneInfo(timezone_name) if _valid_timezone(timezone_name) else ZoneInfo(DEFAULT_TIMEZONE)
    return datetime.combine(day, time(hour), tzinfo=zone).astimezone(UTC)


def _valid_timezone(value: str | None) -> bool:
    if not value:
        return False
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError:
        return False
    return True
