"""Stable appointment presentation helpers shared by schedule surfaces."""

from datetime import UTC, datetime

from app.core.repository import serialize


# Normalize a datetime for the status comparison even when a legacy row is naïve.
def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


# Derive the patient-facing missed state without mutating the appointment record.
def effective_status(row, now: datetime | None = None) -> str:
    status = row.status or "confirmed"
    if status == "confirmed" and _as_utc(row.ends_at) <= (now or datetime.now(UTC)):
        return "missed"
    return status


# Serialize an appointment with its authoritative timezone and derived display status.
def present_appointment(row, now: datetime | None = None) -> dict:
    payload = serialize(row)
    payload["timezone"] = payload.get("timezone") or "UTC"
    payload["status"] = effective_status(row, now)
    payload["is_missed"] = payload["status"] == "missed"
    return payload
