from dataclasses import dataclass

from fastapi import HTTPException

from app.identity.service import ROLE_DEFINITIONS, ROLE_PERMISSIONS

def _profile(definition: dict) -> str:
    modules = set(definition.get("modules", []))
    if definition.get("organization_scope") and {"patients", "billing", "prescriptions"} <= modules:
        return "organization-executive"
    if definition.get("organization_scope") and {"patients", "billing", "clinical"} <= modules:
        return "clinic-admin"
    if definition.get("organization_scope") and "billing" in modules:
        return "organization-executive"
    if definition.get("organization_scope") and modules <= {"settings", "dashboard", "operations", "analytics"}:
        return "system-admin"
    if "prescriptions" in modules and "clinical" in modules:
        return "dentist"
    if "billing" in modules and "clinical" in modules:
        return "treatment-coordinator"
    if "clinical" in modules and "consents" in modules:
        return "hygienist"
    if "clinical" in modules:
        return "dental-assistant"
    if "billing" in modules and "clinical" not in modules:
        return "accounting"
    if "operations" in modules:
        return "front-desk"
    if definition.get("organization_scope"):
        return "system-admin"
    return "staff"


ROLE_PROFILE = {name: _profile(definition) for name, definition in ROLE_DEFINITIONS.items()}


@dataclass(frozen=True)
class AnalyticsScope:
    profile: str
    location_ids: tuple[str, ...]
    provider_id: str | None
    can_view_financial: bool
    can_export: bool


def resolve_scope(actor, location_id: str | None = None, provider_id: str | None = None):
    profile = ROLE_PROFILE.get(actor.role)
    if profile is None:
        raise HTTPException(403, "Dashboard role is not configured")
    assigned = tuple(actor.location_ids)
    location_restricted = actor.settings.visibility == "location" or profile in {
        "clinic-admin",
        "dentist",
        "hygienist",
        "dental-assistant",
        "treatment-coordinator",
        "front-desk",
    }
    allowed_locations = assigned if location_restricted else ()
    if location_id and location_restricted and location_id not in allowed_locations:
        raise HTTPException(403, "Location is outside the authorized analytics scope")
    locations = (
        (location_id,)
        if location_id
        else (allowed_locations or ("__unassigned__",))
        if location_restricted
        else ()
    )
    self_scoped = profile in {"dentist", "hygienist"}
    if self_scoped and provider_id and provider_id != actor.user_id:
        raise HTTPException(403, "Provider is outside the authorized analytics scope")
    effective_provider = actor.user_id if self_scoped else provider_id
    financial = profile in {
        "organization-executive",
        "clinic-admin",
        "treatment-coordinator",
        "accounting",
    }
    return AnalyticsScope(
        profile,
        locations,
        effective_provider,
        financial,
        "analytics_export" in ROLE_PERMISSIONS.get(actor.role, set()),
    )
