"""Patient visibility derived from the effective RBAC grant."""

from app.rbac.policy import Scope
from app.rbac.runtime import decide_tenant

PATIENT_READ_PERMISSION = "patients.patient_profile.read"


async def patient_read_decision(db, actor):
    """Return the canonical patient read decision for the current actor.

    Older sessions can still carry the legacy ``patients`` module alias. They
    retain organization-wide visibility until their role is represented by a
    canonical grant; canonical roles always use the decision's reach/filter.
    """

    decision = await decide_tenant(
        db,
        actor.user_id,
        PATIENT_READ_PERMISSION,
        selected_location_id=actor.selected_location_id,
    )
    if decision.allowed:
        return decision
    if "patients" in actor.modules:
        return None
    return decision


# Return whether the effective decision requires assigned-patient filtering.
def needs_assigned_patient_filter(decision) -> bool:
    return bool(decision is not None and decision.filter_scope is Scope.ASSIGNED)


def needs_location_patient_filter(decision, actor=None) -> bool:
    """Return whether patient visibility is limited to assigned clinics."""
    if decision is not None:
        return decision.reach is Scope.LOCATION
    # Legacy module grants do not produce a canonical decision. Preserve the
    # staff assignment boundary while those roles are migrated to resource
    # grants; organization-scoped staff remain tenant-wide.
    return bool(actor is not None and actor.assignment_scope != "organization")


def visible_location_ids(actor) -> set[str]:
    """Return the clinics available to a location-scoped staff member."""
    ids = {location_id for location_id in actor.location_ids if location_id}
    if actor.selected_location_id:
        ids.add(actor.selected_location_id)
    return ids
