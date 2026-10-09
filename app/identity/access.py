from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy import select

from app.identity.models import (
    StaffInvite,
    StaffInviteAssignment,
    StaffLocationAssignment,
    StaffUser,
)


@dataclass(frozen=True)
class EffectiveAccess:
    role: str
    scope: str
    selected_location_id: str | None
    available_location_ids: list[str]
    assignments: list[dict]


async def user_assignments(db, user: StaffUser) -> list[StaffLocationAssignment]:
    rows = (
        await db.scalars(
            select(StaffLocationAssignment)
            .where(StaffLocationAssignment.user_id == user.id, StaffLocationAssignment.active)
            .order_by(StaffLocationAssignment.scope, StaffLocationAssignment.location_id)
        )
    ).all()
    if not rows:
        raise HTTPException(403, "No active staff access assignment")
    return list(rows)


async def invite_assignments(db, invitation: StaffInvite) -> list[StaffInviteAssignment]:
    rows = (
        await db.scalars(
            select(StaffInviteAssignment)
            .where(StaffInviteAssignment.invite_id == invitation.id)
            .order_by(StaffInviteAssignment.scope, StaffInviteAssignment.location_id)
        )
    ).all()
    if not rows:
        raise HTTPException(409, "Invitation has no access assignment")
    return list(rows)


async def effective_access(
    db, user: StaffUser, requested_location_id: str | None
) -> EffectiveAccess:
    rows = await user_assignments(db, user)
    organization_assignment = next((row for row in rows if row.scope == "organization"), None)
    location_rows = [row for row in rows if row.scope == "location"]
    selected = None
    if requested_location_id:
        selected = next(
            (row for row in location_rows if row.location_id == requested_location_id), None
        )
        if selected is None and organization_assignment is None:
            raise HTTPException(403, "Location is outside the staff member's assigned access")
    if selected is None:
        selected = organization_assignment or (location_rows[0] if location_rows else None)
    if selected is None:
        raise HTTPException(403, "No active staff access assignment")
    selected_location_id = requested_location_id or selected.location_id
    return EffectiveAccess(
        role=selected.role,
        scope=selected.scope,
        selected_location_id=selected_location_id,
        available_location_ids=[row.location_id for row in location_rows if row.location_id],
        assignments=[
            {
                "id": row.id,
                "location_id": row.location_id,
                "scope": row.scope,
                "role": row.role,
            }
            for row in rows
        ],
    )
