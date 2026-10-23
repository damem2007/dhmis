from dataclasses import dataclass

from fastapi import HTTPException
from sqlalchemy import select

from app.identity.models import (
    StaffInvite,
    StaffInviteAssignment,
    StaffLocationAssignment,
    StaffUser,
)
from app.rbac.models import TenantRole, TenantRoleAssignment

TENANT_SUPER_ADMIN_ROLE_ID = "tenant-super-admin"


def _is_tenant_super_admin(role_id: str | None, role_name: str | None = None) -> bool:
    """Recognize the protected role across canonical and legacy identifiers."""

    normalized_id = str(role_id or "").strip().casefold().replace("_", "-")
    return normalized_id == TENANT_SUPER_ADMIN_ROLE_ID


# Defines the effective access model, contract, or value object.
@dataclass(frozen=True)
class EffectiveAccess:
    role_id: str | None
    role: str
    scope: str
    selected_location_id: str | None
    available_location_ids: list[str]
    assignments: list[dict]


@dataclass(frozen=True)
class CanonicalAccessAssignment:
    """Expose a role-table assignment with the legacy access shape."""

    id: str
    role_id: str
    role: str
    scope: str
    location_id: str | None
    created_at: object


# Handle user assignments for this module.
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


# Handle invite assignments for this module.
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


# Handle effective access for this module.
async def effective_access(
    db, user: StaffUser, requested_location_id: str | None
) -> EffectiveAccess:
    canonical_rows = (
        await db.execute(
            select(TenantRoleAssignment, TenantRole.name)
            .join(TenantRole, TenantRole.id == TenantRoleAssignment.role_id)
            .where(
                TenantRoleAssignment.user_id == user.id,
                TenantRole.status == "published",
            )
            .order_by(
                TenantRoleAssignment.created_at,
                TenantRoleAssignment.id,
            )
        )
    ).all()
    if canonical_rows:
        rows = [
            CanonicalAccessAssignment(
                id=assignment.id,
                role_id=assignment.role_id,
                role=role_name,
                scope=assignment.level.lower(),
                location_id=assignment.location_id,
                created_at=assignment.created_at,
            )
            for assignment, role_name in canonical_rows
        ]
    else:
        legacy_rows = await user_assignments(db, user)
        rows = [
            CanonicalAccessAssignment(
                id=assignment.id,
                role_id=user.role_id or assignment.role,
                role=assignment.role,
                scope=assignment.scope,
                location_id=assignment.location_id,
                created_at=assignment.created_at,
            )
            for assignment in legacy_rows
        ]

    # The protected canonical assignment takes precedence over any stale
    # legacy/admin projection. This keeps a user with both rows effective as
    # Tenant Super Admin until the reconciliation migration normalizes the
    # informational user.role and role_id columns.
    preferred = next(
        (row for row in rows if _is_tenant_super_admin(row.role_id, row.role)),
        None,
    ) or next((row for row in rows if row.role_id == user.role_id), None)
    organization_assignment = next(
        (row for row in rows if row.scope == "organization" and row is preferred),
        None,
    ) or next((row for row in rows if row.scope == "organization"), None)
    location_rows = [row for row in rows if row.scope == "location"]
    selected = None
    if requested_location_id:
        # Tenant Super Admin is organization-wide. Keep that protected role
        # effective even when the browser sends a selected location and an
        # older location-level admin projection is still present.
        if organization_assignment and _is_tenant_super_admin(
            organization_assignment.role_id, organization_assignment.role
        ):
            selected = organization_assignment
        else:
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
        role_id=(
            TENANT_SUPER_ADMIN_ROLE_ID
            if _is_tenant_super_admin(selected.role_id, selected.role)
            else selected.role_id
        ),
        role=selected.role,
        scope=selected.scope,
        selected_location_id=selected_location_id,
        available_location_ids=[row.location_id for row in location_rows if row.location_id],
        assignments=[
            {
                "id": row.id,
                "role_id": row.role_id,
                "location_id": row.location_id,
                "scope": row.scope,
                "role": row.role,
            }
            for row in rows
        ],
    )
