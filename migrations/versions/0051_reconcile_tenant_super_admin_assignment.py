"""Reconcile the bootstrap organization assignment to Tenant Super Admin.

Older tenant schemas can contain the protected role and its grants while the
original organization administrator still has only a legacy ``admin`` role
assignment.  The canonical setup role must own the tenant-wide permissions so
the role editor and runtime actor agree about who holds them.
"""

from uuid import uuid4

import sqlalchemy as sa
from alembic import context, op

from app.identity.service import default_role_name
from app.rbac.registry import load_approved_registry


revision = "0051_superadmin_assignment"
down_revision = "0050_treatment_applicability"
branch_labels = None
depends_on = None


# Reconcile the first organization-level bootstrap assignment without naming a tenant.
def upgrade() -> None:
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names(schema=schema))
    required = {
        "staff_users",
        "staff_location_assignments",
        "tenant_roles",
        "tenant_role_grants",
        "tenant_role_assignments",
    }
    if not required.issubset(tables):
        return

    role_exists = bind.execute(
        sa.text(
            f'''SELECT 1 FROM "{schema}".tenant_roles
                WHERE id = 'tenant-super-admin'
                  AND status <> 'archived'
                LIMIT 1'''
        )
    ).scalar()
    if role_exists is None:
        return

    # Repair the protected role grants as well. This covers tenants where the
    # role existed when an earlier repair ran but its grant backfill was
    # interrupted or skipped.
    existing_grants = {
        row[0]
        for row in bind.execute(
            sa.text(
                f'''SELECT permission_key FROM "{schema}".tenant_role_grants
                    WHERE role_id = 'tenant-super-admin' '''
            )
        )
    }
    grant_rows = []
    for permission in load_approved_registry().permissions.values():
        if (
            permission.domain.value != "tenant"
            or not permission.reviewed
            or permission.retired
            or permission.key in existing_grants
        ):
            continue
        scopes = {scope.value for scope in permission.valid_scopes}
        scope = "Organization" if "Organization" in scopes else "Location" if "Location" in scopes else None
        if scope is None:
            continue
        grant_rows.append(
            {
                "id": str(uuid4()),
                "permission_key": permission.key,
                "scope": scope,
            }
        )
    if grant_rows:
        bind.execute(
            sa.text(
                f'''INSERT INTO "{schema}".tenant_role_grants
                    (id, role_id, permission_key, effect, scope, conditions,
                     created_at, updated_at, created_by, updated_by)
                    VALUES (:id, 'tenant-super-admin', :permission_key, 'allow', :scope,
                            '{{}}'::json, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                            'tenant-superadmin-assignment-reconciliation',
                            'tenant-superadmin-assignment-reconciliation')
                    ON CONFLICT (role_id, permission_key) DO NOTHING'''
            ),
            grant_rows,
        )

    has_setup_assignment = bind.execute(
        sa.text(
            f'''SELECT 1 FROM "{schema}".tenant_role_assignments
                WHERE role_id = 'tenant-super-admin'
                  AND level = 'Organization'
                LIMIT 1'''
        )
    ).scalar()
    if has_setup_assignment is not None:
        return

    bootstrap_user = bind.execute(
        sa.text(
            f'''SELECT assignment.user_id
                FROM "{schema}".staff_location_assignments assignment
                JOIN "{schema}".staff_users staff
                  ON staff.id = assignment.user_id
                WHERE assignment.active
                  AND assignment.scope = 'organization'
                  AND lower(assignment.role) = lower(:bootstrap_role)
                  AND staff.active
                  AND staff.archived_at IS NULL
                ORDER BY assignment.assigned_at, assignment.created_at, assignment.id
                LIMIT 1'''
        ),
        {"bootstrap_role": default_role_name("organization")},
    ).scalar()
    if bootstrap_user is None:
        return

    assignment_id = str(uuid4())
    bind.execute(
        sa.text(
            f'''INSERT INTO "{schema}".tenant_role_assignments
                (id, user_id, role_id, level, location_id, expires_at,
                 created_at, updated_at, created_by, updated_by)
                VALUES (:id, :user_id, 'tenant-super-admin', 'Organization', NULL,
                        NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                        'tenant-superadmin-assignment-reconciliation',
                        'tenant-superadmin-assignment-reconciliation')
                ON CONFLICT DO NOTHING'''
        ),
        {"id": assignment_id, "user_id": bootstrap_user},
    )
    bind.execute(
        sa.text(
            f'''UPDATE "{schema}".staff_users
                SET role_id = 'tenant-super-admin',
                    role = 'Tenant Super Admin',
                    updated_by = 'tenant-superadmin-assignment-reconciliation',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :user_id'''
        ),
        {"user_id": bootstrap_user},
    )


# Keep the project's forward-only authorization migration policy.
def downgrade() -> None:
    raise RuntimeError("Use a reviewed forward migration")
