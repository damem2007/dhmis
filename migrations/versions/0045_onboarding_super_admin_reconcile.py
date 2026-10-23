"""Reconcile onboarding assignments while preserving Tenant Super Admin."""

import sqlalchemy as sa
from alembic import context, op
from uuid import uuid4

from app.rbac.registry import load_approved_registry


revision = "0045_onboard_superadmin_fix"
down_revision = "0044_role_display_reconcile"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Remove only generated admin duplicates and normalize setup users."""

    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names(schema=schema))
    required = {"staff_users", "tenant_role_assignments", "tenant_roles", "tenant_role_grants"}
    if not required.issubset(tables):
        return
    has_super_admin_role = bind.execute(
        sa.text(
            f'SELECT 1 FROM "{schema}".tenant_roles '
            "WHERE id = 'tenant-super-admin' LIMIT 1"
        )
    ).scalar()
    registry = load_approved_registry()
    grant_rows = []
    if has_super_admin_role:
        existing = {
            row[0]
            for row in bind.execute(
                sa.text(
                    f'SELECT permission_key FROM "{schema}".tenant_role_grants '
                    "WHERE role_id = 'tenant-super-admin'"
                )
            )
        }
        for permission in registry.permissions.values():
            if (
                permission.domain.value != "tenant"
                or not permission.reviewed
                or permission.retired
                or permission.key in existing
            ):
                continue
            scopes = {scope.value for scope in permission.valid_scopes}
            scope = "Organization" if "Organization" in scopes else "Location" if "Location" in scopes else None
            if scope is not None:
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
                f'''
                INSERT INTO "{schema}".tenant_role_grants
                    (id, role_id, permission_key, effect, scope, conditions,
                     created_at, updated_at, created_by, updated_by)
                VALUES
                    (:id, 'tenant-super-admin', :permission_key, 'allow', :scope,
                     '{{}}'::json, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                     'onboarding-superadmin-migration',
                     'onboarding-superadmin-migration')
                ON CONFLICT (role_id, permission_key) DO NOTHING
                '''
            ),
            grant_rows,
        )
    op.execute(
        sa.text(
            f'''
            DELETE FROM "{schema}".tenant_role_assignments requested
            USING "{schema}".tenant_role_assignments setup,
                  "{schema}".tenant_roles requested_role
            WHERE setup.user_id = requested.user_id
              AND setup.level = 'Organization'
              AND setup.role_id = 'tenant-super-admin'
              AND requested.level = 'Organization'
              AND requested.role_id <> setup.role_id
              AND requested.role_id = requested_role.id
              AND lower(requested_role.name) IN ('admin', 'organization-admin')
              AND requested.created_by = requested.user_id
              AND setup.created_by = requested.user_id
            '''
        )
    )
    op.execute(
        sa.text(
            f'''
            UPDATE "{schema}".staff_users u
            SET role_id = setup.role_id,
                role = setup_role.name
            FROM "{schema}".tenant_role_assignments setup
            JOIN "{schema}".tenant_roles setup_role
              ON setup_role.id = setup.role_id
            WHERE setup.user_id = u.id
              AND setup.level = 'Organization'
              AND setup.role_id = 'tenant-super-admin'
            '''
        )
    )


def downgrade() -> None:
    """Keep the project's forward-only migration policy."""

    raise RuntimeError("Use a reviewed forward migration")
