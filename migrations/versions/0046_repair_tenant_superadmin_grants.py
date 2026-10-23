"""Repair the canonical Tenant Super Admin role grants in every tenant schema.

The onboarding reconciliation migration is already applied in existing
installations, so this forward migration repairs tenants where the protected
role exists but its persisted grant rows were not created. It deliberately
reads the approved control-plane registry and never embeds tenant identities.
"""

from uuid import uuid4

import sqlalchemy as sa
from alembic import context, op

from app.rbac.registry import load_approved_registry


revision = "0046_repair_superadmin_grants"
down_revision = "0045_onboard_superadmin_fix"
branch_labels = None
depends_on = None


# Repair the protected tenant setup role without changing ordinary role grants.
def upgrade() -> None:
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names(schema=schema))
    required = {"tenant_roles", "tenant_role_grants"}
    if not required.issubset(tables):
        return

    role_exists = bind.execute(
        sa.text(
            f'SELECT 1 FROM "{schema}".tenant_roles '
            "WHERE id = 'tenant-super-admin' LIMIT 1"
        )
    ).scalar()
    if role_exists is None:
        return

    # The role is protected by its canonical id, so normalize metadata even
    # when an earlier partial bootstrap left it in an unusable state.
    bind.execute(
        sa.text(
            f'''UPDATE "{schema}".tenant_roles
                SET domain = 'tenant',
                    name = 'Tenant Super Admin',
                    status = 'published',
                    locked = TRUE,
                    description = 'Locked tenant role with every active reviewed tenant permission.',
                    updated_by = 'tenant-superadmin-grants-repair',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = 'tenant-super-admin' '''
        )
    )

    existing = {
        row[0]
        for row in bind.execute(
            sa.text(
                f'''SELECT permission_key
                    FROM "{schema}".tenant_role_grants
                    WHERE role_id = 'tenant-super-admin' '''
            )
        )
    }
    grant_rows = []
    registry = load_approved_registry()
    for permission in registry.permissions.values():
        if (
            permission.domain.value != "tenant"
            or not permission.reviewed
            or permission.retired
            or permission.key in existing
        ):
            continue
        valid_scopes = {scope.value for scope in permission.valid_scopes}
        if "Organization" in valid_scopes:
            scope = "Organization"
        elif "Location" in valid_scopes:
            scope = "Location"
        else:
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
                VALUES
                    (:id, 'tenant-super-admin', :permission_key, 'allow', :scope,
                     '{{}}'::json, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                     'tenant-superadmin-grants-repair',
                     'tenant-superadmin-grants-repair')
                ON CONFLICT (role_id, permission_key) DO NOTHING'''
            ),
            grant_rows,
        )


# The project uses forward-only migration policy for authorization data.
def downgrade() -> None:
    raise RuntimeError("Use a reviewed forward migration")
