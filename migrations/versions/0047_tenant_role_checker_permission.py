"""Grant tenant role-policy approval to the built-in admin roles.

The checker is a normal, resource-specific RBAC action. This backfill keeps
existing tenants aligned after the permission was added to the registry.
"""

from uuid import uuid4

import sqlalchemy as sa
from alembic import context, op


revision = "0047_role_checker_grant"
down_revision = "0046_repair_superadmin_grants"
branch_labels = None
depends_on = None


PERMISSION_KEY = "access.tenant_role_permission_mapping.approve"
ROLE_NAMES = ("admin", "organization-admin", "clinic-admin")


# Backfill the checker grant for the built-in tenant administrator roles.
def upgrade() -> None:
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names(schema=schema))
    if not {"tenant_roles", "tenant_role_grants"}.issubset(tables):
        return
    role_names = ", ".join(f":role_name_{index}" for index, _ in enumerate(ROLE_NAMES))
    role_ids = [
        row[0]
        for row in bind.execute(
            sa.text(
                f'''SELECT r.id FROM "{schema}".tenant_roles r
                    WHERE r.name IN ({role_names})
                      AND r.status <> 'archived' '''
            ),
            {f"role_name_{i}": name for i, name in enumerate(ROLE_NAMES)},
        ).fetchall()
    ]
    if not role_ids:
        return
    existing = {
        row[0]
        for row in bind.execute(
            sa.text(
                f'''SELECT role_id FROM "{schema}".tenant_role_grants
                    WHERE permission_key = :permission_key'''
            ),
            {"permission_key": PERMISSION_KEY},
        ).fetchall()
    }
    grants = [
        {"id": str(uuid4()), "role_id": role_id, "permission_key": PERMISSION_KEY}
        for role_id in role_ids if role_id not in existing
    ]
    if not grants:
        return
    bind.execute(
        sa.text(
            f'''INSERT INTO "{schema}".tenant_role_grants
                (id, role_id, permission_key, effect, scope, conditions,
                 created_at, updated_at, created_by, updated_by)
            VALUES
                (:id, :role_id, :permission_key, 'allow', 'Organization',
                 '{{}}'::json, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                 'tenant-role-checker-permission',
                 'tenant-role-checker-permission')
            ON CONFLICT (role_id, permission_key) DO NOTHING''',
        ),
        grants,
    )


# Keep authorization migrations forward-only so an approval grant is not removed accidentally.
def downgrade() -> None:
    raise RuntimeError("Use a reviewed forward migration")
