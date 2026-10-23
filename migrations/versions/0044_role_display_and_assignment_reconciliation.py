"""Make role labels informational and reconcile onboarding role projections."""

import sqlalchemy as sa
from alembic import context, op


revision = "0044_role_display_reconcile"
down_revision = "0043_role_reference_columns"
branch_labels = None
depends_on = None


def _alter_role_display(schema: str, table: str, role_table: str) -> None:
    """Widen the compatibility label and derive it from the referenced role."""

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if table not in inspector.get_table_names(schema=schema):
        return
    columns = {column["name"] for column in inspector.get_columns(table, schema=schema)}
    if "role" not in columns or "role_id" not in columns:
        return
    op.alter_column(
        table,
        "role",
        existing_type=sa.String(length=30),
        type_=sa.String(length=160),
        existing_nullable=False,
        schema=schema,
    )
    op.execute(
        sa.text(
            f'''
            UPDATE "{schema}"."{table}" u
            SET role_id = r.id
            FROM "{schema}"."{role_table}" r
            WHERE (u.role = r.id OR lower(u.role) = lower(r.name))
              AND r.status <> 'archived'
            '''
        )
    )
    op.execute(
        sa.text(
            f'''
            UPDATE "{schema}"."{table}" u
            SET role = r.name
            FROM "{schema}"."{role_table}" r
            WHERE u.role_id = r.id
            '''
        )
    )


def _reconcile_onboarding_super_admin(schema: str) -> None:
    """Keep the protected setup role and remove its generated admin duplicate."""

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names(schema=schema))
    if not {"staff_users", "tenant_role_assignments", "tenant_roles"}.issubset(tables):
        return
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


def upgrade() -> None:
    """Apply the display-label and onboarding reconciliation to each schema."""

    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        _alter_role_display(schema, "platform_users", "platform_roles")
        return
    _alter_role_display(schema, "staff_users", "tenant_roles")
    _reconcile_onboarding_super_admin(schema)


def downgrade() -> None:
    """Keep the project's forward-only migration policy."""

    raise RuntimeError("Use a reviewed forward migration")
