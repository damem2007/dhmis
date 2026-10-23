"""Add role-table references while retaining legacy role compatibility fields."""

import sqlalchemy as sa
from alembic import context, op

revision = "0043_role_reference_columns"
down_revision = "0042_clinical_chart_settings"
branch_labels = None
depends_on = None


def _add_role_reference(schema: str, table: str, role_table: str, constraint: str) -> None:
    """Add and backfill a nullable role-table reference in one logical schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if table not in inspector.get_table_names(schema=schema):
        return
    columns = {column["name"] for column in inspector.get_columns(table, schema=schema)}
    if "role_id" not in columns:
        op.add_column(
            table,
            sa.Column("role_id", sa.String(36), nullable=True),
            schema=schema,
        )

    # Canonical assignments take precedence over the old compatibility label.
    # The fallback keeps old tenants readable when assignments were not yet
    # reconciled during an interrupted upgrade.
    if table == "platform_users":
        op.execute(
            sa.text(
                f'''
                WITH ranked AS (
                    SELECT a.user_id, a.role_id,
                           row_number() OVER (
                               PARTITION BY a.user_id
                               ORDER BY (a.role_id = 'platform-super-admin') DESC,
                                        a.created_at, a.id
                           ) AS position
                    FROM "{schema}".platform_role_assignments a
                )
                UPDATE "{schema}".platform_users u
                SET role_id = ranked.role_id
                FROM ranked
                WHERE u.role_id IS NULL
                  AND ranked.position = 1
                  AND ranked.user_id = u.id
                '''
            )
        )
        op.execute(
            sa.text(
                f'''
                UPDATE "{schema}".platform_users u
                SET role_id = r.id
                FROM "{schema}".platform_roles r
                WHERE u.role_id IS NULL
                  AND (
                      u.role = r.id
                      OR lower(u.role) = lower(r.name)
                      OR (u.role = 'platform_admin' AND r.id = 'platform-super-admin')
                  )
                '''
            )
        )
    else:
        op.execute(
            sa.text(
                f'''
                WITH ranked AS (
                    SELECT a.user_id, a.role_id,
                           row_number() OVER (
                               PARTITION BY a.user_id
                               ORDER BY (a.role_id = 'tenant-super-admin') DESC,
                                        (a.level = 'Organization') DESC,
                                        a.created_at, a.id
                           ) AS position
                    FROM "{schema}".tenant_role_assignments a
                )
                UPDATE "{schema}".staff_users u
                SET role_id = ranked.role_id
                FROM ranked
                WHERE u.role_id IS NULL
                  AND ranked.position = 1
                  AND ranked.user_id = u.id
                '''
            )
        )
        op.execute(
            sa.text(
                f'''
                UPDATE "{schema}".staff_users u
                SET role_id = r.id
                FROM "{schema}".tenant_roles r
                WHERE u.role_id IS NULL
                  AND (
                      u.role = r.id
                      OR lower(u.role) = lower(r.name)
                  )
                '''
            )
        )

    foreign_keys = {
        item["name"] for item in inspector.get_foreign_keys(table, schema=schema)
    }
    if constraint not in foreign_keys:
        op.create_foreign_key(
            constraint,
            table,
            role_table,
            ["role_id"],
            ["id"],
            source_schema=schema,
            referent_schema=schema,
        )
    if "role_id" not in {
        index["name"] for index in inspector.get_indexes(table, schema=schema)
    }:
        op.create_index(f"ix_{table}_role_id", table, ["role_id"], schema=schema)


def upgrade():
    """Reference the role tables for control-plane and tenant users."""
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        _add_role_reference(
            schema,
            "platform_users",
            "platform_roles",
            "fk_platform_users_role_id",
        )
    else:
        _add_role_reference(
            schema,
            "staff_users",
            "tenant_roles",
            "fk_staff_users_role_id",
        )


def downgrade():
    """Keep the project's forward-only migration policy."""
    raise RuntimeError("Use a reviewed forward migration")
