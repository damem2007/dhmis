"""Add forward-only chart-entry status and govern missing-tooth returns.

Missing-tooth declarations are retained as clinical history. Returning one
updates its status and is routed through maker-checker; no chart row is
deleted. This migration is intentionally not executed by the application.
"""

from uuid import uuid4

import sqlalchemy as sa
from alembic import context, op

revision = "0049_chart_entry_status"
down_revision = "0048_appointment_tz_snapshot"
branch_labels = None
depends_on = None


# Add status columns and seed the tenant maker-checker rule.
def upgrade() -> None:
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names(schema=schema))
    if "chart_entries" in tables:
        columns = {column["name"] for column in sa.inspect(bind).get_columns("chart_entries", schema=schema)}
        if "status" not in columns:
            op.add_column(
                "chart_entries",
                sa.Column("status", sa.String(20), nullable=False, server_default="active"),
                schema=schema,
            )
        if "status_reason" not in columns:
            op.add_column(
                "chart_entries",
                sa.Column("status_reason", sa.String(1000), nullable=False, server_default=""),
                schema=schema,
            )
        if "status_changed_at" not in columns:
            op.add_column(
                "chart_entries",
                sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True),
                schema=schema,
            )
        if "status_changed_by" not in columns:
            op.add_column(
                "chart_entries",
                sa.Column("status_changed_by", sa.String(100), nullable=True),
                schema=schema,
            )

    # Existing tenants receive the new rule without replacing their other
    # custom rules. Choose a free priority if the configured baseline number
    # is already occupied.
    if "tenant_four_eyes_rules" in tables:
        rule_id = "missing-tooth-return"
        exists = bind.execute(
            sa.text(
                f'''SELECT 1 FROM "{schema}".tenant_four_eyes_rules
                    WHERE id = :rule_id'''
            ),
            {"rule_id": rule_id},
        ).first()
        if exists is None:
            priorities = {
                row[0]
                for row in bind.execute(
                    sa.text(f'''SELECT priority FROM "{schema}".tenant_four_eyes_rules''')
                ).fetchall()
            }
            priority = 200
            while priority in priorities:
                priority += 1
            bind.execute(
                sa.text(
                    f'''INSERT INTO "{schema}".tenant_four_eyes_rules
                        (id, name, scope, priority, patterns, created_at, updated_at,
                         created_by, updated_by)
                        VALUES (:id, :name, :scope, :priority, CAST(:patterns AS json),
                                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, :actor, :actor)'''
                ),
                {
                    "id": rule_id,
                    "name": "Missing tooth return",
                    "scope": "Tenant",
                    "priority": priority,
                    "patterns": '["clinical.odontogram.return_missing"]',
                    "actor": "missing-tooth-return-migration",
                },
            )

    # The protected setup role must be able to initiate the workflow. The
    # separate return_missing permission remains default-deny for all other
    # roles until an administrator grants it explicitly.
    if {"tenant_roles", "tenant_role_grants"}.issubset(tables):
        role_id = bind.execute(
            sa.text(
                f'''SELECT id FROM "{schema}".tenant_roles
                    WHERE id = 'tenant-super-admin' OR name = 'Tenant Super Admin'
                    LIMIT 1'''
            )
        ).scalar()
        if role_id:
            grant_exists = bind.execute(
                sa.text(
                    f'''SELECT 1 FROM "{schema}".tenant_role_grants
                        WHERE role_id = :role_id
                          AND permission_key = :permission_key'''
                ),
                {"role_id": role_id, "permission_key": "clinical.odontogram.return_missing"},
            ).first()
            if grant_exists is None:
                bind.execute(
                    sa.text(
                        f'''INSERT INTO "{schema}".tenant_role_grants
                            (id, role_id, permission_key, effect, scope, conditions,
                             created_at, updated_at, created_by, updated_by)
                            VALUES (:id, :role_id, :permission_key, 'allow', 'Organization',
                                    CAST(:conditions AS json), CURRENT_TIMESTAMP,
                                    CURRENT_TIMESTAMP, :actor, :actor)'''
                    ),
                    {
                        "id": str(uuid4()),
                        "role_id": role_id,
                        "permission_key": "clinical.odontogram.return_missing",
                        "conditions": "{}",
                        "actor": "missing-tooth-return-migration",
                    },
                )


# Keep chart status history forward-only.
def downgrade() -> None:
    raise RuntimeError("Use a reviewed forward migration")
