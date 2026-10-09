"""Ensure notification governance columns exist after the 0017 rollout.

Some development databases recorded 0017 before its governance columns were
included in the migration file. This forward-only repair is additive and
idempotent: it restores the columns required by the RBAC notification query
without changing existing authorization assignments or request data.
"""

import sqlalchemy as sa
from alembic import context, op


revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    prefix = "platform" if schema == "dhmis_control" else "tenant"
    request_table = f"{prefix}_change_requests"

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns(request_table, schema=schema)}
    if "governing_rule_id" not in columns:
        op.add_column(
            request_table,
            sa.Column("governing_rule_id", sa.String(80), nullable=True),
            schema=schema,
        )
    if "approval_context" not in columns:
        op.add_column(
            request_table,
            sa.Column("approval_context", sa.JSON(), nullable=False, server_default="{}"),
            schema=schema,
        )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
