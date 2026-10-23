"""Persist tenant-wide clinical chart display preferences."""

import sqlalchemy as sa
from alembic import context, op

revision = "0042_clinical_chart_settings"
down_revision = "0041_code_library_source_content"
branch_labels = None
depends_on = None


def upgrade():
    """Add the configuration column to the reusable tenant template and tenants."""
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "tenant_settings" not in inspector.get_table_names(schema=schema):
        return
    columns = {column["name"] for column in inspector.get_columns("tenant_settings", schema=schema)}
    if "clinical_chart" not in columns:
        op.add_column(
            "tenant_settings",
            sa.Column("clinical_chart", sa.JSON(), nullable=False, server_default="{}"),
            schema=schema,
        )


def downgrade():
    """Keep the project's forward-only migration policy."""
    raise RuntimeError("Use a reviewed forward migration")
