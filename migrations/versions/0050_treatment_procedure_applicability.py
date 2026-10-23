"""Add catalogue applicability metadata used by treatment-plan procedure pickers.

The migration is forward-only and intentionally not executed by the application.
"""

import sqlalchemy as sa
from alembic import context, op


revision = "0050_treatment_applicability"
down_revision = "0049_chart_entry_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add tenant-scoped category, applicability, and surface metadata."""
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "treatment_catalogue_items" not in inspector.get_table_names(schema=schema):
        return
    columns = {column["name"] for column in inspector.get_columns("treatment_catalogue_items", schema=schema)}
    if "category" not in columns:
        op.add_column(
            "treatment_catalogue_items",
            sa.Column("category", sa.String(80), nullable=False, server_default=""),
            schema=schema,
        )
    if "applies_to" not in columns:
        op.add_column(
            "treatment_catalogue_items",
            sa.Column("applies_to", sa.String(30), nullable=False, server_default="whole_mouth"),
            schema=schema,
        )
    if "allowed_surfaces" not in columns:
        op.add_column(
            "treatment_catalogue_items",
            sa.Column("allowed_surfaces", sa.JSON(), nullable=False, server_default="[]"),
            schema=schema,
        )


def downgrade() -> None:
    """Keep the project's forward-only migration policy."""
    raise RuntimeError("Use a reviewed forward migration")
