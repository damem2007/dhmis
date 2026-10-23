"""Add tenant-scoped treatment catalogue type and category options."""

import sqlalchemy as sa
from alembic import context, op


revision = "0052_catalogue_options"
down_revision = "0051_superadmin_assignment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the tenant-owned type/category option table."""
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    bind = op.get_bind()
    if "treatment_catalogue_options" in sa.inspect(bind).get_table_names(schema=schema):
        return
    op.create_table(
        "treatment_catalogue_options",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("option_type", sa.String(20), nullable=False),
        sa.Column("item_type", sa.String(30), nullable=False),
        sa.Column("value", sa.String(80), nullable=False),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("option_type", "item_type", "value", name="uq_treatment_catalogue_option_value"),
        schema=schema,
    )


def downgrade() -> None:
    """Keep the project's forward-only migration policy."""
    raise RuntimeError("Use a reviewed forward migration")
