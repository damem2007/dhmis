"""Store procedure fees independently from optional Services & fees links."""

import sqlalchemy as sa
from alembic import context, op


revision = "0053_catalogue_procedure_fees"
down_revision = "0052_catalogue_options"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add a non-negative procedure surcharge to tenant catalogue items."""
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "treatment_catalogue_items" not in inspector.get_table_names(schema=schema):
        return
    columns = {column["name"] for column in inspector.get_columns("treatment_catalogue_items", schema=schema)}
    if "fee_cents" not in columns:
        op.add_column(
            "treatment_catalogue_items",
            sa.Column("fee_cents", sa.Integer(), nullable=False, server_default="0"),
            schema=schema,
        )


def downgrade() -> None:
    raise RuntimeError("Use a reviewed forward migration")
