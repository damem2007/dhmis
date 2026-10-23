"""Store the operator-selected runtime mode for platform adapters."""

import sqlalchemy as sa
from alembic import context, op


revision = "0059_configurable_adapter_modes"
down_revision = "0058_appointment_widget"
branch_labels = None
depends_on = None


# Add configurable provider modes to control-plane adapter records.
def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return
    op.add_column(
        "platform_adapter_defaults",
        sa.Column("mode", sa.String(length=20), nullable=False, server_default="auto"),
        schema=schema,
    )
    op.add_column(
        "tenant_adapter_overrides",
        sa.Column("mode", sa.String(length=20), nullable=False, server_default="auto"),
        schema=schema,
    )


# Keep the migration catalogue forward-only.
def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
