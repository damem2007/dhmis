"""Configure the storefront map provider."""

import sqlalchemy as sa
from alembic import context, op


revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


# Run the upgrade entry point for this module.
def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return
    op.execute(
        sa.text(
            """
            INSERT INTO dhmis_control.platform_adapter_defaults
                (id, region, capability, provider_name, active, created_by, updated_by)
            VALUES
                ('adapter-default-map', '*', 'map_provider', 'openstreetmap', true, 'migration', 'migration')
            ON CONFLICT (region, capability) DO NOTHING
            """
        )
    )


# Run the downgrade entry point for this module.
def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
