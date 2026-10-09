"""Configure the default platform geocoding provider."""

import sqlalchemy as sa
from alembic import context, op


revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


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
                ('adapter-default-geocoding', '*', 'geocoding_provider', 'nominatim', true, 'migration', 'migration')
            ON CONFLICT (region, capability) DO NOTHING
            """
        )
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
