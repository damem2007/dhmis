"""Use the postal-aware geocoding provider for platform address search."""

import sqlalchemy as sa
from alembic import context, op


revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return
    op.execute(
        sa.text(
            """
            UPDATE dhmis_control.platform_adapter_defaults
               SET provider_name = 'postal-aware', updated_by = 'migration'
             WHERE capability = 'geocoding_provider'
               AND provider_name = 'nominatim'
            """
        )
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
