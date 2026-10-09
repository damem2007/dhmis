"""Use TomTom for address coordinates while maps remain provider-independent."""

import sqlalchemy as sa
from alembic import context, op


revision = "0024"
down_revision = "0023"
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
               SET provider_name = 'tomtom', updated_by = 'migration'
             WHERE capability = 'geocoding_provider'
               AND provider_name = 'postal-aware'
            """
        )
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
