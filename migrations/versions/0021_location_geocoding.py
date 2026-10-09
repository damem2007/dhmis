"""Store editable location addresses and OpenStreetMap coordinates."""

import sqlalchemy as sa
from alembic import context, op


revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.add_column(
        "locations",
        sa.Column("address", sa.String(500), nullable=False, server_default=""),
        schema=schema,
    )
    op.add_column("locations", sa.Column("latitude", sa.Float(), nullable=True), schema=schema)
    op.add_column("locations", sa.Column("longitude", sa.Float(), nullable=True), schema=schema)
    op.add_column(
        "locations",
        sa.Column("osm_place_id", sa.String(120), nullable=False, server_default=""),
        schema=schema,
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
