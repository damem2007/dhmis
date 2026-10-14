"""Add soft lifecycle state to tenant locations."""

import sqlalchemy as sa
from alembic import context, op

revision = "0037_location_lifecycle"
down_revision = "0036_support_ticket_lifecycle"
branch_labels = None
depends_on = None


# Run the upgrade entry point for this module.
def upgrade():
    schema = context.config.attributes["schema"]
    # The same migration chain is run against the shared template and every
    # tenant schema.  Only the control-plane schema has no locations table.
    if schema == "dhmis_control":
        return
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("locations", schema=schema)}
    if "active" not in columns:
        op.add_column("locations", sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()), schema=schema)
    indexes = {index["name"] for index in inspector.get_indexes("locations", schema=schema)}
    if "ix_locations_active" not in indexes:
        op.create_index("ix_locations_active", "locations", ["active"], schema=schema)
    op.alter_column("locations", "active", server_default=None, schema=schema)


# Run the downgrade entry point for this module.
def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
