"""Store an optional phone number for every tenant location."""

import sqlalchemy as sa
from alembic import context, op

revision = "0038_location_phone"
down_revision = "0037_location_lifecycle"
branch_labels = None
depends_on = None


def upgrade():
    """Add the location phone column to the template and every tenant schema."""
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("locations", schema=schema)}
    if "phone" not in columns:
        op.add_column(
            "locations",
            sa.Column("phone", sa.String(length=40), nullable=False, server_default=""),
            schema=schema,
        )
    op.alter_column("locations", "phone", server_default=None, schema=schema)


def downgrade():
    """Keep the forward-only migration policy used by tenant schemas."""
    raise RuntimeError("Use a reviewed forward migration")
