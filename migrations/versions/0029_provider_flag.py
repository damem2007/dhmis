"""Persist the explicit patient-facing provider flag for tenant staff."""

from alembic import context, op
import sqlalchemy as sa


revision = "0029_provider_flag"
down_revision = "0028_tenant_defaults"
branch_labels = None
depends_on = None


# Run the upgrade entry point for this module.
def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.add_column(
        "staff_users",
        sa.Column("is_provider", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema=schema,
    )
    op.add_column(
        "staff_invites",
        sa.Column("is_provider", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema=schema,
    )


# Run the downgrade entry point for this module.
def downgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.drop_column("staff_invites", "is_provider", schema=schema)
    op.drop_column("staff_users", "is_provider", schema=schema)
