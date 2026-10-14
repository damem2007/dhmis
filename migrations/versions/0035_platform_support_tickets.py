"""Create the Support-owned platform ticket source used by Billing."""

import sqlalchemy as sa
from alembic import context, op

revision = "0035_platform_support_tickets"
down_revision = "0034_default_role_permissions"
branch_labels = None
depends_on = None


# Handle record columns for this module.
def record_columns():
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
    ]


# Run the upgrade entry point for this module.
def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return
    op.create_table(
        "platform_support_tickets",
        *record_columns(),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("source", sa.String(40), nullable=False, server_default="support"),
        sa.Column("subscription_id", sa.String(36), nullable=True),
        sa.Column("category", sa.String(80), nullable=False, server_default="General"),
        sa.Column("priority", sa.String(20), nullable=False, server_default="normal"),
        sa.Column("subject", sa.String(240), nullable=False),
        sa.Column("description", sa.String(4000), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column("context", sa.JSON(), nullable=False, server_default="{}"),
        sa.CheckConstraint("priority IN ('low', 'normal', 'high', 'urgent')", name="ck_platform_support_ticket_priority"),
        schema=schema,
    )
    op.create_index(
        "ix_platform_support_tickets_organization_id",
        "platform_support_tickets",
        ["organization_id"],
        schema=schema,
    )
    op.create_index(
        "ix_platform_support_tickets_status",
        "platform_support_tickets",
        ["status"],
        schema=schema,
    )


# Run the downgrade entry point for this module.
def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
