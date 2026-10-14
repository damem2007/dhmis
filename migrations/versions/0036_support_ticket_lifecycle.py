"""Add assignment, resolution and closure fields to Support tickets."""

import sqlalchemy as sa
from alembic import context, op

revision = "0036_support_ticket_lifecycle"
down_revision = "0035_platform_support_tickets"
branch_labels = None
depends_on = None


# Run the upgrade entry point for this module.
def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return
    op.add_column("platform_support_tickets", sa.Column("assignee_id", sa.String(36), nullable=True), schema=schema)
    op.add_column("platform_support_tickets", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True), schema=schema)
    op.add_column("platform_support_tickets", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True), schema=schema)
    op.add_column("platform_support_tickets", sa.Column("resolution_code", sa.String(60), nullable=True), schema=schema)
    op.add_column("platform_support_tickets", sa.Column("resolution_note", sa.String(2000), nullable=True), schema=schema)
    op.create_index("ix_platform_support_tickets_assignee_id", "platform_support_tickets", ["assignee_id"], schema=schema)


# Run the downgrade entry point for this module.
def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
