"""Add staff suspension and archive state.

Revision ID: 0027_staff_lifecycle
Revises: 0026_platform_invite_role_length
"""

from alembic import context, op
import sqlalchemy as sa


revision = "0027_staff_lifecycle"
down_revision = "0026_platform_invite_role_length"
branch_labels = None
depends_on = None


# Run the upgrade entry point for this module.
def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.add_column("staff_users", sa.Column("suspended_until", sa.DateTime(timezone=True), nullable=True), schema=schema)
    op.add_column("staff_users", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True), schema=schema)


# Run the downgrade entry point for this module.
def downgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.drop_column("staff_users", "archived_at", schema=schema)
    op.drop_column("staff_users", "suspended_until", schema=schema)
