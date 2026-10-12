"""Allow platform invitations to carry canonical role identifiers."""

from alembic import context, op
import sqlalchemy as sa


revision = "0026_platform_invite_role_length"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade():
    if context.config.attributes.get("schema") != "dhmis_control":
        return
    op.alter_column(
        "platform_invites",
        "role",
        existing_type=sa.String(length=30),
        type_=sa.String(length=160),
        schema="dhmis_control",
    )


def downgrade():
    if context.config.attributes.get("schema") != "dhmis_control":
        return
    op.alter_column(
        "platform_invites",
        "role",
        existing_type=sa.String(length=160),
        type_=sa.String(length=30),
        schema="dhmis_control",
    )
