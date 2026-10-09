"""Persist platform defaults, templates and platform invitations."""

import sqlalchemy as sa
from alembic import context, op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def record_columns():
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0012"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0012"),
    ]


def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return
    op.create_table(
        "platform_configuration",
        *record_columns(),
        sa.Column("default_visibility", sa.String(20), nullable=False, server_default="organization"),
        sa.Column("default_policy", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("communication_templates", sa.JSON(), nullable=False, server_default="{}"),
        schema=schema,
    )
    op.create_table(
        "platform_invites",
        *record_columns(),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("role", sa.String(30), nullable=False, server_default="platform_admin"),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        schema=schema,
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
