"""Add control-plane delivery queue and password-reset challenges."""

import sqlalchemy as sa
from alembic import context, op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def record_columns():
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0013"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0013"),
    ]


def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return
    op.create_table(
        "platform_outbox_messages",
        *record_columns(),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("idempotency_key", sa.String(120), nullable=False, unique=True),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("result", sa.JSON(), nullable=False, server_default="{}"),
        schema=schema,
    )
    op.create_index(
        "ix_platform_outbox_delivery",
        "platform_outbox_messages",
        ["status", "due_at"],
        schema=schema,
    )
    op.create_table(
        "platform_password_reset_challenges",
        *record_columns(),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires", sa.BigInteger(), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("initiated_by", sa.String(100), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        schema=schema,
    )
    op.create_index(
        "ix_platform_password_reset_user",
        "platform_password_reset_challenges",
        ["user_id", "used"],
        schema=schema,
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
