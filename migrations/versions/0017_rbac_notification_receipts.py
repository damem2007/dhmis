"""Persist read state for maker-checker decision notifications."""

import sqlalchemy as sa
from alembic import context, op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    prefix = "platform" if schema == "dhmis_control" else "tenant"
    request_table = f"{prefix}_change_requests"
    table = f"{prefix}_change_notification_receipts"
    op.add_column(request_table, sa.Column("governing_rule_id", sa.String(80), nullable=True), schema=schema)
    op.add_column(request_table, sa.Column("approval_context", sa.JSON(), nullable=False, server_default="{}"), schema=schema)
    op.create_table(
        table,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0017"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0017"),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("request_id", sa.String(36), sa.ForeignKey(f"{schema}.{request_table}.id"), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        schema=schema,
    )
    op.create_index(f"ix_{table}_user_id", table, ["user_id"], schema=schema)
    op.create_index(
        f"uq_{prefix}_change_notification_receipt",
        table,
        ["user_id", "request_id"],
        unique=True,
        schema=schema,
    )


def downgrade():
    schema = context.config.attributes["schema"]
    prefix = "platform" if schema == "dhmis_control" else "tenant"
    op.drop_table(f"{prefix}_change_notification_receipts", schema=schema)
    op.drop_column(f"{prefix}_change_requests", "approval_context", schema=schema)
    op.drop_column(f"{prefix}_change_requests", "governing_rule_id", schema=schema)
