"""Persist deduplicated analytics Action Centre state."""

import sqlalchemy as sa
from alembic import context, op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.create_table(
        "analytics_action_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("dedupe_key", sa.String(180), nullable=False, unique=True),
        sa.Column("category", sa.String(60), nullable=False),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("detail", sa.String(1000), nullable=False, server_default=""),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column("role_scopes", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("location_id", sa.String(36), nullable=True),
        sa.Column("provider_id", sa.String(36), nullable=True),
        sa.Column("patient_id", sa.String(36), nullable=True),
        sa.Column("target", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=False),
        schema=schema,
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
