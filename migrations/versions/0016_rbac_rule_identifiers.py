"""Preserve approved governance rule identifiers without truncation."""

import sqlalchemy as sa
from alembic import context, op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    prefix = "platform" if schema == "dhmis_control" else "tenant"
    for suffix in ("four_eyes_rules", "sod_rules"):
        op.alter_column(
            f"{prefix}_{suffix}",
            "id",
            type_=sa.String(80),
            existing_type=sa.String(36),
            schema=schema,
        )


def downgrade():
    schema = context.config.attributes["schema"]
    prefix = "platform" if schema == "dhmis_control" else "tenant"
    for suffix in ("four_eyes_rules", "sod_rules"):
        op.alter_column(
            f"{prefix}_{suffix}",
            "id",
            type_=sa.String(36),
            existing_type=sa.String(80),
            schema=schema,
        )
