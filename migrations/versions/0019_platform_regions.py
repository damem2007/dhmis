"""Add the platform-owned CA/US Region Registry."""

import sqlalchemy as sa
from alembic import context, op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return
    op.create_table(
        "platform_regions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0019"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0019"),
        sa.Column("code", sa.String(2), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("jurisdiction_provider", sa.String(80), nullable=False),
        sa.Column("claims_route", sa.String(120), nullable=False),
        sa.Column("locale", sa.String(30), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("tax_defaults", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("residency_defaults", sa.JSON(), nullable=False, server_default="{}"),
        schema=schema,
    )
    op.create_index("ix_platform_regions_code", "platform_regions", ["code"], schema=schema)


def downgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        op.drop_table("platform_regions", schema=schema)
