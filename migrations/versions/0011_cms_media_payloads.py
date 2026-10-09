"""Persist tenant CMS media bytes with revision-scoped integrity metadata."""

import sqlalchemy as sa
from alembic import context, op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.add_column("cms_media_assets", sa.Column("content", sa.LargeBinary(), nullable=True), schema=schema)
    op.add_column(
        "cms_media_assets",
        sa.Column("content_sha256", sa.String(64), nullable=False, server_default=""),
        schema=schema,
    )
    op.add_column(
        "cms_media_assets",
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        schema=schema,
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
