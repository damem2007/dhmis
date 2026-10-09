"""Tenant-owned CMS revisions, media evidence, and publication pointers."""

import sqlalchemy as sa
from alembic import context, op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def record_columns():
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
    ]


def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.create_table(
        "cms_revisions",
        *record_columns(),
        sa.Column("revision_number", sa.Integer(), nullable=False, unique=True),
        sa.Column("status", sa.String(24), nullable=False, server_default="draft"),
        sa.Column("base_revision_id", sa.String(36), nullable=True),
        sa.Column("content", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("applicability", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("validation", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("policy_versions", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("published_by", sa.String(100), nullable=False, server_default=""),
        sa.Column("publication_key", sa.String(100), nullable=True, unique=True),
        schema=schema,
    )
    op.create_table(
        "cms_publication_pointers",
        *record_columns(),
        sa.Column("scope_key", sa.String(100), nullable=False, unique=True),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(f"{schema}.locations.id"), nullable=True),
        sa.Column("revision_id", sa.String(36), sa.ForeignKey(f"{schema}.cms_revisions.id"), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        schema=schema,
    )
    op.create_table(
        "cms_media_assets",
        *record_columns(),
        sa.Column("revision_id", sa.String(36), sa.ForeignKey(f"{schema}.cms_revisions.id"), nullable=False),
        sa.Column("asset_key", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("file_name", sa.String(220), nullable=False, server_default=""),
        sa.Column("file_url", sa.String(500), nullable=False, server_default=""),
        sa.Column("mime_type", sa.String(120), nullable=False, server_default=""),
        sa.Column("alt_text", sa.String(300), nullable=False, server_default=""),
        sa.Column("consent", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("visible", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("revision_id", "asset_key"),
        schema=schema,
    )
    op.create_index(
        "ix_cms_revisions_status_number",
        "cms_revisions",
        ["status", "revision_number"],
        schema=schema,
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
