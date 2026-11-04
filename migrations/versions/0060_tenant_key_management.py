"""Add control-plane storage for wrapped tenant encryption keys."""

import sqlalchemy as sa
from alembic import context, op


revision = "0060_tenant_key_management"
down_revision = "0059_configurable_adapter_modes"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return
    op.create_table(
        "organization_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("provider", sa.String(40), nullable=False, server_default="local"),
        sa.Column("key_version", sa.String(80), nullable=False, server_default="v1"),
        sa.Column("wrapped_key", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("recovery_metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.ForeignKeyConstraint(["organization_id"], [f"{schema}.organizations.id"]),
        sa.UniqueConstraint("organization_id", "key_version", name="uq_organization_keys_version"),
        schema=schema,
    )
    op.create_index(
        "ix_organization_keys_organization_id",
        "organization_keys",
        ["organization_id"],
        schema=schema,
    )
    op.create_index(
        "ix_organization_keys_status",
        "organization_keys",
        ["status"],
        schema=schema,
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
