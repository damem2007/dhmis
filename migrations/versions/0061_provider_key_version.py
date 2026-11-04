"""Separate provider envelope versions from tenant DEK versions."""

import sqlalchemy as sa
from alembic import context, op

revision = "0061_provider_key_version"
down_revision = "0060_tenant_key_management"
branch_labels = None
depends_on = None


def upgrade():
    if context.config.attributes["schema"] != "dhmis_control":
        return
    op.add_column(
        "organization_keys",
        sa.Column("provider_version", sa.String(80), nullable=True),
        schema="dhmis_control",
    )
    # Migration 0060 used ``key_version`` for both values. Preserve that
    # envelope version before separating tenant DEK and provider versions.
    op.execute(
        "UPDATE dhmis_control.organization_keys "
        "SET provider_version = key_version WHERE provider_version IS NULL"
    )
    op.alter_column(
        "organization_keys",
        "provider_version",
        existing_type=sa.String(80),
        nullable=False,
        server_default="v1",
        schema="dhmis_control",
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
