"""Seed the clinic service catalogue used by billing and the public site."""

import sqlalchemy as sa
from alembic import context, op

from app.billing.defaults import DEFAULT_SERVICES


revision = "0030_default_services"
down_revision = "0029_provider_flag"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    for index, (code, name, description, fee_cents) in enumerate(DEFAULT_SERVICES, start=1):
        op.execute(
            sa.text(
                f"""
                INSERT INTO "{schema}".services
                    (id, code, name, fee_cents, description, created_at, updated_at, created_by, updated_by)
                VALUES (:id, :code, :name, :fee_cents, :description, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'tenant-defaults', 'tenant-defaults')
                ON CONFLICT (code) DO NOTHING
                """
            ).bindparams(
                id=f"default-service-{index:02d}",
                code=code,
                name=name,
                fee_cents=fee_cents,
                description=description,
            )
        )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
