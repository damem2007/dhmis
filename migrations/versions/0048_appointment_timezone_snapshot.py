"""Persist the clinic timezone used when an appointment was booked."""

import sqlalchemy as sa
from alembic import context, op


revision = "0048_appointment_tz_snapshot"
down_revision = "0047_role_checker_grant"
branch_labels = None
depends_on = None


# Add and backfill the appointment timezone for every tenant schema.
def upgrade() -> None:
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.add_column(
        "appointments",
        sa.Column("timezone", sa.String(60), nullable=True),
        schema=schema,
    )
    op.execute(
        sa.text(
            f'''UPDATE "{schema}".appointments AS appointment
                SET timezone = COALESCE(location.timezone, 'UTC')
                FROM "{schema}".locations AS location
                WHERE appointment.location_id = location.id
                  AND appointment.timezone IS NULL'''
        )
    )
    op.execute(
        sa.text(
            f'''UPDATE "{schema}".appointments
                SET timezone = 'UTC'
                WHERE timezone IS NULL'''
        )
    )
    op.alter_column(
        "appointments",
        "timezone",
        existing_type=sa.String(60),
        nullable=False,
        server_default="UTC",
        schema=schema,
    )


# Keep appointment history forward-only; timezone snapshots are audit data.
def downgrade() -> None:
    raise RuntimeError("Use a reviewed forward migration")
