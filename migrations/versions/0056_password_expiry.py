"""Add password timestamps and platform password policy storage."""

import sqlalchemy as sa
from alembic import context, op


revision = "0056_password_expiry"
down_revision = "0055_quick_chart_conditions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    schema = context.config.attributes["schema"]
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if schema == "dhmis_control":
        if "platform_users" in inspector.get_table_names(schema=schema):
            columns = {column["name"] for column in inspector.get_columns("platform_users", schema=schema)}
            if "password_changed_at" not in columns:
                op.add_column("platform_users", sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True), schema=schema)
                op.execute(sa.text(f'UPDATE "{schema}".platform_users SET password_changed_at = updated_at WHERE password_changed_at IS NULL'))
        if "platform_configuration" in inspector.get_table_names(schema=schema):
            columns = {column["name"] for column in inspector.get_columns("platform_configuration", schema=schema)}
            if "password_policy" not in columns:
                op.add_column("platform_configuration", sa.Column("password_policy", sa.JSON(), nullable=False, server_default="{}"), schema=schema)
        return
    if "staff_users" in inspector.get_table_names(schema=schema):
        columns = {column["name"] for column in inspector.get_columns("staff_users", schema=schema)}
        if "password_changed_at" not in columns:
            op.add_column("staff_users", sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True), schema=schema)
            op.execute(sa.text(f'UPDATE "{schema}".staff_users SET password_changed_at = updated_at WHERE password_changed_at IS NULL'))


def downgrade() -> None:
    raise RuntimeError("Use a reviewed forward migration")
