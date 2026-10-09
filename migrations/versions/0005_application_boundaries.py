"""Tenant routing, platform identity, and patient verification boundaries."""

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
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
        op.add_column("organizations", sa.Column("slug", sa.String(80), nullable=True), schema=schema)
        op.add_column(
            "organizations", sa.Column("domains", sa.JSON(), nullable=False, server_default="[]"), schema=schema
        )
        for name in ("front_office_enabled", "booking_enabled", "patient_portal_enabled"):
            op.add_column(
                "organizations",
                sa.Column(name, sa.Boolean(), nullable=False, server_default=sa.true()),
                schema=schema,
            )
        op.execute(
            sa.text(
                'UPDATE dhmis_control.organizations SET slug = '
                "'tenant-' || left(replace(id, '-', ''), 8) WHERE slug IS NULL"
            )
        )
        op.alter_column("organizations", "slug", nullable=False, schema=schema)
        op.create_unique_constraint("organizations_slug_key", "organizations", ["slug"], schema=schema)
        op.create_table(
            "platform_users",
            *record_columns(),
            sa.Column("email", sa.String(254), nullable=False, unique=True),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("role", sa.String(30), nullable=False, server_default="platform_admin"),
            sa.Column("password_hash", sa.String(300), nullable=False),
            sa.Column("mfa_secret", sa.String(1000), nullable=False, server_default=""),
            sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("mfa_counter", sa.BigInteger(), nullable=False, server_default="-1"),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("token_version", sa.Integer(), nullable=False, server_default="1"),
            schema=schema,
        )
        op.create_table(
            "platform_challenges",
            *record_columns(),
            sa.Column("user_id", sa.String(36), nullable=False),
            sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("expires", sa.BigInteger(), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
            schema=schema,
        )
        op.create_table(
            "platform_sessions",
            *record_columns(),
            sa.Column("user_id", sa.String(36), nullable=False),
            sa.Column("expires", sa.BigInteger(), nullable=False),
            sa.Column("last_active", sa.BigInteger(), nullable=False),
            sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
            schema=schema,
        )
        op.create_table(
            "platform_audit_events",
            *record_columns(),
            sa.Column("actor_id", sa.String(100), nullable=False),
            sa.Column("action", sa.String(100), nullable=False),
            sa.Column("organization_id", sa.String(36), nullable=True),
            sa.Column("reason", sa.String(1000), nullable=False, server_default=""),
            sa.Column("details", postgresql.JSONB(), nullable=False, server_default="{}"),
            schema=schema,
        )
        return

    def foreign(table):
        return f"{schema}.{table}.id"

    op.create_table(
        "patient_verification_challenges",
        *record_columns(),
        sa.Column("patient_id", sa.String(36), sa.ForeignKey(foreign("patients")), nullable=False),
        sa.Column("appointment_id", sa.String(36), sa.ForeignKey(foreign("appointments")), nullable=True),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("expires", sa.BigInteger(), nullable=False),
        sa.Column("resend_after", sa.BigInteger(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema=schema,
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
