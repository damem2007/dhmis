"""Phase 2 patient identity, portal, forms, documents, messaging, and CMS."""

import sqlalchemy as sa
from alembic import context, op

revision = "0003"
down_revision = "0002"
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
        op.add_column(
            "organizations",
            sa.Column("public_content", sa.JSON(), nullable=False, server_default="{}"),
            schema=schema,
        )
        return

    def foreign(table):
        return f"{schema}.{table}.id"

    op.create_table(
        "patient_users",
        *record_columns(),
        sa.Column("patient_id", sa.String(36), sa.ForeignKey(foreign("patients")), nullable=False, unique=True),
        sa.Column("email", sa.String(254), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(300), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="1"),
        schema=schema,
    )
    op.create_table(
        "patient_sessions",
        *record_columns(),
        sa.Column("user_id", sa.String(36), sa.ForeignKey(foreign("patient_users")), nullable=False),
        sa.Column("expires", sa.BigInteger(), nullable=False),
        sa.Column("last_active", sa.BigInteger(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema=schema,
    )
    op.create_table(
        "patient_invites",
        *record_columns(),
        sa.Column("patient_id", sa.String(36), sa.ForeignKey(foreign("patients")), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires", sa.BigInteger(), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema=schema,
    )
    op.create_table(
        "documents",
        *record_columns(),
        sa.Column("patient_id", sa.String(36), sa.ForeignKey(foreign("patients")), nullable=False),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(foreign("locations")), nullable=False),
        sa.Column("category", sa.String(30), nullable=False),
        sa.Column("filename", sa.String(220), nullable=False),
        sa.Column("mime_type", sa.String(120), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("comparison_group", sa.String(80), nullable=False, server_default=""),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        schema=schema,
    )
    op.create_table(
        "form_templates",
        *record_columns(),
        sa.Column("title", sa.String(180), nullable=False),
        sa.Column("version", sa.String(30), nullable=False),
        sa.Column("fields", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("title", "version"),
        schema=schema,
    )
    op.create_table(
        "form_submissions",
        *record_columns(),
        sa.Column("template_id", sa.String(36), sa.ForeignKey(foreign("form_templates")), nullable=False),
        sa.Column("patient_id", sa.String(36), sa.ForeignKey(foreign("patients")), nullable=False),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(foreign("locations")), nullable=False),
        sa.Column("template_version", sa.String(30), nullable=False),
        sa.Column("responses", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="completed"),
        sa.Column("certificate", sa.JSON(), nullable=False, server_default="{}"),
        schema=schema,
    )
    op.create_table(
        "message_threads",
        *record_columns(),
        sa.Column("patient_id", sa.String(36), sa.ForeignKey(foreign("patients")), nullable=False),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(foreign("locations")), nullable=False),
        sa.Column("subject", sa.String(180), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        schema=schema,
    )
    op.create_table(
        "messages",
        *record_columns(),
        sa.Column("thread_id", sa.String(36), sa.ForeignKey(foreign("message_threads")), nullable=False),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(foreign("locations")), nullable=False),
        sa.Column("sender_type", sa.String(20), nullable=False),
        sa.Column("sender_id", sa.String(36), nullable=False),
        sa.Column("body_cipher", sa.Text(), nullable=False),
        schema=schema,
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
