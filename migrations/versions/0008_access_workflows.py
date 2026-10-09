"""Staff invitation lifecycle, profile, and local password-reset workflows."""

import sqlalchemy as sa
from alembic import context, op

revision = "0008"
down_revision = "0007"
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
    op.add_column(
        "staff_users",
        sa.Column("photo_url", sa.String(500), nullable=False, server_default=""),
        schema=schema,
    )
    op.add_column(
        "staff_invites",
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        schema=schema,
    )
    op.add_column(
        "staff_invites",
        sa.Column("resend_count", sa.Integer(), nullable=False, server_default="0"),
        schema=schema,
    )
    op.add_column(
        "staff_invites", sa.Column("supersedes_id", sa.String(36), nullable=True), schema=schema
    )
    op.add_column(
        "staff_invites",
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        schema=schema,
    )
    op.add_column(
        "staff_invites",
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        schema=schema,
    )
    op.execute(
        sa.text(
            f"""
            UPDATE "{schema}".staff_invites
            SET status = CASE
                WHEN used THEN 'accepted'
                WHEN expires < extract(epoch from now())::bigint THEN 'expired'
                ELSE 'pending'
            END
            """
        )
    )
    op.create_table(
        "password_reset_challenges",
        *record_columns(),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey(f"{schema}.staff_users.id"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires", sa.BigInteger(), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("initiated_by", sa.String(100), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False, server_default=""),
        schema=schema,
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
