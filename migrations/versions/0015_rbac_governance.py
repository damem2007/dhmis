"""Add maker-checker policy, request, decision, rule, and history persistence."""

import sqlalchemy as sa
from alembic import context, op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def record_columns(default="migration-0015"):
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default=default),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default=default),
    ]


def create_governance(schema: str, prefix: str):
    request_table = f"{prefix}_change_requests"
    decision_table = f"{prefix}_change_decisions"
    op.create_table(
        request_table,
        *record_columns(),
        sa.Column("domain", sa.String(20), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("maker_id", sa.String(36), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("patch", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("risk", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("affected_users", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("required_approvals", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("break_glass", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("role_id", sa.String(36), nullable=True),
        sa.Column("role_version", sa.Integer(), nullable=True),
        sa.Column("runtime_permission_key", sa.String(180), nullable=True),
        sa.Column("runtime_payload", sa.JSON(), nullable=False, server_default="{}"),
        schema=schema,
    )
    op.create_index(
        f"ix_{prefix}_change_request_status_expiry",
        request_table,
        ["status", "expires_at"],
        schema=schema,
    )
    op.create_index(
        f"ix_{request_table}_maker_id", request_table, ["maker_id"], schema=schema
    )
    op.create_table(
        decision_table,
        *record_columns(),
        sa.Column(
            "request_id",
            sa.String(36),
            sa.ForeignKey(f"{schema}.{request_table}.id"),
            nullable=False,
        ),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("decision", sa.String(10), nullable=False),
        sa.Column("comment", sa.String(2000), nullable=False, server_default=""),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        schema=schema,
    )
    op.create_index(
        f"uq_{prefix}_change_decision",
        decision_table,
        ["request_id", "user_id"],
        unique=True,
        schema=schema,
    )
    op.create_table(
        f"{prefix}_policy_versions",
        *record_columns(),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("author_id", sa.String(36), nullable=False),
        sa.Column("approver_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("changes", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("break_glass", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema=schema,
    )
    op.create_index(
        f"ix_{prefix}_policy_versions_version",
        f"{prefix}_policy_versions",
        ["version"],
        schema=schema,
    )
    op.create_table(
        f"{prefix}_approval_policy",
        *record_columns(),
        sa.Column("settings", sa.JSON(), nullable=False, server_default="{}"),
        schema=schema,
    )
    op.create_table(
        f"{prefix}_four_eyes_rules",
        *record_columns(),
        sa.Column("name", sa.String(180), nullable=False),
        sa.Column("scope", sa.String(20), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("patterns", sa.JSON(), nullable=False, server_default="[]"),
        schema=schema,
    )
    op.create_index(
        f"uq_{prefix}_four_eyes_priority",
        f"{prefix}_four_eyes_rules",
        ["priority"],
        unique=True,
        schema=schema,
    )
    op.create_table(
        f"{prefix}_sod_rules",
        *record_columns(),
        sa.Column("message", sa.String(1000), nullable=False),
        sa.Column("side_a", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("side_b", sa.JSON(), nullable=False, server_default="[]"),
        schema=schema,
    )


def upgrade():
    schema = context.config.attributes["schema"]
    create_governance(schema, "platform" if schema == "dhmis_control" else "tenant")


def downgrade():
    schema = context.config.attributes["schema"]
    prefix = "platform" if schema == "dhmis_control" else "tenant"
    for suffix in (
        "sod_rules",
        "four_eyes_rules",
        "approval_policy",
        "policy_versions",
        "change_decisions",
        "change_requests",
    ):
        op.drop_table(f"{prefix}_{suffix}", schema=schema)
