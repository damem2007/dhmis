"""Add the platform-owned plan catalogue and tenant subscriptions."""

import sqlalchemy as sa
from alembic import context, op

revision = "0032_platform_plans_subs"
down_revision = "0031_tenant_brand_defaults"
branch_labels = None
depends_on = None


# Handle record columns for this module.
def record_columns():
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
    ]


# Run the upgrade entry point for this module.
def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return

    op.create_table(
        "platform_plans",
        *record_columns(),
        sa.Column("code", sa.String(80), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("price_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("currency", sa.String(3), nullable=False, server_default="CAD"),
        sa.Column("interval", sa.String(20), nullable=False, server_default="month"),
        sa.Column("trial_days", sa.Integer(), nullable=False, server_default="14"),
        sa.Column("max_locations", sa.Integer(), nullable=True),
        sa.Column("features", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.CheckConstraint("price_cents >= 0", name="ck_platform_plans_price_nonnegative"),
        sa.CheckConstraint("trial_days >= 0", name="ck_platform_plans_trial_nonnegative"),
        schema=schema,
    )
    op.create_table(
        "platform_subscriptions",
        *record_columns(),
        sa.Column("organization_id", sa.String(36), nullable=False, unique=True),
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="trialing"),
        sa.Column("trial_ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_at_period_end", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("external_reference", sa.String(180), nullable=False, server_default=""),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.ForeignKeyConstraint(["plan_id"], [f"{schema}.platform_plans.id"]),
        sa.ForeignKeyConstraint(["organization_id"], [f"{schema}.organizations.id"]),
        schema=schema,
    )

    table = sa.table(
        "platform_plans",
        sa.column("id", sa.String),
        sa.column("code", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.String),
        sa.column("price_cents", sa.Integer),
        sa.column("currency", sa.String),
        sa.column("interval", sa.String),
        sa.column("trial_days", sa.Integer),
        sa.column("max_locations", sa.Integer),
        sa.column("features", sa.JSON),
        sa.column("active", sa.Boolean),
        sa.column("created_by", sa.String),
        sa.column("updated_by", sa.String),
        schema=schema,
    )
    op.bulk_insert(
        table,
        [
            {
                "id": "platform-plan-solo",
                "code": "solo",
                "name": "Solo",
                "description": "One dentist, one location.",
                "price_cents": 9900,
                "currency": "CAD",
                "interval": "month",
                "trial_days": 14,
                "max_locations": 1,
                "features": ["Charting and treatment plans", "Recalls and reminders", "Patient portal"],
                "active": True,
                "created_by": "migration",
                "updated_by": "migration",
            },
            {
                "id": "platform-plan-clinic",
                "code": "clinic",
                "name": "Clinic",
                "description": "Up to 8 providers.",
                "price_cents": 29900,
                "currency": "CAD",
                "interval": "month",
                "trial_days": 14,
                "max_locations": 3,
                "features": ["Everything in Solo", "Billing and claims", "Reports and analytics"],
                "active": True,
                "created_by": "migration",
                "updated_by": "migration",
            },
            {
                "id": "platform-plan-group",
                "code": "group",
                "name": "Group",
                "description": "Multiple locations with enterprise controls.",
                "price_cents": 0,
                "currency": "CAD",
                "interval": "month",
                "trial_days": 14,
                "max_locations": None,
                "features": ["Everything in Clinic", "SSO and audit log", "API, webhooks and sandbox"],
                "active": True,
                "created_by": "migration",
                "updated_by": "migration",
            },
        ],
    )


# Run the downgrade entry point for this module.
def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
