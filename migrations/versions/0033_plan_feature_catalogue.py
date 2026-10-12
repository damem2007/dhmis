"""Add a typed platform feature catalogue and plan entitlements."""

import sqlalchemy as sa
from alembic import context, op

revision = "0033_plan_feature_catalogue"
down_revision = "0032_platform_plans_subs"
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


FEATURES = (
    ("module.charting", "Charting and treatment plans", "Clinical workflows and treatment planning.", "clinical", "boolean", ""),
    ("module.recalls", "Recalls and reminders", "Recall schedules and automated patient reminders.", "engagement", "boolean", ""),
    ("module.patient_portal", "Patient portal", "Patient forms, messages, plans and payments.", "portal", "boolean", ""),
    ("module.billing", "Billing and claims", "Invoices, ledger and claims workflows.", "financial", "boolean", ""),
    ("module.reports", "Reports and analytics", "Operational, financial and provider reporting.", "analytics", "boolean", ""),
    ("module.sso_audit", "SSO and audit log", "Single sign-on and advanced audit controls.", "security", "boolean", ""),
    ("module.api", "API, webhooks and sandbox", "Developer API access, webhooks and sandbox tooling.", "developer", "boolean", ""),
    ("limit.locations", "Locations", "Maximum locations available to a tenant.", "limits", "limit", "locations"),
)


def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return

    op.create_table(
        "platform_features",
        *record_columns(),
        sa.Column("key", sa.String(120), nullable=False, unique=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("category", sa.String(80), nullable=False, server_default="core"),
        sa.Column("feature_type", sa.String(20), nullable=False, server_default="boolean"),
        sa.Column("unit", sa.String(40), nullable=False, server_default=""),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.CheckConstraint("feature_type IN ('boolean', 'limit', 'metered')", name="ck_platform_features_type"),
        schema=schema,
    )
    op.create_table(
        "platform_plan_features",
        *record_columns(),
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("feature_id", sa.String(36), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("value", sa.Integer(), nullable=True),
        sa.Column("unlimited", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("included_quantity", sa.Integer(), nullable=True),
        sa.Column("public_label", sa.String(180), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["plan_id"], [f"{schema}.platform_plans.id"]),
        sa.ForeignKeyConstraint(["feature_id"], [f"{schema}.platform_features.id"]),
        sa.UniqueConstraint("plan_id", "feature_id", name="uq_platform_plan_feature"),
        schema=schema,
    )

    feature_table = sa.table(
        "platform_features",
        sa.column("id", sa.String), sa.column("key", sa.String), sa.column("name", sa.String),
        sa.column("description", sa.String), sa.column("category", sa.String),
        sa.column("feature_type", sa.String), sa.column("unit", sa.String), sa.column("active", sa.Boolean),
        sa.column("created_by", sa.String), sa.column("updated_by", sa.String), schema=schema,
    )
    op.bulk_insert(feature_table, [
        {"id": f"platform-feature-{index:02d}", "key": key, "name": name, "description": description,
         "category": category, "feature_type": feature_type, "unit": unit, "active": True,
         "created_by": "migration", "updated_by": "migration"}
        for index, (key, name, description, category, feature_type, unit) in enumerate(FEATURES, start=1)
    ])

    assignments = {
        "solo": {"module.charting", "module.recalls", "module.patient_portal"},
        "clinic": {"module.charting", "module.recalls", "module.patient_portal", "module.billing", "module.reports"},
        "group": {"module.charting", "module.recalls", "module.patient_portal", "module.billing", "module.reports", "module.sso_audit", "module.api"},
    }
    plan_table = sa.table("platform_plans", sa.column("id", sa.String), sa.column("code", sa.String), schema=schema)
    feature_lookup = {key: f"platform-feature-{index:02d}" for index, (key, *_rest) in enumerate(FEATURES, start=1)}
    plan_lookup = {row[1]: row[0] for row in op.get_bind().execute(sa.select(plan_table.c.id, plan_table.c.code)).all()}
    plan_feature_table = sa.table(
        "platform_plan_features", sa.column("id", sa.String), sa.column("plan_id", sa.String),
        sa.column("feature_id", sa.String), sa.column("enabled", sa.Boolean), sa.column("value", sa.Integer),
        sa.column("unlimited", sa.Boolean), sa.column("included_quantity", sa.Integer),
        sa.column("public_label", sa.String), sa.column("created_by", sa.String), sa.column("updated_by", sa.String), schema=schema,
    )
    rows = []
    for plan_code, module_keys in assignments.items():
        plan_id = plan_lookup.get(plan_code)
        if not plan_id:
            continue
        for key in sorted(module_keys):
            rows.append({"id": f"{plan_code}-{key.replace('.', '-')}", "plan_id": plan_id, "feature_id": feature_lookup[key], "enabled": True, "value": None, "unlimited": False, "included_quantity": None, "public_label": "", "created_by": "migration", "updated_by": "migration"})
        rows.append({"id": f"{plan_code}-limit-locations", "plan_id": plan_id, "feature_id": feature_lookup["limit.locations"], "enabled": True, "value": None if plan_code == "group" else {"solo": 1, "clinic": 3}[plan_code], "unlimited": plan_code == "group", "included_quantity": None, "public_label": "", "created_by": "migration", "updated_by": "migration"})
    op.bulk_insert(plan_feature_table, rows)


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
