"""Add the appointment-widget entitlement to the platform catalogue."""

import sqlalchemy as sa
from alembic import context, op

revision = "0058_appointment_widget"
down_revision = "0057"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    if schema != "dhmis_control":
        return
    bind = op.get_bind()
    features = sa.table(
        "platform_features",
        sa.column("id", sa.String),
        sa.column("key", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.String),
        sa.column("category", sa.String),
        sa.column("feature_type", sa.String),
        sa.column("unit", sa.String),
        sa.column("active", sa.Boolean),
        sa.column("created_by", sa.String),
        sa.column("updated_by", sa.String),
        schema=schema,
    )
    feature_id = "platform-feature-09"
    if not bind.execute(sa.select(features.c.id).where(features.c.key == "module.appointment_widget")).scalar_one_or_none():
        op.bulk_insert(features, [{
            "id": feature_id,
            "key": "module.appointment_widget",
            "name": "Appointment widget",
            "description": "Embeddable appointment booking for tenant-owned websites.",
            "category": "engagement",
            "feature_type": "boolean",
            "unit": "",
            "active": True,
            "created_by": "migration",
            "updated_by": "migration",
        }])
    else:
        feature_id = bind.execute(sa.select(features.c.id).where(features.c.key == "module.appointment_widget")).scalar_one()

    plans = sa.table("platform_plans", sa.column("id", sa.String), sa.column("code", sa.String), schema=schema)
    assignments = sa.table(
        "platform_plan_features",
        sa.column("id", sa.String), sa.column("plan_id", sa.String), sa.column("feature_id", sa.String),
        sa.column("enabled", sa.Boolean), sa.column("value", sa.Integer), sa.column("unlimited", sa.Boolean),
        sa.column("included_quantity", sa.Integer), sa.column("public_label", sa.String),
        sa.column("created_by", sa.String), sa.column("updated_by", sa.String), schema=schema,
    )
    for plan_id, code in bind.execute(sa.select(plans.c.id, plans.c.code)).all():
        exists = bind.execute(sa.select(assignments.c.id).where(assignments.c.plan_id == plan_id, assignments.c.feature_id == feature_id)).scalar_one_or_none()
        if not exists:
            bind.execute(assignments.insert().values(
                id=f"{code}-module-appointment-widget", plan_id=plan_id, feature_id=feature_id,
                enabled=True, value=None, unlimited=False, included_quantity=None,
                public_label="Appointment widget", created_by="migration", updated_by="migration",
            ))


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
