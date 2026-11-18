"""Add public plan visibility, curated experiences, and commercial add-on billing."""

from uuid import uuid4

import sqlalchemy as sa
from alembic import context, op

revision = "0062_plan_visibility_addons"
down_revision = "0061_provider_key_version"
branch_labels = None
depends_on = None


def upgrade():
    if context.config.attributes["schema"] != "dhmis_control":
        return

    op.add_column(
        "platform_plans",
        sa.Column("public_available", sa.Boolean(), nullable=False, server_default=sa.false()),
        schema="dhmis_control",
    )
    # Existing plans remain private until a platform operator explicitly
    # elects to expose each one through the public plan API.

    op.create_table(
        "platform_tenant_addons",
        sa.Column("organization_id", sa.String(36), nullable=False, index=True),
        sa.Column("feature_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="active"),
        sa.Column("quantity", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("unit_price_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("discount_basis_points", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("currency", sa.String(3), nullable=False, server_default="CAD"),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("id", sa.Uuid(as_uuid=False), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.ForeignKeyConstraint(["feature_id"], ["dhmis_control.platform_features.id"]),
        sa.CheckConstraint("quantity > 0", name="ck_platform_tenant_addon_quantity"),
        sa.CheckConstraint("unit_price_cents >= 0", name="ck_platform_tenant_addon_price"),
        sa.CheckConstraint(
            "discount_basis_points BETWEEN 0 AND 10000", name="ck_platform_tenant_addon_discount"
        ),
        sa.UniqueConstraint("organization_id", "feature_id", name="uq_platform_tenant_addon_feature"),
        schema="dhmis_control",
    )
    op.create_table(
        "platform_commercial_ledger_entries",
        sa.Column("organization_id", sa.String(36), nullable=False, index=True),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("description", sa.String(240), nullable=False),
        sa.Column("gross_amount_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("discount_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("net_amount_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("currency", sa.String(3), nullable=False, server_default="CAD"),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column("reference", sa.String(120), nullable=False, unique=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("id", sa.Uuid(as_uuid=False), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.CheckConstraint("gross_amount_cents >= 0", name="ck_platform_commercial_ledger_gross"),
        sa.CheckConstraint(
            "discount_cents >= 0 AND discount_cents <= gross_amount_cents",
            name="ck_platform_commercial_ledger_discount",
        ),
        sa.CheckConstraint(
            "net_amount_cents = gross_amount_cents - discount_cents", name="ck_platform_commercial_ledger_net"
        ),
        schema="dhmis_control",
    )
    # Establish the SaaS ledger boundary for subscriptions that existed before
    # this migration. These are scheduled during a trial and open otherwise;
    # patient/clinical invoices are intentionally never copied here.
    op.execute(
        """
        INSERT INTO dhmis_control.platform_commercial_ledger_entries
          (id, organization_id, kind, description, gross_amount_cents, discount_cents,
           net_amount_cents, currency, status, reference, metadata, created_by, updated_by)
        SELECT
          gen_random_uuid(),
          s.organization_id,
          'plan_assignment',
          p.name || ' plan · ' || p.interval,
          p.price_cents,
          0,
          p.price_cents,
          p.currency,
          CASE WHEN s.status = 'trialing' THEN 'scheduled' ELSE 'open' END,
          'plan-migration:' || s.organization_id || ':' || s.plan_id,
          jsonb_build_object('plan_id', p.id, 'plan_code', p.code, 'subscription_status', s.status),
          'migration',
          'migration'
        FROM dhmis_control.platform_subscriptions s
        JOIN dhmis_control.platform_plans p ON p.id = s.plan_id
        """
    )

    features = sa.table(
        "platform_features",
        sa.column("id", sa.Uuid(as_uuid=False)),
        sa.column("key", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.String),
        sa.column("category", sa.String),
        sa.column("feature_type", sa.String),
        sa.column("unit", sa.String),
        sa.column("active", sa.Boolean),
        sa.column("created_by", sa.String),
        sa.column("updated_by", sa.String),
        schema="dhmis_control",
    )
    additions = (
        (
            "experience.tenant_website",
            "Tenant website",
            "Public clinic website.",
            "experience",
            "boolean",
            "",
        ),
        (
            "capability.appointment_booking",
            "Online appointment booking",
            "Allow patients to create appointments through enabled patient channels.",
            "engagement",
            "boolean",
            "",
        ),
        (
            "limit.appointment_widget_origins",
            "Appointment widget origins",
            "Maximum approved website origins for the Appointment Widget.",
            "limits",
            "limit",
            "origins",
        ),
    )
    existing = {row[0] for row in op.get_bind().execute(sa.select(features.c.key)).all()}
    op.bulk_insert(
        features,
        [
            {
                "id": str(uuid4()),
                "key": key,
                "name": name,
                "description": description,
                "category": category,
                "feature_type": feature_type,
                "unit": unit,
                "active": True,
                "created_by": "migration",
                "updated_by": "migration",
            }
            for key, name, description, category, feature_type, unit in additions
            if key not in existing
        ],
    )

    plans = sa.table(
        "platform_plans",
        sa.column("id", sa.Uuid(as_uuid=False)),
        schema="dhmis_control",
    )
    assignments = sa.table(
        "platform_plan_features",
        sa.column("id", sa.Uuid(as_uuid=False)),
        sa.column("plan_id", sa.Uuid(as_uuid=False)),
        sa.column("feature_id", sa.Uuid(as_uuid=False)),
        sa.column("enabled", sa.Boolean),
        sa.column("value", sa.Integer),
        sa.column("unlimited", sa.Boolean),
        sa.column("included_quantity", sa.Integer),
        sa.column("public_label", sa.String),
        sa.column("created_by", sa.String),
        sa.column("updated_by", sa.String),
        schema="dhmis_control",
    )
    feature_ids = {
        key: identifier
        for identifier, key in op.get_bind().execute(sa.select(features.c.id, features.c.key)).all()
    }
    for plan_id in op.get_bind().execute(sa.select(plans.c.id)).scalars():
        for key, value, label in (
            ("experience.tenant_website", None, "Tenant website"),
            ("capability.appointment_booking", None, "Online appointment booking"),
            ("limit.appointment_widget_origins", 1, "1 widget origin"),
        ):
            feature_id = feature_ids.get(key)
            if not feature_id:
                continue
            exists = (
                op.get_bind()
                .execute(
                    sa.select(assignments.c.id).where(
                        assignments.c.plan_id == plan_id,
                        assignments.c.feature_id == feature_id,
                    )
                )
                .scalar_one_or_none()
            )
            if not exists:
                op.get_bind().execute(
                    assignments.insert().values(
                        id=str(uuid4()),
                        plan_id=plan_id,
                        feature_id=feature_id,
                        enabled=True,
                        value=value,
                        unlimited=False,
                        included_quantity=None,
                        public_label=label,
                        created_by="migration",
                        updated_by="migration",
                    )
                )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
