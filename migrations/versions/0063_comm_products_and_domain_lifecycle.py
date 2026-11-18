"""Add commercial products, immutable reversals, and domain lifecycle records."""

import sqlalchemy as sa
from alembic import context, op

revision = "0063_commercial_domains"
down_revision = "0062_plan_visibility_addons"
branch_labels = None
depends_on = None


def upgrade():
    if context.config.attributes["schema"] != "dhmis_control":
        return

    op.add_column(
        "platform_plans",
        sa.Column("configuration_mode", sa.String(20), nullable=False, server_default="fixed"),
        schema="dhmis_control",
    )
    op.add_column(
        "platform_plans",
        sa.Column("configuration_status", sa.String(30), nullable=False, server_default="draft"),
        schema="dhmis_control",
    )
    op.add_column(
        "platform_plans",
        sa.Column("configuration_notes", sa.JSON(), nullable=False, server_default="{}"),
        schema="dhmis_control",
    )
    # Existing plans have already been provisioned under the legacy catalogue.
    # Keep them assignable while new/edited plans use preflight validation.
    op.execute("UPDATE dhmis_control.platform_plans SET configuration_status = 'validated'")

    op.create_table(
        "platform_plan_combinations",
        sa.Column("plan_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("code", sa.String(80), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("feature_keys", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("price_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("currency", sa.String(3), nullable=False, server_default="CAD"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("id", sa.Uuid(as_uuid=False), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.ForeignKeyConstraint(["plan_id"], ["dhmis_control.platform_plans.id"]),
        sa.UniqueConstraint("plan_id", "code", name="uq_platform_plan_combination"),
        sa.CheckConstraint("price_cents >= 0", name="ck_platform_plan_combination_price"),
        schema="dhmis_control",
    )
    op.create_table(
        "platform_addon_products",
        sa.Column("feature_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("code", sa.String(80), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("quantity", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("price_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("currency", sa.String(3), nullable=False, server_default="CAD"),
        sa.Column("interval", sa.String(20), nullable=False, server_default="month"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("id", sa.Uuid(as_uuid=False), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.ForeignKeyConstraint(["feature_id"], ["dhmis_control.platform_features.id"]),
        sa.UniqueConstraint("code", name="uq_platform_addon_product_code"),
        sa.CheckConstraint("quantity > 0", name="ck_platform_addon_product_quantity"),
        sa.CheckConstraint("price_cents >= 0", name="ck_platform_addon_product_price"),
        schema="dhmis_control",
    )
    op.add_column(
        "platform_tenant_addons",
        sa.Column("product_id", sa.Uuid(as_uuid=False), nullable=True),
        schema="dhmis_control",
    )
    op.create_foreign_key(
        "fk_platform_tenant_addon_product",
        "platform_tenant_addons",
        "platform_addon_products",
        ["product_id"],
        ["id"],
        source_schema="dhmis_control",
        referent_schema="dhmis_control",
    )

    # Refund and reversal entries are signed amounts. The original charge stays
    # immutable; every adjustment records an explicit relationship to it.
    op.drop_constraint(
        "ck_platform_commercial_ledger_gross", "platform_commercial_ledger_entries", schema="dhmis_control"
    )
    op.drop_constraint(
        "ck_platform_commercial_ledger_discount", "platform_commercial_ledger_entries", schema="dhmis_control"
    )
    op.drop_constraint(
        "ck_platform_commercial_ledger_net", "platform_commercial_ledger_entries", schema="dhmis_control"
    )
    op.create_check_constraint(
        "ck_platform_commercial_ledger_discount_signed",
        "platform_commercial_ledger_entries",
        "(gross_amount_cents >= 0 AND discount_cents >= 0 AND discount_cents <= gross_amount_cents) OR (gross_amount_cents <= 0 AND discount_cents <= 0 AND discount_cents >= gross_amount_cents)",
        schema="dhmis_control",
    )
    op.create_check_constraint(
        "ck_platform_commercial_ledger_net_signed",
        "platform_commercial_ledger_entries",
        "net_amount_cents = gross_amount_cents - discount_cents",
        schema="dhmis_control",
    )
    op.add_column(
        "platform_commercial_ledger_entries",
        sa.Column("reversal_of_entry_id", sa.Uuid(as_uuid=False), nullable=True),
        schema="dhmis_control",
    )
    op.create_foreign_key(
        "fk_platform_commercial_ledger_reversal",
        "platform_commercial_ledger_entries",
        "platform_commercial_ledger_entries",
        ["reversal_of_entry_id"],
        ["id"],
        source_schema="dhmis_control",
        referent_schema="dhmis_control",
    )

    op.create_table(
        "organization_domain_requests",
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column("status", sa.String(40), nullable=False, server_default="pending"),
        sa.Column("public_hostname", sa.String(253), nullable=True),
        sa.Column("backoffice_hostname", sa.String(253), nullable=False),
        sa.Column("canonical", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("activation_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suspension_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("id", sa.Uuid(as_uuid=False), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.ForeignKeyConstraint(["organization_id"], ["dhmis_control.organizations.id"]),
        sa.CheckConstraint("mode IN ('managed', 'custom')", name="ck_domain_request_mode"),
        schema="dhmis_control",
    )
    op.create_table(
        "organization_domain_hosts",
        sa.Column("request_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("hostname", sa.String(253), nullable=False),
        sa.Column("role", sa.String(30), nullable=False),
        sa.Column("routing_status", sa.String(40), nullable=False, server_default="pending"),
        sa.Column("tls_status", sa.String(40), nullable=False, server_default="pending"),
        sa.Column("canonical", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("id", sa.Uuid(as_uuid=False), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.ForeignKeyConstraint(["request_id"], ["dhmis_control.organization_domain_requests.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["dhmis_control.organizations.id"]),
        sa.UniqueConstraint("hostname", name="uq_organization_domain_host_hostname"),
        sa.CheckConstraint(
            "role IN ('public', 'back_office', 'managed_back_office')",
            name="ck_domain_host_role",
        ),
        schema="dhmis_control",
    )
    op.create_table(
        "organization_domain_verifications",
        sa.Column("request_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("method", sa.String(20), nullable=False, server_default="dns"),
        sa.Column("token", sa.String(160), nullable=False),
        sa.Column("dns_name", sa.String(253), nullable=False, server_default=""),
        sa.Column("http_path", sa.String(300), nullable=False, server_default=""),
        sa.Column("ownership_status", sa.String(40), nullable=False, server_default="pending"),
        sa.Column("dns_status", sa.String(40), nullable=False, server_default="pending"),
        sa.Column("tls_status", sa.String(40), nullable=False, server_default="pending"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("id", sa.Uuid(as_uuid=False), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.ForeignKeyConstraint(["request_id"], ["dhmis_control.organization_domain_requests.id"]),
        schema="dhmis_control",
    )
    op.create_table(
        "organization_domain_events",
        sa.Column("request_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("id", sa.Uuid(as_uuid=False), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.ForeignKeyConstraint(["request_id"], ["dhmis_control.organization_domain_requests.id"]),
        schema="dhmis_control",
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
