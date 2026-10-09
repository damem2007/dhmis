"""Move clinic-owned runtime configuration into tenant schemas."""

import sqlalchemy as sa
from alembic import context, op

revision = "0006"
down_revision = "0005"
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
        op.create_table(
            "platform_commercial_accounts",
            *record_columns(),
            sa.Column("organization_id", sa.String(36), nullable=False, unique=True),
            sa.Column("account_status", sa.String(30), nullable=False, server_default="active"),
            sa.Column("plan_code", sa.String(80), nullable=False, server_default="sandbox"),
            sa.Column(
                "subscription_status",
                sa.String(30),
                nullable=False,
                server_default="not_configured",
            ),
            sa.Column("external_reference", sa.String(180), nullable=False, server_default=""),
            sa.Column("commercial_metadata", sa.JSON(), nullable=False, server_default="{}"),
            schema=schema,
        )
        op.create_table(
            "platform_adapter_defaults",
            *record_columns(),
            sa.Column("region", sa.String(10), nullable=False, server_default="*"),
            sa.Column("capability", sa.String(80), nullable=False),
            sa.Column("provider_name", sa.String(120), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.UniqueConstraint("region", "capability"),
            schema=schema,
        )
        op.create_table(
            "tenant_adapter_overrides",
            *record_columns(),
            sa.Column("organization_id", sa.String(36), nullable=False),
            sa.Column("capability", sa.String(80), nullable=False),
            sa.Column("provider_name", sa.String(120), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("approved_by", sa.String(100), nullable=False),
            sa.Column("approval_reason", sa.String(1000), nullable=False, server_default=""),
            sa.UniqueConstraint("organization_id", "capability"),
            schema=schema,
        )
        op.create_table(
            "adapter_customization_requests",
            *record_columns(),
            sa.Column("organization_id", sa.String(36), nullable=False),
            sa.Column("capability", sa.String(80), nullable=False),
            sa.Column("provider_name", sa.String(120), nullable=False),
            sa.Column("reason", sa.String(1000), nullable=False),
            sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
            sa.Column("requested_by", sa.String(100), nullable=False),
            sa.Column("decided_by", sa.String(100), nullable=False, server_default=""),
            sa.Column("decision_reason", sa.String(1000), nullable=False, server_default=""),
            sa.Column("decision_metadata", sa.JSON(), nullable=False, server_default="{}"),
            schema=schema,
        )
        defaults = [
            ("*", "payment_gateway", "sandbox"),
            ("*", "signature_provider", "sandbox"),
            ("*", "messaging_provider", "sandbox"),
            ("*", "email_provider", "sandbox"),
            ("*", "sms_provider", "sandbox"),
            ("*", "accounting_exporter", "sandbox"),
            ("CA", "claims_network", "Sandbox1_CDAnet"),
            ("US", "claims_network", "Sandbox2_USAdapter"),
        ]
        table = sa.table(
            "platform_adapter_defaults",
            sa.column("id", sa.String),
            sa.column("region", sa.String),
            sa.column("capability", sa.String),
            sa.column("provider_name", sa.String),
            sa.column("created_by", sa.String),
            sa.column("updated_by", sa.String),
            schema=schema,
        )
        op.bulk_insert(
            table,
            [
                {
                    "id": f"adapter-default-{index:02d}",
                    "region": region,
                    "capability": capability,
                    "provider_name": provider,
                    "created_by": "migration",
                    "updated_by": "migration",
                }
                for index, (region, capability, provider) in enumerate(defaults, start=1)
            ],
        )
        op.execute(
            sa.text(
                """
                INSERT INTO dhmis_control.platform_commercial_accounts
                    (id, organization_id, account_status, plan_code, subscription_status,
                     external_reference, commercial_metadata, created_by, updated_by)
                SELECT gen_random_uuid()::text, id,
                       CASE WHEN status = 'active' THEN 'active' ELSE status END,
                       plan, 'not_configured', '', '{}'::json, 'migration', 'migration'
                FROM dhmis_control.organizations
                ON CONFLICT (organization_id) DO NOTHING
                """
            )
        )
        op.execute(
            sa.text(
                """
                INSERT INTO dhmis_control.tenant_adapter_overrides
                    (id, organization_id, capability, provider_name, active,
                     approved_by, approval_reason, created_by, updated_by)
                SELECT gen_random_uuid()::text, o.id, choice.key, choice.value, true,
                       'migration', 'Backfilled from legacy Organization adapter configuration',
                       'migration', 'migration'
                FROM dhmis_control.organizations o
                CROSS JOIN LATERAL jsonb_each_text(COALESCE(o.adapters::jsonb, '{}'::jsonb)) choice
                ON CONFLICT (organization_id, capability) DO NOTHING
                """
            )
        )
        return

    op.create_table(
        "tenant_settings",
        *record_columns(),
        sa.Column("visibility", sa.String(20), nullable=False, server_default="organization"),
        sa.Column("branding", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("policy", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("jurisdiction_policy", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("public_content", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("communication_templates", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("operational_thresholds", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("booking_widget", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("migration_state", sa.JSON(), nullable=False, server_default="{}"),
        schema=schema,
    )
    op.execute(
        sa.text(
            f"""
            INSERT INTO "{schema}".tenant_settings
                (id, visibility, branding, policy, jurisdiction_policy, public_content,
                 communication_templates, operational_thresholds, booking_widget,
                 migration_state, created_by, updated_by)
            VALUES
                ('organization-settings', 'organization', CAST(:branding AS JSON),
                 CAST(:policy AS json),
                 CAST(:jurisdiction_policy as json), CAST(:public_content as json), CAST(:communication_templates as json), CAST(:operational_thresholds as json), CAST(:booking_widget as json),
                 cast(:migration_state as json), 'migration', 'migration')
            ON CONFLICT (id) DO NOTHING
            """
        ).bindparams(
        branding="{}",
        policy='{"cancellation_notice_hours":24,"cancellation_fee_cents":0,"buffer_minutes":0,"reminder_hours":24}',
        jurisdiction_policy="{}",
        public_content="{}",
        communication_templates="{}",
        operational_thresholds="{}",
        booking_widget="{}",
        migration_state='{"legacy_control_backfilled":false}',
    )
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
