"""Add tenant clinical catalogue, Quick chart, and quote snapshot tables."""

import sqlalchemy as sa
from alembic import context, op

revision = "0040_clinical_catalogue_quotes"
down_revision = "0039_tenant_code_library"
branch_labels = None
depends_on = None


def upgrade():
    """Create shared tenant structures in the template and every tenant schema."""
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names(schema=schema))
    if "treatment_plans" in existing:
        columns = {column["name"] for column in inspector.get_columns("treatment_plans", schema=schema)}
        if "provider_id" not in columns:
            op.add_column(
                "treatment_plans",
                sa.Column("provider_id", sa.String(36), nullable=True),
                schema=schema,
            )
            op.create_foreign_key(
                "fk_treatment_plans_provider_id",
                "treatment_plans",
                "staff_users",
                ["provider_id"],
                ["id"],
                source_schema=schema,
                referent_schema=schema,
            )
    if "treatment_catalogue_items" not in existing:
        op.create_table(
            "treatment_catalogue_items",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0040"),
            sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0040"),
            sa.Column("item_type", sa.String(30), nullable=False),
            sa.Column("code", sa.String(80), nullable=False),
            sa.Column("name", sa.String(180), nullable=False),
            sa.Column("description", sa.String(1000), nullable=False, server_default=""),
            sa.Column("service_id", sa.String(36), nullable=True),
            sa.Column("procedure_code_id", sa.String(36), nullable=True),
            sa.Column("fee_source", sa.String(40), nullable=False, server_default="services"),
            sa.Column("quick_chart", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("appearance_key", sa.String(60), nullable=False, server_default="healthy"),
            sa.Column("draw_on", sa.String(40), nullable=False, server_default=""),
            sa.Column("resolved_by", sa.String(40), nullable=False, server_default=""),
            sa.Column("tooth_status_effect", sa.String(40), nullable=False, server_default=""),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.ForeignKeyConstraint(["service_id"], [f"{schema}.services.id"]),
            sa.UniqueConstraint("item_type", "code", name="uq_treatment_catalogue_item_code"),
            schema=schema,
        )
    if "quick_chart_sets" not in existing:
        op.create_table(
            "quick_chart_sets",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0040"),
            sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0040"),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("description", sa.String(1000), nullable=False, server_default=""),
            sa.Column("items", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.UniqueConstraint("name", name="uq_quick_chart_set_name"),
            schema=schema,
        )
    if "quotes" not in existing:
        op.create_table(
            "quotes",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0040"),
            sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0040"),
            sa.Column("patient_id", sa.String(36), nullable=False),
            sa.Column("location_id", sa.String(36), nullable=False),
            sa.Column("treatment_plan_id", sa.String(36), nullable=False),
            sa.Column("option_index", sa.Integer(), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("snapshot", sa.JSON(), nullable=False),
            sa.Column("total_cents", sa.Integer(), nullable=False),
            sa.Column("estimated_insurance_cents", sa.Integer(), nullable=False),
            sa.Column("estimated_patient_cents", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
            sa.ForeignKeyConstraint(["patient_id"], [f"{schema}.patients.id"]),
            sa.ForeignKeyConstraint(["location_id"], [f"{schema}.locations.id"]),
            sa.ForeignKeyConstraint(["treatment_plan_id"], [f"{schema}.treatment_plans.id"]),
            sa.UniqueConstraint("treatment_plan_id", "option_index", "version", name="uq_quote_revision"),
            schema=schema,
        )


def downgrade():
    """Keep the project's forward-only migration policy."""
    raise RuntimeError("Use a reviewed forward migration")
