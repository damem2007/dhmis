"""Phase 3 prescriptions, coordination, surgery, credentials, and reporting fields."""

import sqlalchemy as sa
from alembic import context, op

revision = "0004"
down_revision = "0003"
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
            sa.Column("database_alias", sa.String(80), nullable=False, server_default="primary"),
            schema=schema,
        )
        return

    def foreign(table):
        return f"{schema}.{table}.id"

    op.add_column(
        "locations", sa.Column("branding", sa.JSON(), nullable=False, server_default="{}"), schema=schema
    )
    op.add_column(
        "locations", sa.Column("policy", sa.JSON(), nullable=False, server_default="{}"), schema=schema
    )
    op.add_column(
        "encounters",
        sa.Column("care_setting", sa.String(30), nullable=False, server_default="outpatient"),
        schema=schema,
    )
    op.add_column(
        "invoices", sa.Column("provider_id", sa.String(36), nullable=True), schema=schema
    )
    op.create_foreign_key(
        "invoices_provider_fk",
        "invoices",
        "staff_users",
        ["provider_id"],
        ["id"],
        source_schema=schema,
        referent_schema=schema,
    )
    op.create_table(
        "medication_safety_rules",
        *record_columns(),
        sa.Column("medication", sa.String(160), nullable=False),
        sa.Column("conflicts", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("severity", sa.String(20), nullable=False, server_default="warning"),
        sa.Column("message", sa.String(500), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        schema=schema,
    )
    op.create_table(
        "prescriptions",
        *record_columns(),
        sa.Column("patient_id", sa.String(36), sa.ForeignKey(foreign("patients")), nullable=False),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(foreign("locations")), nullable=False),
        sa.Column("prescriber_id", sa.String(36), sa.ForeignKey(foreign("staff_users")), nullable=False),
        sa.Column("medication", sa.String(160), nullable=False),
        sa.Column("dosage", sa.String(120), nullable=False),
        sa.Column("route", sa.String(60), nullable=False, server_default="oral"),
        sa.Column("frequency", sa.String(120), nullable=False),
        sa.Column("duration_days", sa.Integer(), nullable=False),
        sa.Column("instructions", sa.String(1000), nullable=False, server_default=""),
        sa.Column("controlled_substance", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("safety_flags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("override_reason", sa.String(1000), nullable=False, server_default=""),
        sa.Column("status", sa.String(30), nullable=False, server_default="issued"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        schema=schema,
    )
    op.create_table(
        "lab_cases",
        *record_columns(),
        sa.Column("patient_id", sa.String(36), sa.ForeignKey(foreign("patients")), nullable=False),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(foreign("locations")), nullable=False),
        sa.Column("provider_id", sa.String(36), sa.ForeignKey(foreign("staff_users")), nullable=False),
        sa.Column("case_type", sa.String(120), nullable=False),
        sa.Column("laboratory", sa.String(180), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="created"),
        sa.Column("notes", sa.String(2000), nullable=False, server_default=""),
        sa.Column("status_history", sa.JSON(), nullable=False, server_default="[]"),
        schema=schema,
    )
    op.create_table(
        "referrals",
        *record_columns(),
        sa.Column("patient_id", sa.String(36), sa.ForeignKey(foreign("patients")), nullable=False),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(foreign("locations")), nullable=False),
        sa.Column("provider_id", sa.String(36), sa.ForeignKey(foreign("staff_users")), nullable=False),
        sa.Column("direction", sa.String(20), nullable=False),
        sa.Column("specialty", sa.String(120), nullable=False),
        sa.Column("organization_name", sa.String(180), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="created"),
        sa.Column("reason", sa.String(2000), nullable=False),
        sa.Column("status_history", sa.JSON(), nullable=False, server_default="[]"),
        schema=schema,
    )
    op.create_table(
        "day_surgery_admissions",
        *record_columns(),
        sa.Column("encounter_id", sa.String(36), sa.ForeignKey(foreign("encounters")), nullable=False, unique=True),
        sa.Column("patient_id", sa.String(36), sa.ForeignKey(foreign("patients")), nullable=False),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(foreign("locations")), nullable=False),
        sa.Column("provider_id", sa.String(36), sa.ForeignKey(foreign("staff_users")), nullable=False),
        sa.Column("procedure_name", sa.String(180), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="admitted"),
        sa.Column("preop_checklist", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("anesthesia_records", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("recovery_notes", sa.String(8000), nullable=False, server_default=""),
        sa.Column("discharge_summary", sa.String(8000), nullable=False, server_default=""),
        schema=schema,
    )
    op.create_table(
        "provider_credentials",
        *record_columns(),
        sa.Column("provider_id", sa.String(36), sa.ForeignKey(foreign("staff_users")), nullable=False),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(foreign("locations")), nullable=True),
        sa.Column("credential_type", sa.String(120), nullable=False),
        sa.Column("credential_number", sa.String(160), nullable=False),
        sa.Column("jurisdiction", sa.String(80), nullable=False),
        sa.Column("issued_on", sa.Date(), nullable=False),
        sa.Column("expires_on", sa.Date(), nullable=False),
        sa.Column("alert_lead_days", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("provider_id", "credential_type", "jurisdiction"),
        schema=schema,
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
