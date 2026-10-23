"""Add tenant-owned licensed procedure-code activation and version storage."""

import sqlalchemy as sa
from alembic import context, op

revision = "0039_tenant_code_library"
down_revision = "0038_location_phone"
branch_labels = None
depends_on = None


def upgrade():
    """Create code-library tables in the template and every tenant schema."""
    schema = context.config.attributes["schema"]
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if schema == "dhmis_control":
        columns = {column["name"] for column in inspector.get_columns("platform_regions", schema=schema)}
        if "code_set_type" not in columns:
            op.add_column("platform_regions", sa.Column("code_set_type", sa.String(20), nullable=False, server_default=""), schema=schema)
            op.execute(sa.text(f'UPDATE "{schema}".platform_regions SET code_set_type = CASE code WHEN \'CA\' THEN \'CDA\' WHEN \'US\' THEN \'CDT\' ELSE \'\' END'))
            op.alter_column("platform_regions", "code_set_type", server_default=None, schema=schema)
        if "tenant_code_set_activation" not in inspector.get_table_names(schema=schema):
            op.create_table(
                "tenant_code_set_activation",
                sa.Column("id", sa.String(36), primary_key=True),
                sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
                sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
                sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0039"),
                sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0039"),
                sa.Column("organization_id", sa.String(36), nullable=False, unique=True),
                sa.Column("code_set_type", sa.String(20), nullable=False),
                sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
                sa.Column("last_status_changed_at", sa.DateTime(timezone=True), nullable=True),
                schema=schema,
            )
        return

    existing = set(inspector.get_table_names(schema=schema))
    if "code_library_activations" not in existing:
        op.create_table(
            "code_library_activations",
            sa.Column("id", sa.String(36), primary_key=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0039"), sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0039"),
            sa.Column("code_set_type", sa.String(20), nullable=False), sa.Column("licence_holder", sa.String(180), nullable=False), sa.Column("licence_reference", sa.String(180), nullable=False), sa.Column("valid_until", sa.Date(), nullable=True), sa.Column("source_file_name", sa.String(255), nullable=False, server_default=""), sa.Column("source_file_size", sa.Integer(), nullable=False, server_default="0"), sa.Column("attested", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("status", sa.String(20), nullable=False, server_default="active"), sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True), sa.Column("activated_by", sa.String(100), nullable=False, server_default=""),
            sa.UniqueConstraint("code_set_type", name="uq_code_library_activation_type"), schema=schema,
        )
    if "code_library_versions" not in existing:
        op.create_table(
            "code_library_versions",
            sa.Column("id", sa.String(36), primary_key=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0039"), sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0039"),
            sa.Column("activation_id", sa.String(36), nullable=False), sa.Column("version", sa.String(80), nullable=False), sa.Column("checksum", sa.String(128), nullable=False), sa.Column("source_file_name", sa.String(255), nullable=False, server_default=""), sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("imported_by", sa.String(100), nullable=False), sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()), sa.ForeignKeyConstraint(["activation_id"], [f"{schema}.code_library_activations.id"]), sa.UniqueConstraint("activation_id", "version", name="uq_code_library_version"), schema=schema,
        )
    if "procedure_codes" not in existing:
        op.create_table(
            "procedure_codes",
            sa.Column("id", sa.String(36), primary_key=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0039"), sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0039"),
            sa.Column("version_id", sa.String(36), nullable=False), sa.Column("code", sa.String(80), nullable=False), sa.Column("description", sa.Text(), nullable=False), sa.Column("category", sa.String(120), nullable=False, server_default=""), sa.Column("status", sa.String(20), nullable=False, server_default="active"), sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True), sa.ForeignKeyConstraint(["version_id"], [f"{schema}.code_library_versions.id"]), sa.UniqueConstraint("version_id", "code", name="uq_procedure_code_version_code"), schema=schema,
        )
    if "treatment_code_mappings" not in existing:
        op.create_table(
            "treatment_code_mappings",
            sa.Column("id", sa.String(36), primary_key=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0039"), sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0039"),
            sa.Column("service_id", sa.String(36), nullable=False), sa.Column("procedure_code_id", sa.String(36), nullable=False), sa.Column("status", sa.String(20), nullable=False, server_default="active"), sa.ForeignKeyConstraint(["service_id"], [f"{schema}.services.id"]), sa.ForeignKeyConstraint(["procedure_code_id"], [f"{schema}.procedure_codes.id"]), sa.UniqueConstraint("service_id", "procedure_code_id", name="uq_treatment_code_mapping"), schema=schema,
        )


def downgrade():
    """Keep the project's forward-only migration policy."""
    raise RuntimeError("Use a reviewed forward migration")
