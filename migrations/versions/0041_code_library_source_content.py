"""Persist tenant-isolated licensed source bytes for code-library versions."""

import sqlalchemy as sa
from alembic import context, op

revision = "0041_code_library_source_content"
down_revision = "0040_clinical_catalogue_quotes"
branch_labels = None
depends_on = None


def upgrade():
    """Add optional source metadata/content columns to every tenant schema."""
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table in ("code_library_activations", "code_library_versions"):
        if table not in inspector.get_table_names(schema=schema):
            continue
        columns = {column["name"] for column in inspector.get_columns(table, schema=schema)}
        if "source_mime_type" not in columns:
            op.add_column(table, sa.Column("source_mime_type", sa.String(120), nullable=False, server_default=""), schema=schema)
        if table == "code_library_versions" and "source_file_size" not in columns:
            op.add_column(table, sa.Column("source_file_size", sa.Integer(), nullable=False, server_default="0"), schema=schema)
        if "source_content" not in columns:
            op.add_column(table, sa.Column("source_content", sa.LargeBinary(), nullable=True), schema=schema)


def downgrade():
    """Keep the project's forward-only migration policy."""
    raise RuntimeError("Use a reviewed forward migration")
