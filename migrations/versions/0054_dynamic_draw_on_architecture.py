"""Add condition/procedure links and immutable chart rendering snapshots."""

import hashlib

import sqlalchemy as sa
from alembic import context, op

revision = "0054_dynamic_draw_arch"
down_revision = "0053_catalogue_procedure_fees"
branch_labels = None
depends_on = None


def upgrade() -> None:
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "chart_entries" in inspector.get_table_names(schema=schema):
        columns = {c["name"] for c in inspector.get_columns("chart_entries", schema=schema)}
        if "rendering_snapshot" not in columns:
            op.add_column("chart_entries", sa.Column("rendering_snapshot", sa.JSON(), nullable=True), schema=schema)
    if "condition_treatment_links" not in inspector.get_table_names(schema=schema):
        op.create_table(
            "condition_treatment_links",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.String(100), nullable=False),
            sa.Column("updated_by", sa.String(100), nullable=False),
            sa.Column("condition_id", sa.String(36), sa.ForeignKey(f"{schema}.treatment_catalogue_items.id"), nullable=False),
            sa.Column("treatment_id", sa.String(36), sa.ForeignKey(f"{schema}.treatment_catalogue_items.id"), nullable=False),
            sa.Column("relationship_type", sa.String(30), nullable=False, server_default="may_resolve"),
            sa.UniqueConstraint("condition_id", "treatment_id", "relationship_type", name="uq_condition_treatment_link"),
            schema=schema,
        )
    # Legacy resolved_by remains intact for audit. Exact, unambiguous matches are
    # migrated into the normalized association table; ambiguous values are reported.
    rows = bind.execute(sa.text(f"SELECT id, resolved_by FROM {schema}.treatment_catalogue_items WHERE item_type='condition' AND COALESCE(resolved_by,'') <> ''"))
    legacy_services = bind.execute(sa.text(f"SELECT id, service_id FROM {schema}.treatment_catalogue_items WHERE item_type <> 'treatment' AND service_id IS NOT NULL")).all()
    for item_id, service_id in legacy_services:
        print(f"0054 legacy non-billable service link retained for review: item={item_id} service={service_id}")
    items = bind.execute(sa.text(f"SELECT id, code, name FROM {schema}.treatment_catalogue_items WHERE item_type='treatment'")).mappings().all()
    for condition_id, resolved_by in rows:
        for token in (part.strip() for part in (resolved_by or "").split(",")):
            if not token:
                continue
            matches = [item for item in items if token.casefold() in {item["id"].casefold(), item["code"].casefold(), item["name"].casefold()}]
            if len(matches) == 1:
                exists = bind.execute(sa.text(f"SELECT 1 FROM {schema}.condition_treatment_links WHERE condition_id=:c AND treatment_id=:t AND relationship_type='may_resolve'"), {"c": condition_id, "t": matches[0]["id"]}).first()
                if not exists:
                    link_id = hashlib.sha256(f"{condition_id}:{matches[0]['id']}:may_resolve".encode()).hexdigest()[:36]
                    bind.execute(sa.text(f"INSERT INTO {schema}.condition_treatment_links (id,created_at,updated_at,created_by,updated_by,condition_id,treatment_id,relationship_type) VALUES (:id,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'migration','migration',:c,:t,'may_resolve')"), {"id": link_id, "c": condition_id, "t": matches[0]["id"]})
            else:
                print(f"0054 unresolved resolved_by token: condition={condition_id} token={token}")


def downgrade() -> None:
    raise RuntimeError("Use a reviewed forward migration")
