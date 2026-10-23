"""Restrict Quick chart flags to condition catalogue entries."""

from alembic import context, op
import sqlalchemy as sa


revision = "0055_quick_chart_conditions"
down_revision = "0054_dynamic_draw_arch"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Clear legacy Quick chart flags from treatments and tooth statuses."""
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    bind = op.get_bind()
    op.execute(
        sa.text(
            f"UPDATE {schema}.treatment_catalogue_items "
            "SET quick_chart = FALSE "
            "WHERE item_type <> 'condition' AND quick_chart = TRUE"
        )
    )
    # Existing sets may contain legacy treatment codes. Keep only active
    # condition codes so settings and odontogram consumers share one contract.
    inspector = sa.inspect(bind)
    if "quick_chart_sets" not in inspector.get_table_names(schema=schema):
        return
    condition_codes = {
        row[0]
        for row in bind.execute(
            sa.text(
                f"SELECT code FROM {schema}.treatment_catalogue_items "
                "WHERE item_type = 'condition' AND active = TRUE"
            )
        ).all()
    }
    metadata = sa.MetaData()
    quick_chart_sets = sa.Table("quick_chart_sets", metadata, autoload_with=bind, schema=schema)
    # ``items`` collides with ColumnCollection.items(), so use mapping access
    # to select the actual JSON column.
    items_column = quick_chart_sets.c["items"]
    for set_id, raw_items in bind.execute(sa.select(quick_chart_sets.c.id, items_column)).all():
        items = raw_items if isinstance(raw_items, list) else []
        filtered = list(dict.fromkeys(item for item in items if item in condition_codes))
        if filtered != items:
            bind.execute(
                quick_chart_sets.update()
                .where(quick_chart_sets.c.id == set_id)
                .values(items=filtered)
            )


def downgrade() -> None:
    """Keep the forward-only data correction; restoring ambiguous flags is unsafe."""
    raise RuntimeError("Use a reviewed forward migration")
