"""Initial schema snapshot; deliberately immutable, independent of future ORM changes."""

import json
from pathlib import Path

from alembic import context, op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    snapshot = json.loads((Path(__file__).parent / "0001_schema.json").read_text())
    group = "control" if schema == "dhmis_control" else "tenant"
    for statement in snapshot[group]:
        op.execute(statement.replace("tenant.", f'"{schema}".'))
    if group == "tenant":
        op.execute(f'''CREATE FUNCTION "{schema}".reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'Append-only record: modification rejected'; END; $$''')
        for table in ("audit_events", "ledger_entries", "chart_entries", "perio_exams"):
            op.execute(
                f'CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON "{schema}".{table} FOR EACH ROW EXECUTE FUNCTION "{schema}".reject_mutation()'
            )


def downgrade():
    raise RuntimeError("Destructive downgrade is not supported. Use a reviewed forward migration.")
