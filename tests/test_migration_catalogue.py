"""Static invariants for the shared schema migration catalogue.

The application runs one Alembic chain against the control schema, the tenant
template, and each provisioned tenant schema. These checks deliberately avoid
opening a database so they also run in a clean installation before the first
tenant exists.
"""

import ast
import re
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parents[1] / "migrations" / "versions"
TENANT_SCHEMA_INSTANCE = re.compile(r"dhmis_t_[0-9a-f]{32}", re.IGNORECASE)
UUID_LITERAL = re.compile(
    r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-f])",
    re.IGNORECASE,
)


# Internal test helper for metadata.
def _metadata(path: Path) -> tuple[str, str | None]:
    tree = ast.parse(path.read_text(), filename=str(path))
    values: dict[str, str | None] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in {"revision", "down_revision"}:
            if isinstance(node.value, ast.Constant):
                values[target.id] = node.value.value
    return values["revision"], values.get("down_revision")


# Exercise or prepare test migration catalogue is a single complete chain for this test module.
def test_migration_catalogue_is_a_single_complete_chain():
    files = sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9][0-9]_*.py"))

    assert len(files) == 37
    revisions = [_metadata(path) for path in files]
    assert revisions[0] == ("0001", None)
    for previous, current in zip(revisions, revisions[1:]):
        assert current[1] == previous[0]


# Exercise or prepare test migrations do not embed provisioned tenant identity for this test module.
def test_migrations_do_not_embed_provisioned_tenant_identity():
    for path in MIGRATIONS_DIR.glob("[0-9][0-9][0-9][0-9]_*.py"):
        source = path.read_text()
        assert not TENANT_SCHEMA_INSTANCE.search(source), path.name
        assert not UUID_LITERAL.search(source), path.name
        # "tenant" is a logical snapshot/prefix, but never a real schema
        # name. A guard against it would skip every provisioned schema.
        assert 'schema != "tenant"' not in source, path.name


def test_backend_definitions_have_maintainability_annotations():
    """Keep new production definitions documented without changing runtime docs."""
    for root in (MIGRATIONS_DIR.parents[1] / "app", MIGRATIONS_DIR):
        for path in root.rglob("*.py"):
            lines = path.read_text().splitlines()
            tree = ast.parse("\n".join(lines), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if ast.get_docstring(node) is not None:
                    continue
                decorators = getattr(node, "decorator_list", [])
                line = min([decorator.lineno for decorator in decorators] or [node.lineno]) - 2
                while line >= 0 and not lines[line].strip():
                    line -= 1
                assert line >= 0 and lines[line].lstrip().startswith("#"), (
                    f"{path}:{node.lineno} {node.name} needs a docstring or comment"
                )
