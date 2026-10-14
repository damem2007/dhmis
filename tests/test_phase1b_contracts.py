"""Phase 1B regression checks for route and import compatibility."""

import ast
import importlib
import json
from pathlib import Path

from app.main import app

BACKEND_ROOT = Path(__file__).resolve().parents[1]
OPENAPI_BASELINE = Path(__file__).with_name("fixtures") / "openapi-baseline.json"
REGISTERED_MODULES = (
    "app.integrations.geocoding_providers",
    "app.cms.service",
    "app.analytics.service",
    "app.patient_identity.router",
    "app.cms.router",
    "app.portal.router",
    "app.rbac.policy",
    "app.rbac.workflow",
    "app.rbac.router",
    "app.organizations.admin",
)


def _load_openapi_baseline() -> dict:
    """Load the canonical OpenAPI snapshot captured at the checkpoint."""
    return json.loads(OPENAPI_BASELINE.read_text(encoding="utf-8"))


def _operation_pairs(spec: dict) -> set[tuple[str, str]]:
    """Return every documented path and HTTP-method pair from an OpenAPI spec."""
    methods = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
    return {
        (path, method)
        for path, item in spec["paths"].items()
        for method in item
        if method in methods
    }


def _operation_ids(spec: dict) -> list[str]:
    """Return operation identifiers in deterministic path and method order."""
    methods = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
    return [
        details["operationId"]
        for path in sorted(spec["paths"])
        for method, details in sorted(spec["paths"][path].items())
        if method in methods
    ]


def _public_definitions(module_name: str) -> set[str]:
    """Discover public classes, functions, and router assignments in a module."""
    source_path = BACKEND_ROOT / Path(*module_name.split("."))
    source_path = source_path.with_suffix(".py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    names = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
    }
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
            if any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    names.update(
                        item.value
                        for item in node.value.elts
                        if isinstance(item, ast.Constant) and isinstance(item.value, str)
                    )
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if any(isinstance(target, ast.Name) and target.id == "router" for target in targets):
            names.add("router")
    return names


def test_openapi_matches_checkpoint_snapshot() -> None:
    """Fail immediately if route paths or schemas drift during extraction."""
    baseline = _load_openapi_baseline()
    current = app.openapi()
    assert current == baseline


def test_openapi_routes_and_operation_ids_are_unique() -> None:
    """Guard against duplicate registration and duplicate operation identifiers."""
    spec = app.openapi()
    pairs = _operation_pairs(spec)
    operation_ids = _operation_ids(spec)
    assert len(pairs) == sum(
        1
        for item in spec["paths"].values()
        for method in item
        if method in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
    )
    assert len(operation_ids) == len(set(operation_ids))


def test_registered_module_exports_remain_importable() -> None:
    """Preserve public definitions while registered modules are split incrementally."""
    for module_name in REGISTERED_MODULES:
        module = importlib.import_module(module_name)
        missing = sorted(
            name for name in _public_definitions(module_name) if not hasattr(module, name)
        )
        assert not missing, f"{module_name} lost public exports: {missing}"
