"""Contract checks for tenant-owned licensed code-library boundaries."""

import base64

import pytest
from fastapi import HTTPException

from app.code_library.router import _decode_source, _safe_value
from app.code_library.schemas import ActivationInput, VersionImportInput
from app.rbac.registry import load_approved_registry


def test_code_library_permissions_are_assignable_and_region_scoped_by_registry():
    """Keep code-library capabilities in the shared registry for role assignment."""
    registry = load_approved_registry()
    required = {
        "clinical.code_library.read",
        "clinical.code_library.activate",
        "clinical.code_library.manage_licence",
        "clinical.code_library.upload",
        "clinical.code_library.import_version",
        "clinical.code_library.map_code",
        "clinical.code_library.review_retired",
        "clinical.code_library.deactivate",
    }
    assert required <= {
        key for domain, key in registry.permissions if domain == "tenant"
    }
    assert {
        scope.value
        for scope in registry.permissions[("tenant", "clinical.code_library.read")].valid_scopes
    } == {"Organization"}


def test_code_library_inputs_require_licence_attestation_and_version_rows():
    """Keep licence activation and version imports structurally explicit."""
    activation = ActivationInput(
        licence_holder="Clinic",
        licence_reference="LIC-1",
        attested=True,
    )
    version = VersionImportInput(
        version="2026.1",
        checksum="12345678",
        codes=[{"code": "D0001", "description": "Example"}],
    )
    assert activation.attested is True
    assert version.codes[0].code == "D0001"


def test_code_library_source_payload_is_validated_and_formula_values_rejected():
    """Keep source bytes tenant-owned and reject unsafe imported display values."""
    payload = base64.b64encode(b"code,description\nD0001,Example\n").decode()
    assert _decode_source("codes.csv", "text/csv", payload, len(b"code,description\nD0001,Example\n")) == b"code,description\nD0001,Example\n"
    assert _decode_source("codes.csv", "text/csv", "", 128) is None
    with pytest.raises(HTTPException):
        _decode_source("../codes.csv", "text/csv", payload)
    with pytest.raises(HTTPException):
        _decode_source("codes.csv", "text/csv", payload, 1)
    with pytest.raises(HTTPException):
        _safe_value("=HYPERLINK(\"https://example.invalid\")")
