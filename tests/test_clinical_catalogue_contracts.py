"""Contract checks for tenant catalogue, Quick chart, and quote boundaries."""

from pathlib import Path

from app.clinical.schemas import CatalogueItemInput, ClinicalChartSettingsInput, QuickChartSetInput, QuoteInput
from app.rbac.registry import load_approved_registry


def test_clinical_catalogue_inputs_are_tenant_owned_and_ordered():
    """Keep catalogue item types, Quick chart ordering, and quote selection explicit."""
    item = CatalogueItemInput(item_type="treatment", code="FILL", name="Filling")
    quick = QuickChartSetInput(name="Routine", items=["FILL", "FILL", "XRAY"])
    quote = QuoteInput(option_index=0)
    assert item.item_type == "treatment"
    assert quick.items == ["FILL", "FILL", "XRAY"]
    assert quote.option_index == 0


def test_chart_only_catalogue_items_cannot_link_a_service_or_fee():
    """Conditions are chart context; only procedures participate in billing."""
    import pytest

    with pytest.raises(ValueError, match="Only treatment/procedure entries"):
        CatalogueItemInput(item_type="condition", code="CARIES", name="Caries", service_id="service-123")
    item = CatalogueItemInput(item_type="condition", code="CARIES", name="Caries")
    assert item.service_id is None
    assert item.fee_source == "none"
    assert item.fee_cents == 0


def test_quick_chart_is_condition_only():
    """Only condition entries can be exposed as odontogram Quick chart shortcuts."""
    assert CatalogueItemInput(item_type="condition", code="CARIES", name="Caries", quick_chart=True).quick_chart
    assert not CatalogueItemInput(item_type="treatment", code="FILL", name="Filling", quick_chart=True).quick_chart
    assert not CatalogueItemInput(item_type="tooth_status", code="PRESENT", name="Present", quick_chart=True).quick_chart


def test_condition_resolution_is_condition_centric_and_archiving_keeps_mappings():
    """Resolution setup belongs to conditions and catalogue archive is independent."""
    router = (Path(__file__).parents[1] / "app/clinical/router.py").read_text()
    settings = (Path(__file__).parents[2] / "back-office/src/apps/back-office/TreatmentCatalogueSettings.tsx").read_text()
    assert '@router.put("/catalogue/{identifier}/resolution-links")' in router
    assert 'Resolution mappings are managed from Condition setup' in router
    assert "Unlink or reassign active catalogue dependencies before archiving" not in router
    assert "Resolved by these procedures" in settings
    assert "onChange({ condition_ids:" not in settings
    assert "/condition-links" not in settings


def test_clinical_catalogue_migration_is_generic_and_permissioned():
    """Ensure the catalogue migration applies to every tenant schema."""
    migration = Path(__file__).parents[1] / "migrations/versions/0040_clinical_catalogue_quotes.py"
    source = migration.read_text()
    assert 'schema == "dhmis_control"' in source
    assert "treatment_catalogue_items" in source
    assert "quick_chart_sets" in source
    assert "quotes" in source
    registry = load_approved_registry()
    for key in (
        "clinical.treatment_catalogue_item.read",
        "clinical.quick_chart_set.use",
        "reports.quote.recalculate",
    ):
        assert ("tenant", key) in registry.permissions


def test_quote_reconciliation_uses_latest_non_superseded_revision():
    """Keep reconciliation aligned with immutable quote revision semantics."""
    source = (Path(__file__).parents[1] / "app/reporting/router.py").read_text()
    assert 'func.max(Quote.version)' in source
    assert 'Quote.status != "superseded"' in source


def test_chart_settings_are_validated_and_migration_is_generic():
    """Keep chart preferences tenant-owned and prevent invalid dentition ranges."""
    settings = ClinicalChartSettingsInput(
        save_mode="manual",
        enabled_numbering_systems=["universal", "fdi"],
        default_numbering_system="universal",
        dentition_age_ranges={"primary_max_years": None, "mixed_max_years": None},
    )
    assert settings.default_numbering_system in settings.enabled_numbering_systems
    migration = Path(__file__).parents[1] / "migrations/versions/0042_clinical_chart_settings.py"
    source = migration.read_text()
    assert 'schema == "dhmis_control"' in source
    assert "tenant_settings" in source
