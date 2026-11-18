"""Guard UUID primary keys and semantic identities for seeded records."""

from pathlib import Path
from uuid import UUID

from sqlalchemy import Uuid

from app.integrations.models import PlatformAdapterDefault
from app.organizations.models import (
    PlatformConfiguration,
    PlatformCommercialLedgerEntry,
    PlatformFeature,
    PlatformPlan,
    PlatformPlanCombination,
    PlatformPlanFeature,
    PlatformTenantAddon,
    TenantSettings,
)
from app.rbac.models import (
    PlatformApprovalPolicy,
    PlatformFourEyesRule,
    PlatformSoDRule,
    TenantApprovalPolicy,
    TenantFourEyesRule,
    TenantSoDRule,
)


def test_listed_seeded_models_use_independent_uuid_primary_keys():
    models = (
        PlatformAdapterDefault,
        PlatformApprovalPolicy,
        PlatformFourEyesRule,
        PlatformSoDRule,
        PlatformConfiguration,
        PlatformFeature,
        PlatformPlan,
        PlatformPlanFeature,
        PlatformPlanCombination,
        PlatformTenantAddon,
        PlatformCommercialLedgerEntry,
        TenantApprovalPolicy,
        TenantFourEyesRule,
        TenantSoDRule,
        TenantSettings,
    )
    for model in models:
        generated = model.__table__.c.id.default.arg(None)
        parsed = UUID(generated)
        assert str(parsed) == generated
        assert parsed.version == 4


def test_listed_primary_keys_are_uuid_columns_and_rules_keep_business_keys():
    models = (
        PlatformAdapterDefault,
        PlatformApprovalPolicy,
        PlatformFourEyesRule,
        PlatformSoDRule,
        PlatformConfiguration,
        PlatformFeature,
        PlatformPlan,
        PlatformPlanFeature,
        PlatformPlanCombination,
        PlatformTenantAddon,
        PlatformCommercialLedgerEntry,
        TenantApprovalPolicy,
        TenantFourEyesRule,
        TenantSoDRule,
        TenantSettings,
    )
    assert all(isinstance(model.__table__.c.id.type, Uuid) for model in models)
    assert PlatformFourEyesRule.__table__.c.key.unique
    assert PlatformSoDRule.__table__.c.key.unique
    assert TenantFourEyesRule.__table__.c.key.unique
    assert TenantSoDRule.__table__.c.key.unique
    assert PlatformApprovalPolicy.__table__.c.name.unique
    assert TenantApprovalPolicy.__table__.c.name.unique
    assert PlatformConfiguration.__table__.c.name.unique
    assert TenantSettings.__table__.c.name.unique


def test_historical_plan_assignment_migration_generates_independent_uuids():
    migration = (
        Path(__file__).parents[1] / "migrations" / "versions" / "0062_plan_visibility_and_comm_addons.py"
    ).read_text()
    assert 'id=f"{plan_id}-{feature_id}"' not in migration
    assert 'id=str(uuid4())' in migration
    assert 'stable_id(' not in migration


def test_revised_migrations_keep_alembic_versions_and_uuid_binds_compatible():
    versions = Path(__file__).parents[1] / "migrations" / "versions"
    for migration_path in versions.glob("*.py"):
        content = migration_path.read_text()
        for line in content.splitlines():
            if line.startswith("revision ="):
                revision = line.split('"')[1]
                assert len(revision) <= 32
    tenant_configuration = (versions / "0006_tenant_configuration.py").read_text()
    assert "CAST(:settings_id AS UUID)" in tenant_configuration
