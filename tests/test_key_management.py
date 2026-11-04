"""Contract tests for the versioned envelope and legacy-read migration path."""

import os

import pytest
from cryptography.exceptions import InvalidTag

from app.core.key_management import KeyManagementUnavailable
from app.identity.security import Vault


def _key() -> bytes:
    return os.urandom(32)


def test_vault_seals_versioned_ciphertext_and_reads_it():
    vault = Vault(_key(), key_id="v1")

    ciphertext = vault.seal("tenant secret")

    assert ciphertext.startswith("dhmis-v2:v1:")
    assert vault.open(ciphertext) == "tenant secret"


def test_vault_dual_reads_legacy_ciphertext_with_legacy_key():
    legacy_key = _key()
    tenant_key = _key()
    legacy_ciphertext = Vault(legacy_key).seal("legacy secret")

    migrated = Vault(tenant_key, key_id="v1", legacy_key=legacy_key)

    assert migrated.open(legacy_ciphertext) == "legacy secret"
    assert migrated.fingerprint("same email") == Vault(legacy_key).fingerprint("same email")


def test_vault_rejects_ciphertext_for_another_key_version():
    ciphertext = Vault(_key(), key_id="v2").seal("secret")
    migrated = Vault(_key(), key_id="v1", legacy_key=_key())

    with pytest.raises(KeyManagementUnavailable, match="unavailable tenant key"):
        migrated.open(ciphertext)


def test_vault_reads_retained_tenant_key_during_rotation():
    old_key = _key()
    ciphertext = Vault(old_key, key_id="v1").seal("during rotation")
    migrated = Vault(_key(), key_id="v2", fallback_keys=(("v1", old_key),))

    assert migrated.open(ciphertext) == "during rotation"


def test_legacy_ciphertext_without_legacy_key_fails_authentication():
    legacy_ciphertext = Vault(_key()).seal("legacy secret")
    migrated = Vault(_key(), key_id="v1")

    with pytest.raises(InvalidTag):
        migrated.open(legacy_ciphertext)
