"""Adapted from Ajo/platform/security.py: AES-GCM vault and replay-resistant TOTP.
AAD is intentionally DHMIS-specific; Ajo ciphertext is not interchangeable.
"""

import base64
import binascii
import hashlib
import hmac
import os
import struct
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings
from app.core.key_management import KeyManagementUnavailable, current_tenant_key


# Handle digest for this module.
def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


# Defines the vault model, contract, or value object.
class Vault:
    # Initialize the instance with its required state.
    def __init__(self, key, key_id=None, legacy_key=None, fallback_keys=()):
        self.key = key
        self.key_id = key_id
        self.legacy_key = legacy_key
        self.fallback_keys = dict(fallback_keys)
        self.aes = AESGCM(key)

    # Handle seal for this module.
    def seal(self, value):
        nonce = os.urandom(12)
        encrypted = base64.urlsafe_b64encode(
            nonce + self.aes.encrypt(nonce, value.encode(), b"dhmis-v1")
        ).decode()
        return f"dhmis-v2:{self.key_id}:{encrypted}" if self.key_id else encrypted

    # Handle open for this module.
    def open(self, value):
        if value.startswith("dhmis-v2:"):
            try:
                _, key_id, encoded = value.split(":", 2)
                raw = base64.urlsafe_b64decode(encoded)
            except (ValueError, binascii.Error) as error:
                raise KeyManagementUnavailable("Versioned ciphertext envelope is invalid") from error
            if key_id == self.key_id:
                return self.aes.decrypt(raw[:12], raw[12:], b"dhmis-v1").decode()
            fallback = self.fallback_keys.get(key_id)
            if fallback is None:
                raise KeyManagementUnavailable(f"Ciphertext requires unavailable tenant key {key_id}")
            return AESGCM(fallback).decrypt(raw[:12], raw[12:], b"dhmis-v1").decode()
        raw = base64.urlsafe_b64decode(value)
        try:
            return self.aes.decrypt(raw[:12], raw[12:], b"dhmis-v1").decode()
        except InvalidTag:
            # Existing rows use the application-wide VAULT_KEY.  Keep a
            # read-only compatibility path while those rows are migrated.
            if self.legacy_key is None:
                raise
            legacy = AESGCM(self.legacy_key)
            return legacy.decrypt(raw[:12], raw[12:], b"dhmis-v1").decode()

    # Handle fingerprint for this module.
    def fingerprint(self, value):
        # Keep lookup fingerprints on the legacy application key during the
        # migration window so existing email indexes remain searchable while
        # encrypted record bodies move to tenant-scoped DEKs.
        lookup_key = self.legacy_key or self.key
        return hmac.new(lookup_key, value.encode(), hashlib.sha256).hexdigest()


# Handle totp for this module.
def totp(secret_value, counter=None):
    counter = int(time.time() // 30) if counter is None else counter
    key = base64.b32decode(secret_value)
    raw = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = raw[-1] & 15
    return str((struct.unpack(">I", raw[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)


# Handle verify totp for this module.
def verify_totp(secret_value, code, last_counter=-1):
    for counter in [int(time.time() // 30) - 1, int(time.time() // 30), int(time.time() // 30) + 1]:
        if counter > last_counter and hmac.compare_digest(totp(secret_value, counter), str(code)):
            return counter
    return None


# Handle vault for this module.
def vault():
    material = current_tenant_key()
    if settings().vault_key is None:
        raise KeyManagementUnavailable("VAULT_KEY is required for legacy ciphertext migration")
    legacy_key = base64.urlsafe_b64decode(settings().vault_key.get_secret_value())
    if material is not None:
        return Vault(
            material.key,
            key_id=material.version,
            legacy_key=legacy_key,
            fallback_keys=material.fallback_keys,
        )
    return Vault(legacy_key)
