"""Adapted from Ajo/platform/security.py: AES-GCM vault and replay-resistant TOTP.
AAD is intentionally DHMIS-specific; Ajo ciphertext is not interchangeable.
"""

import base64
import hashlib
import hmac
import os
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings


# Handle digest for this module.
def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


# Defines the vault model, contract, or value object.
class Vault:
    # Initialize the instance with its required state.
    def __init__(self, key):
        self.key = key
        self.aes = AESGCM(key)

    # Handle seal for this module.
    def seal(self, value):
        nonce = os.urandom(12)
        return base64.urlsafe_b64encode(nonce + self.aes.encrypt(nonce, value.encode(), b"dhmis-v1")).decode()

    # Handle open for this module.
    def open(self, value):
        raw = base64.urlsafe_b64decode(value)
        return self.aes.decrypt(raw[:12], raw[12:], b"dhmis-v1").decode()

    # Handle fingerprint for this module.
    def fingerprint(self, value):
        return hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()


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
    return Vault(base64.urlsafe_b64decode(settings().vault_key.get_secret_value()))
