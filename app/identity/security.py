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


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Vault:
    def __init__(self, key):
        self.key = key
        self.aes = AESGCM(key)

    def seal(self, value):
        nonce = os.urandom(12)
        return base64.urlsafe_b64encode(nonce + self.aes.encrypt(nonce, value.encode(), b"dhmis-v1")).decode()

    def open(self, value):
        raw = base64.urlsafe_b64decode(value)
        return self.aes.decrypt(raw[:12], raw[12:], b"dhmis-v1").decode()

    def fingerprint(self, value):
        return hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()


def totp(secret_value, counter=None):
    counter = int(time.time() // 30) if counter is None else counter
    key = base64.b32decode(secret_value)
    raw = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = raw[-1] & 15
    return str((struct.unpack(">I", raw[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)


def verify_totp(secret_value, code, last_counter=-1):
    for counter in [int(time.time() // 30) - 1, int(time.time() // 30), int(time.time() // 30) + 1]:
        if counter > last_counter and hmac.compare_digest(totp(secret_value, counter), str(code)):
            return counter
    return None


def vault():
    return Vault(base64.urlsafe_b64decode(settings().vault_key.get_secret_value()))
