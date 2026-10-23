"""SQLAlchemy field types for application-level AES-GCM protected data.

The database stores only ciphertext for fields using these types.  Values are
decrypted by the application after the row has crossed the database boundary,
using the same tenant-scoped vault key used by secure messaging.
"""

import json
from datetime import date

from sqlalchemy.types import TEXT, TypeDecorator

from app.identity.security import vault


class EncryptedText(TypeDecorator):
    """Store a string as authenticated AES-GCM ciphertext."""

    impl = TEXT
    cache_ok = False

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return vault().seal(str(value))

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return vault().open(value)


class EncryptedDate(TypeDecorator):
    """Store an ISO date as authenticated AES-GCM ciphertext."""

    impl = TEXT
    cache_ok = False

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, date):
            raise TypeError("EncryptedDate values must be date instances")
        return vault().seal(value.isoformat())

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return date.fromisoformat(vault().open(value))


class EncryptedJSON(TypeDecorator):
    """Store JSON-compatible values as authenticated AES-GCM ciphertext."""

    impl = TEXT
    cache_ok = False

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return vault().seal(json.dumps(value, separators=(",", ":"), sort_keys=True))

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return json.loads(vault().open(value))


def normalized_email(value: str) -> str:
    """Normalize email addresses before hashing or encrypting them."""

    return value.strip().lower()


def email_lookup(value: str | None) -> str | None:
    """Return a keyed exact-match token without storing the email in plaintext."""

    if not value:
        return None
    return vault().fingerprint(normalized_email(value))
