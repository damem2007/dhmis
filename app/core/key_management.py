"""Tenant encryption-key lifecycle and provider abstraction.

The application currently has a legacy ``VAULT_KEY`` ciphertext format.  This
module adds a versioned envelope and a per-organization data-encryption key
(DEK) without requiring a live KMS during local development. Production
deployments select one of the managed provider adapters and inject its
credentials through the deployment secret manager.
"""

import base64
import binascii
import secrets
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import settings
from app.organizations.models import OrganizationKey


class KeyManagementError(RuntimeError):
    """Base error for key-provider and tenant-key failures."""


class KeyManagementUnavailable(KeyManagementError):
    """Raised when encrypted data cannot be safely accessed."""


class KeyProvider(Protocol):
    """Contract implemented by local and managed key providers."""

    name: str
    version: str

    def health(self) -> dict: ...

    def wrap(self, plaintext_key: bytes) -> str: ...

    def unwrap(self, wrapped_key: str, version: str) -> bytes: ...


def _decode_key(raw: str | None, label: str) -> bytes:
    """Decode and validate a base64-encoded AES-256 key without logging it."""

    if not raw:
        raise KeyManagementUnavailable(f"{label} is not configured")
    try:
        value = base64.urlsafe_b64decode(raw.encode())
    except (binascii.Error, ValueError) as error:
        raise KeyManagementUnavailable(f"{label} is not valid base64") from error
    if len(value) != 32:
        raise KeyManagementUnavailable(f"{label} must decode to 32 bytes")
    return value


def _validate_dek(plaintext_key: bytes) -> None:
    """Require the fixed-size DEK used by every provider adapter."""

    if len(plaintext_key) != 32:
        raise KeyManagementError("Tenant DEKs must be 32 bytes")


def _provider_envelope(provider_name: str, version: str, payload: bytes) -> str:
    """Encode provider ciphertext without exposing provider response details."""

    encoded = base64.urlsafe_b64encode(payload).decode()
    return f"{provider_name}:{version}:{encoded}"


def _provider_payload(wrapped_key: str, provider_name: str, version: str) -> bytes:
    """Decode and validate a provider ciphertext envelope."""

    try:
        stored_provider, stored_version, encoded = wrapped_key.split(":", 2)
        if stored_provider != provider_name or stored_version != version:
            raise ValueError
        return base64.urlsafe_b64decode(encoded.encode())
    except (ValueError, binascii.Error) as error:
        raise KeyManagementUnavailable("Provider ciphertext envelope is invalid") from error


def _missing_dependency(package: str, provider_name: str, error: Exception) -> KeyManagementUnavailable:
    """Return an actionable error while keeping SDKs optional for local use."""

    result = KeyManagementUnavailable(f"{provider_name} provider requires the optional '{package}' package")
    result.__cause__ = error
    return result


class LocalKeyProvider:
    """Development provider that wraps DEKs with the configured local key.

    This provider is intentionally not a production KMS.  It exists so tests
    can exercise the same envelope and rotation contracts without credentials
    for a cloud service.
    """

    name = "local"

    def __init__(self):
        self.master_key = _decode_key(
            settings().vault_key.get_secret_value() if settings().vault_key else None,
            "VAULT_KEY",
        )
        self.version = settings().key_provider_version
        self.aes = AESGCM(self.master_key)

    def health(self) -> dict:
        return {"provider": self.name, "version": self.version, "ready": True, "mode": "development"}

    def wrap(self, plaintext_key: bytes) -> str:
        _validate_dek(plaintext_key)
        nonce = secrets.token_bytes(12)
        ciphertext = self.aes.encrypt(nonce, plaintext_key, b"dhmis-dek-v1")
        envelope = base64.urlsafe_b64encode(nonce + ciphertext).decode()
        return f"local:{self.version}:{envelope}"

    def unwrap(self, wrapped_key: str, version: str) -> bytes:
        try:
            provider, stored_version, encoded = wrapped_key.split(":", 2)
        except ValueError as error:
            raise KeyManagementUnavailable("Tenant key envelope is invalid") from error
        if provider != self.name or stored_version != version:
            raise KeyManagementUnavailable("Tenant key was created by an unavailable provider version")
        try:
            raw = base64.urlsafe_b64decode(encoded.encode())
            plaintext = self.aes.decrypt(raw[:12], raw[12:], b"dhmis-dek-v1")
        except (binascii.Error, ValueError, IndexError) as error:
            raise KeyManagementUnavailable("Tenant key envelope is invalid") from error
        except Exception as error:
            raise KeyManagementUnavailable("Tenant key cannot be unwrapped") from error
        if len(plaintext) != 32:
            raise KeyManagementUnavailable("Unwrapped tenant key has an invalid length")
        return plaintext


class AwsKMSProvider:
    """AWS KMS adapter using the standard boto3 credential chain."""

    name = "aws-kms"

    def __init__(self):
        try:
            import boto3
        except ImportError as error:
            raise _missing_dependency("boto3", self.name, error)
        self.key_id = settings().aws_kms_key_id or settings().kms_key_id
        self.region = settings().aws_kms_region or settings().kms_region
        if not self.key_id:
            raise KeyManagementUnavailable("AWS KMS requires AWS_KMS_KEY_ID or KMS_KEY_ID")
        self.version = settings().key_provider_version
        try:
            self.client = boto3.client("kms", region_name=self.region or None)
        except Exception as error:
            raise KeyManagementUnavailable("AWS KMS client could not be initialized") from error

    def health(self) -> dict:
        try:
            metadata = self.client.describe_key(KeyId=self.key_id)["KeyMetadata"]
            ready = metadata.get("KeyState") == "Enabled"
        except Exception as error:
            raise KeyManagementUnavailable("AWS KMS health check failed") from error
        return {"provider": self.name, "version": self.version, "ready": ready, "mode": "managed"}

    def wrap(self, plaintext_key: bytes) -> str:
        _validate_dek(plaintext_key)
        try:
            response = self.client.encrypt(
                KeyId=self.key_id,
                Plaintext=plaintext_key,
                EncryptionAlgorithm="SYMMETRIC_DEFAULT",
            )
            return _provider_envelope(self.name, self.version, response["CiphertextBlob"])
        except Exception as error:
            raise KeyManagementUnavailable("AWS KMS wrap failed") from error

    def unwrap(self, wrapped_key: str, version: str) -> bytes:
        payload = _provider_payload(wrapped_key, self.name, version)
        try:
            plaintext = self.client.decrypt(
                KeyId=self.key_id,
                CiphertextBlob=payload,
                EncryptionAlgorithm="SYMMETRIC_DEFAULT",
            )["Plaintext"]
        except Exception as error:
            raise KeyManagementUnavailable("AWS KMS unwrap failed") from error
        _validate_dek(plaintext)
        return plaintext


class GoogleCloudKMSProvider:
    """Google Cloud KMS adapter using Application Default Credentials."""

    name = "gcp-kms"

    def __init__(self):
        try:
            from google.cloud import kms_v1
        except ImportError as error:
            raise _missing_dependency("google-cloud-kms", self.name, error)
        self.key_name = settings().gcp_kms_key_name
        if not self.key_name:
            raise KeyManagementUnavailable("Google Cloud KMS requires GCP_KMS_KEY_NAME")
        self.version = settings().key_provider_version
        try:
            self.client = kms_v1.KeyManagementServiceClient()
        except Exception as error:
            raise KeyManagementUnavailable("Google Cloud KMS client could not be initialized") from error

    def health(self) -> dict:
        try:
            key = self.client.get_crypto_key(request={"name": self.key_name})
            ready = str(key.primary.state).upper().endswith("ENABLED")
        except Exception as error:
            raise KeyManagementUnavailable("Google Cloud KMS health check failed") from error
        return {"provider": self.name, "version": self.version, "ready": ready, "mode": "managed"}

    def wrap(self, plaintext_key: bytes) -> str:
        _validate_dek(plaintext_key)
        try:
            response = self.client.encrypt(request={"name": self.key_name, "plaintext": plaintext_key})
            return _provider_envelope(self.name, self.version, bytes(response.ciphertext))
        except Exception as error:
            raise KeyManagementUnavailable("Google Cloud KMS wrap failed") from error

    def unwrap(self, wrapped_key: str, version: str) -> bytes:
        payload = _provider_payload(wrapped_key, self.name, version)
        try:
            response = self.client.decrypt(request={"name": self.key_name, "ciphertext": payload})
            plaintext = bytes(response.plaintext)
        except Exception as error:
            raise KeyManagementUnavailable("Google Cloud KMS unwrap failed") from error
        _validate_dek(plaintext)
        return plaintext


class AzureKeyVaultProvider:
    """Azure Key Vault adapter using the DefaultAzureCredential chain."""

    name = "azure-key-vault"

    def __init__(self):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
            from azure.keyvault.keys.crypto import CryptographyClient
        except ImportError as error:
            raise _missing_dependency("azure-identity and azure-keyvault-keys", self.name, error)
        self.key_url = settings().azure_key_vault_key_url
        if not self.key_url:
            raise KeyManagementUnavailable("Azure Key Vault requires AZURE_KEY_VAULT_KEY_URL")
        parsed = urlparse(self.key_url)
        parts = [part for part in parsed.path.split("/") if part]
        if parsed.scheme != "https" or not parsed.netloc or len(parts) < 2 or parts[0] != "keys":
            raise KeyManagementUnavailable("AZURE_KEY_VAULT_KEY_URL must be an HTTPS key URL")
        self.vault_url = f"{parsed.scheme}://{parsed.netloc}"
        self.key_name = parts[1]
        self.key_version = parts[2] if len(parts) > 2 else None
        self.version = settings().key_provider_version
        try:
            credential = DefaultAzureCredential()
            self.key_client = KeyClient(vault_url=self.vault_url, credential=credential)
            key = self.key_client.get_key(self.key_name, version=self.key_version)
            self.client = CryptographyClient(key.id, credential)
        except Exception as error:
            raise KeyManagementUnavailable("Azure Key Vault client could not be initialized") from error

    def health(self) -> dict:
        try:
            self.key_client.get_key(self.key_name, version=self.key_version)
        except Exception as error:
            raise KeyManagementUnavailable("Azure Key Vault health check failed") from error
        return {"provider": self.name, "version": self.version, "ready": True, "mode": "managed"}

    def wrap(self, plaintext_key: bytes) -> str:
        _validate_dek(plaintext_key)
        try:
            from azure.keyvault.keys.crypto import KeyWrapAlgorithm

            result = self.client.wrap_key(KeyWrapAlgorithm.a256kw, plaintext_key)
            return _provider_envelope(self.name, self.version, bytes(result.encrypted_key))
        except Exception as error:
            raise KeyManagementUnavailable("Azure Key Vault wrap failed") from error

    def unwrap(self, wrapped_key: str, version: str) -> bytes:
        payload = _provider_payload(wrapped_key, self.name, version)
        try:
            from azure.keyvault.keys.crypto import KeyWrapAlgorithm

            result = self.client.unwrap_key(KeyWrapAlgorithm.a256kw, payload)
            plaintext = bytes(result.key)
        except Exception as error:
            raise KeyManagementUnavailable("Azure Key Vault unwrap failed") from error
        _validate_dek(plaintext)
        return plaintext


class VaultTransitProvider:
    """HashiCorp Vault Transit adapter using the configured Vault token."""

    name = "vault-transit"

    def __init__(self):
        try:
            import hvac
        except ImportError as error:
            raise _missing_dependency("hvac", self.name, error)
        config = settings()
        if not config.vault_transit_addr or not config.vault_transit_key:
            raise KeyManagementUnavailable("Vault Transit requires VAULT_TRANSIT_ADDR and VAULT_TRANSIT_KEY")
        if not config.vault_transit_token:
            raise KeyManagementUnavailable("Vault Transit requires VAULT_TRANSIT_TOKEN")
        try:
            self.client = hvac.Client(
                url=config.vault_transit_addr,
                token=config.vault_transit_token.get_secret_value(),
                namespace=config.vault_transit_namespace or None,
            )
        except Exception as error:
            raise KeyManagementUnavailable("Vault Transit client could not be initialized") from error
        self.mount = config.vault_transit_mount
        self.key_name = config.vault_transit_key
        self.version = config.key_provider_version

    def health(self) -> dict:
        try:
            self.client.secrets.transit.read_key(name=self.key_name, mount_point=self.mount)
        except Exception as error:
            raise KeyManagementUnavailable("Vault Transit health check failed") from error
        return {"provider": self.name, "version": self.version, "ready": True, "mode": "managed"}

    def wrap(self, plaintext_key: bytes) -> str:
        _validate_dek(plaintext_key)
        try:
            response = self.client.secrets.transit.encrypt_data(
                name=self.key_name,
                plaintext=base64.b64encode(plaintext_key).decode(),
                mount_point=self.mount,
            )
            ciphertext = response["data"]["ciphertext"].encode()
            return _provider_envelope(self.name, self.version, ciphertext)
        except Exception as error:
            raise KeyManagementUnavailable("Vault Transit wrap failed") from error

    def unwrap(self, wrapped_key: str, version: str) -> bytes:
        payload = _provider_payload(wrapped_key, self.name, version).decode()
        try:
            response = self.client.secrets.transit.decrypt_data(
                name=self.key_name,
                ciphertext=payload,
                mount_point=self.mount,
            )
            plaintext = base64.b64decode(response["data"]["plaintext"])
        except Exception as error:
            raise KeyManagementUnavailable("Vault Transit unwrap failed") from error
        _validate_dek(plaintext)
        return plaintext


def provider() -> KeyProvider:
    """Resolve the configured provider and fail closed for unsupported modes."""

    return _provider_for_name(settings().key_provider)


def _provider_for_name(name: str) -> KeyProvider:
    """Construct a configured provider by its persisted control-plane name."""

    selected = name.strip().lower()
    if selected == "local":
        return LocalKeyProvider()
    providers = {
        "aws": AwsKMSProvider,
        "aws-kms": AwsKMSProvider,
        "gcp": GoogleCloudKMSProvider,
        "gcp-kms": GoogleCloudKMSProvider,
        "google-cloud-kms": GoogleCloudKMSProvider,
        "azure": AzureKeyVaultProvider,
        "azure-key-vault": AzureKeyVaultProvider,
        "vault": VaultTransitProvider,
        "vault-transit": VaultTransitProvider,
    }
    selected_provider = providers.get(selected)
    if selected_provider is not None:
        return selected_provider()
    raise KeyManagementUnavailable(f"Unsupported KEY_PROVIDER: {selected}")


@dataclass(frozen=True)
class TenantKeyMaterial:
    """The active DEK and its non-secret control-plane metadata."""

    organization_id: str
    provider: str
    version: str
    key: bytes
    fallback_keys: tuple[tuple[str, bytes], ...] = ()


_tenant_key: ContextVar[TenantKeyMaterial | None] = ContextVar("dhmis_tenant_key", default=None)


@contextmanager
def use_tenant_key(material: TenantKeyMaterial):
    """Make one tenant DEK available to SQLAlchemy field adapters and routers."""

    marker = _tenant_key.set(material)
    try:
        yield
    finally:
        _tenant_key.reset(marker)


def current_tenant_key() -> TenantKeyMaterial | None:
    """Return the request/task-local tenant key, if a tenant session is active."""

    return _tenant_key.get()


async def ensure_tenant_key(organization_id: str, created_by: str = "system") -> OrganizationKey:
    """Create or return the active wrapped DEK for an organization."""

    from app.core.database import control_session

    async with control_session() as db:
        row = await db.scalar(
            select(OrganizationKey)
            .where(OrganizationKey.organization_id == organization_id, OrganizationKey.status == "active")
            .order_by(OrganizationKey.created_at.desc())
        )
        if row is not None:
            return row
        selected = provider()
        row = OrganizationKey(
            organization_id=organization_id,
            provider=selected.name,
            key_version=selected.version,
            provider_version=selected.version,
            wrapped_key=selected.wrap(secrets.token_bytes(32)),
            status="active",
            recovery_metadata={
                "created_at": datetime.now(UTC).isoformat(),
                "deletion_protection_required": True,
                "restore_test_status": "not_run",
            },
            created_by=created_by,
            updated_by=created_by,
        )
        db.add(row)
        await db.flush()
        return row


async def load_tenant_key(organization_id: str) -> TenantKeyMaterial:
    """Load and unwrap an organization's active DEK from the control plane."""

    from app.core.database import control_session

    row = await ensure_tenant_key(organization_id)
    selected = provider()
    if row.provider != selected.name:
        raise KeyManagementUnavailable("Tenant key provider does not match the configured provider")
    async with control_session() as db:
        retained = (
            await db.scalars(
                select(OrganizationKey)
                .where(
                    OrganizationKey.organization_id == organization_id,
                    OrganizationKey.status == "retired",
                )
                .order_by(OrganizationKey.created_at.desc())
            )
        ).all()
    fallback_keys = tuple(
        (
            old.key_version,
            _provider_for_name(old.provider).unwrap(
                old.wrapped_key, getattr(old, "provider_version", old.key_version)
            ),
        )
        for old in retained
    )
    return TenantKeyMaterial(
        organization_id=organization_id,
        provider=row.provider,
        version=row.key_version,
        key=selected.unwrap(row.wrapped_key, getattr(row, "provider_version", row.key_version)),
        fallback_keys=fallback_keys,
    )


def health() -> dict:
    """Return non-secret provider readiness information for health endpoints."""

    try:
        return provider().health()
    except KeyManagementError as error:
        return {"provider": settings().key_provider, "ready": False, "error": type(error).__name__}


def _next_dek_version(current: str) -> str:
    """Return a monotonic tenant-DEK version without exposing key material."""

    if current.startswith("v") and current[1:].isdigit():
        return f"v{int(current[1:]) + 1}"
    return f"v2-{secrets.token_hex(4)}"


async def rotate_tenant_keys(
    *,
    reencrypt: bool = True,
    rewrap_only: bool = False,
    organization_id: str | None = None,
    dry_run: bool = False,
    batch_size: int = 500,
) -> list[dict]:
    """Rotate tenant DEKs, optionally re-encrypting all tenant ciphertext.

    ``rewrap_only`` preserves the DEK and changes only its provider envelope.
    Normal rotation creates a new DEK, retires the previous row, and then
    rewrites encrypted patient, identity, outbox, and messaging values. The
    old wrapped row is retained for the configured retention period.
    """

    from app.core.database import control_session

    selected = provider()
    async with control_session() as db:
        query = select(OrganizationKey).where(OrganizationKey.status == "active")
        if organization_id:
            query = query.where(OrganizationKey.organization_id == organization_id)
        rows = (await db.scalars(query.order_by(OrganizationKey.created_at.desc()))).all()

    results: list[dict] = []
    for row in rows:
        provider_version = getattr(row, "provider_version", row.key_version)
        now = datetime.now(UTC).isoformat()
        if rewrap_only:
            previous_key = _provider_for_name(row.provider).unwrap(row.wrapped_key, provider_version)
            result = {"organization_id": row.organization_id, "operation": "rewrap", "status": "planned"}
            if not dry_run:
                async with control_session() as db:
                    current = await db.get(OrganizationKey, row.id)
                    if current is None or current.status != "active":
                        raise KeyManagementUnavailable("Tenant key changed during re-wrap")
                    current.wrapped_key = selected.wrap(previous_key)
                    current.provider = selected.name
                    current.provider_version = selected.version
                    current.updated_by = "key-rewrap"
                    current.recovery_metadata = {
                        **(current.recovery_metadata or {}),
                        "last_rewrapped_at": now,
                        "restore_test_status": "not_run",
                    }
                result["status"] = "rewrapped"
            results.append(result)
            continue

        next_version = _next_dek_version(row.key_version)
        result = {
            "organization_id": row.organization_id,
            "operation": "rotate",
            "previous_key_version": row.key_version,
            "key_version": next_version,
            "status": "planned",
        }
        if not dry_run:
            async with control_session() as db:
                current = await db.get(OrganizationKey, row.id)
                if current is None or current.status != "active":
                    raise KeyManagementUnavailable("Tenant key changed during rotation")
                current.status = "retired"
                current.updated_by = "key-rotation"
                current.recovery_metadata = {
                    **(current.recovery_metadata or {}),
                    "retired_at": now,
                    "replaced_by": next_version,
                }
                replacement = OrganizationKey(
                    organization_id=current.organization_id,
                    provider=selected.name,
                    key_version=next_version,
                    provider_version=selected.version,
                    wrapped_key=selected.wrap(secrets.token_bytes(32)),
                    status="active",
                    recovery_metadata={
                        "created_at": now,
                        "rotated_from": current.key_version,
                        "deletion_protection_required": True,
                        "restore_test_status": "not_run",
                    },
                    created_by="key-rotation",
                    updated_by="key-rotation",
                )
                db.add(replacement)
            if reencrypt:
                migration = await migrate_tenant_encryption(
                    organization_id=row.organization_id,
                    dry_run=False,
                    batch_size=batch_size,
                )
                result["reencryption"] = migration
                async with control_session() as db:
                    active = await db.scalar(
                        select(OrganizationKey).where(
                            OrganizationKey.organization_id == row.organization_id,
                            OrganizationKey.status == "active",
                        )
                    )
                    if active is not None:
                        counts = migration[0].get("counts", {}) if migration else {}
                        active.recovery_metadata = {
                            **(active.recovery_metadata or {}),
                            "last_reencrypted_at": datetime.now(UTC).isoformat(),
                            "reencryption_counts": counts,
                            "reencryption_status": "passed",
                        }
                        active.updated_by = "key-rotation"
            result["status"] = "rotated"
        results.append(result)
    return results


async def migrate_tenant_encryption(
    *, organization_id: str | None = None, dry_run: bool = False, batch_size: int = 500
) -> list[dict]:
    """Rewrite legacy and prior-version ciphertext under each active tenant DEK.

    The operation is idempotent and commits one tenant at a time. SQLAlchemy
    encrypted types decrypt on read and are explicitly marked dirty so their
    bind processors write a fresh versioned envelope. Messaging ciphertext is
    plain ``Text`` by design, so it is handled explicitly here.
    """

    from app.core.database import control_session, organization_session
    from app.messaging.models import Message
    from app.notifications.models import OutboxMessage
    from app.organizations.models import Organization
    from app.patient_identity.models import PatientInvite, PatientUser, PatientVerificationChallenge
    from app.patients.models import GuardianLink, Patient

    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    models = (Patient, GuardianLink, PatientUser, PatientInvite, PatientVerificationChallenge, OutboxMessage)
    async with control_session() as db:
        query = select(Organization).where(Organization.status != "deleted")
        if organization_id:
            query = query.where(Organization.id == organization_id)
        organizations = (await db.scalars(query.order_by(Organization.id))).all()

    results: list[dict] = []
    for organization in organizations:
        counts = {model.__name__: 0 for model in models}
        counts[Message.__name__] = 0
        async with organization_session(organization) as db:
            for model in models:
                offset = 0
                while True:
                    rows = (
                        await db.scalars(select(model).order_by(model.id).offset(offset).limit(batch_size))
                    ).all()
                    if not rows:
                        break
                    for row in rows:
                        for attribute in model.__table__.columns:
                            if attribute.type.__class__.__name__ not in {
                                "EncryptedText",
                                "EncryptedDate",
                                "EncryptedJSON",
                            }:
                                continue
                            value = getattr(row, attribute.name)
                            if value is not None:
                                counts[model.__name__] += 1
                                if not dry_run:
                                    setattr(row, attribute.name, value)
                                    flag_modified(row, attribute.name)
                    if not dry_run:
                        await db.flush()
                    offset += len(rows)
            offset = 0
            while True:
                messages = (
                    await db.scalars(select(Message).order_by(Message.id).offset(offset).limit(batch_size))
                ).all()
                if not messages:
                    break
                for message in messages:
                    if not message.body_cipher:
                        continue
                    # Re-seal every row so a previous tenant key or legacy VAULT_KEY
                    # envelope is replaced by the active tenant DEK.
                    from app.identity.security import vault

                    plaintext = vault().open(message.body_cipher)
                    counts[Message.__name__] += 1
                    if not dry_run:
                        message.body_cipher = vault().seal(plaintext)
                        flag_modified(message, "body_cipher")
                if not dry_run:
                    await db.flush()
                offset += len(messages)
        results.append({"organization_id": organization.id, "status": "planned" if dry_run else "migrated", "counts": counts})
    return results


async def run_recovery_test() -> list[dict]:
    """Exercise unwrap and re-encryption for every active tenant key.

    This is a provider/recovery hook, not a substitute for restoring a real
    encrypted database backup in an isolated environment.
    """

    from app.core.database import control_session

    selected = provider()
    now = datetime.now(UTC).isoformat()
    results: list[dict] = []
    async with control_session() as db:
        rows = (await db.scalars(select(OrganizationKey).where(OrganizationKey.status == "active"))).all()
        for row in rows:
            key = selected.unwrap(row.wrapped_key, getattr(row, "provider_version", row.key_version))
            probe = AESGCM(key)
            nonce = secrets.token_bytes(12)
            ciphertext = probe.encrypt(nonce, b"dhmis-recovery-probe", b"dhmis-recovery-v1")
            if probe.decrypt(nonce, ciphertext, b"dhmis-recovery-v1") != b"dhmis-recovery-probe":
                raise KeyManagementUnavailable("Recovery probe failed")
            row.recovery_metadata = {
                **(row.recovery_metadata or {}),
                "last_restore_test_at": now,
                "restore_test_status": "passed",
            }
            results.append({"organization_id": row.organization_id, "status": "passed"})
    return results


async def run_restore_test(restore_database_url: str) -> list[dict]:
    """Verify a read-only restored database can unwrap its tenant keys.

    Backup tooling remains deployment-specific. This hook accepts the restored
    database URL supplied by that tooling, reads only the control-plane key
    rows, and performs the same authenticated probe used by the live recovery
    check. It never writes to the restore target or prints the URL.
    """

    from sqlalchemy import text

    from app.core.database import build_engine

    if not restore_database_url:
        raise KeyManagementUnavailable("A restored database URL is required")
    restored_engine = build_engine(restore_database_url)
    selected = provider()
    results: list[dict] = []
    try:
        async with restored_engine.connect() as connection:
            rows = (
                await connection.execute(
                    text(
                        "SELECT organization_id, provider, key_version, provider_version, wrapped_key "
                        "FROM dhmis_control.organization_keys WHERE status = 'active'"
                    )
                )
            ).mappings().all()
            for row in rows:
                if row["provider"] != selected.name:
                    raise KeyManagementUnavailable("Restored tenant key provider does not match configuration")
                provider_version = row.get("provider_version") or row["key_version"]
                key = selected.unwrap(row["wrapped_key"], provider_version)
                probe = AESGCM(key)
                nonce = secrets.token_bytes(12)
                ciphertext = probe.encrypt(nonce, b"dhmis-restore-probe", b"dhmis-recovery-v1")
                if probe.decrypt(nonce, ciphertext, b"dhmis-recovery-v1") != b"dhmis-restore-probe":
                    raise KeyManagementUnavailable("Restored database recovery probe failed")
                results.append({"organization_id": row["organization_id"], "status": "passed"})
    finally:
        await restored_engine.dispose()
    return results
