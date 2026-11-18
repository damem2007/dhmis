import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]


# Defines the settings model, contract, or value object.
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BACKEND_ROOT / ".env", extra="ignore")
    database_url: SecretStr
    jwt_secret: SecretStr
    bootstrap_key: SecretStr
    demo_password: SecretStr
    # Legacy wrapping key retained for dual-read migration and local tests.
    vault_key: SecretStr | None = None
    key_provider: str = "local"
    key_provider_version: str = "v1"
    # AWS KMS can use the default boto3 credential chain; these identify the
    # customer-managed key and region without placing credentials in config.
    kms_key_id: str = ""
    kms_region: str = ""
    aws_kms_key_id: str = ""
    aws_kms_region: str = ""
    # Google Cloud KMS uses Application Default Credentials and a full key
    # resource name, for example projects/.../cryptoKeys/....
    gcp_kms_key_name: str = ""
    # Azure uses DefaultAzureCredential and a Key Vault key URL.
    azure_key_vault_key_url: str = ""
    # Vault Transit uses a token supplied through a secret manager at runtime.
    vault_transit_addr: str = ""
    vault_transit_mount: str = "transit"
    vault_transit_key: str = ""
    vault_transit_token: SecretStr | None = None
    vault_transit_namespace: str = ""
    redis_url: str = "redis://127.0.0.1:6379/0"
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    allow_live_integrations: bool = False
    provider_options: Annotated[dict, NoDecode] = {}
    database_aliases: Annotated[dict[str, SecretStr], NoDecode] = {}
    environment: str = "development"
    challenge_token_ttl: int = Field(default=300, gt=0)
    staff_session_ttl_seconds: int = Field(default=28800, gt=0)
    staff_idle_timeout_seconds: int = Field(default=3600, gt=0)
    # Roles & Access reads these values from the backend metadata endpoint so
    # every client uses the same refresh cadence and module batch size.
    rbac_catalogue_check_interval_seconds: int = Field(default=60, ge=15, le=3600)
    rbac_catalogue_modules_per_page: int = Field(default=5, ge=1, le=50)
    platform_public_url: str = "http://platform.dhmis.test:8080" #"http://192.168.1.68:5172"
    tenant_admin_public_url_template: str = "http://admin.{tenant_slug}.dhmis.test:5175"
    tenant_public_url_template: str = "http://{tenant_slug}.dhmis.test:8080"
    cors_origins: list[str] = [
        "http://localhost:5172",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://192.168.1.68:5172",
        "http://192.168.1.68:5173",
        "http://192.168.1.68:5174",
        "http://192.168.1.68:5175",
    ]

    # Handle parse provider options for this module.
    @field_validator("provider_options", mode="before")
    @classmethod
    def parse_provider_options(cls, value):
        return cls.parse_json_object("PROVIDER_OPTIONS", value)

    # Handle parse database aliases for this module.
    @field_validator("database_aliases", mode="before")
    @classmethod
    def parse_database_aliases(cls, value):
        return cls.parse_json_object("DATABASE_ALIASES", value)

    # Handle parse json object for this module.
    @classmethod
    def parse_json_object(cls, name, value):
        if isinstance(value, dict):
            return value
        raw = str(value).strip()
        if raw == "{":
            contents = (BACKEND_ROOT / ".env").read_text()
            raw = contents.split(name + "=", 1)[1].lstrip()
        try:
            result, _ = json.JSONDecoder().raw_decode(raw)
        except (json.JSONDecodeError, IndexError) as error:
            raise ValueError(f"{name} must be a JSON object") from error
        if not isinstance(result, dict):
            raise ValueError(f"{name} must be a JSON object")
        return result


# Handle settings for this module.
@lru_cache
def settings():
    return Settings()
