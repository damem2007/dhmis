import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")
    database_url: SecretStr
    jwt_secret: SecretStr
    bootstrap_key: SecretStr
    demo_password: SecretStr
    vault_key: SecretStr
    redis_url: str = "redis://127.0.0.1:6379/0"
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    allow_live_integrations: bool = False
    provider_options: Annotated[dict, NoDecode] = {}
    database_aliases: Annotated[dict[str, SecretStr], NoDecode] = {}
    environment: str = "development"
    platform_public_url: str = "http://192.168.1.68:5173"
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:3000",
        "http://192.168.1.68:5173",
        "http://192.168.1.68:5174",
        "http://192.168.1.68:5175",
        "http://192.168.1.68:3000",
    ]

    @field_validator("provider_options", mode="before")
    @classmethod
    def parse_provider_options(cls, value):
        return cls.parse_json_object("PROVIDER_OPTIONS", value)

    @field_validator("database_aliases", mode="before")
    @classmethod
    def parse_database_aliases(cls, value):
        return cls.parse_json_object("DATABASE_ALIASES", value)

    @classmethod
    def parse_json_object(cls, name, value):
        if isinstance(value, dict):
            return value
        raw = str(value).strip()
        if raw == "{":
            contents = (ROOT / ".env").read_text()
            raw = contents.split(name + "=", 1)[1].lstrip()
        try:
            result, _ = json.JSONDecoder().raw_decode(raw)
        except (json.JSONDecodeError, IndexError) as error:
            raise ValueError(f"{name} must be a JSON object") from error
        if not isinstance(result, dict):
            raise ValueError(f"{name} must be a JSON object")
        return result


@lru_cache
def settings():
    return Settings()
