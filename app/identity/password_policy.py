from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, Field


class PasswordPolicy(BaseModel):
    password_min_length: int = Field(default=12, ge=8, le=128)
    password_expiration_days: int = Field(default=0, ge=0, le=730)
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_number: bool = True
    password_require_special: bool = True


DEFAULT_PASSWORD_POLICY = PasswordPolicy().model_dump()


def effective_password_policy(value: dict | None) -> PasswordPolicy:
    return PasswordPolicy(**{**DEFAULT_PASSWORD_POLICY, **(value or {})})


def password_expired(password_changed_at: datetime | None, policy: PasswordPolicy, now: datetime | None = None) -> bool:
    expires_at = password_expiry_at(password_changed_at, policy)
    return bool(expires_at and (now or datetime.now(UTC)) >= expires_at)


def password_expiry_at(password_changed_at: datetime | None, policy: PasswordPolicy) -> datetime | None:
    """Return the UTC expiry instant for a local password, when enabled."""
    if policy.password_expiration_days <= 0 or password_changed_at is None:
        return None
    changed = password_changed_at
    if changed.tzinfo is None:
        changed = changed.replace(tzinfo=UTC)
    return changed.astimezone(UTC) + timedelta(days=policy.password_expiration_days)


def password_expiry_days_remaining(
    password_changed_at: datetime | None,
    policy: PasswordPolicy,
    now: datetime | None = None,
) -> int | None:
    """Return a calendar-day countdown rounded up while the password is valid."""
    expires_at = password_expiry_at(password_changed_at, policy)
    if expires_at is None:
        return None
    remaining_seconds = (expires_at - (now or datetime.now(UTC))).total_seconds()
    return max(0, int((remaining_seconds + 86399) // 86400))


def validate_password(password: str, policy: PasswordPolicy) -> str | None:
    if len(password) < policy.password_min_length:
        return f"Password must be at least {policy.password_min_length} characters"
    if policy.password_require_uppercase and not any(char.isupper() for char in password):
        return "Password must include an uppercase letter"
    if policy.password_require_lowercase and not any(char.islower() for char in password):
        return "Password must include a lowercase letter"
    if policy.password_require_number and not any(char.isdigit() for char in password):
        return "Password must include a number"
    if policy.password_require_special and not any(not char.isalnum() for char in password):
        return "Password must include a special character"
    return None
