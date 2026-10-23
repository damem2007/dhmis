"""Static contracts for patient data encryption at rest."""

from pathlib import Path

from sqlalchemy import inspect

from app.core.secure_fields import EncryptedDate, EncryptedJSON, EncryptedText
from app.notifications.models import OutboxMessage
from app.patient_identity.models import PatientInvite, PatientUser, PatientVerificationChallenge
from app.patients.models import GuardianLink, Patient


def test_patient_phi_columns_use_authenticated_encryption_types():
    """Profile, guardian relationship, and portal contact fields are encrypted."""

    encrypted = {
        "first_name": EncryptedText,
        "last_name": EncryptedText,
        "birth_date": EncryptedDate,
        "email": EncryptedText,
        "phone": EncryptedText,
        "allergies": EncryptedJSON,
        "medical_history": EncryptedText,
        "dental_history": EncryptedText,
        "alerts": EncryptedJSON,
        "archive_reason": EncryptedText,
    }
    columns = {column.key: column.type for column in inspect(Patient).mapper.columns}
    assert all(isinstance(columns[name], type_) for name, type_ in encrypted.items())
    assert isinstance(inspect(GuardianLink).mapper.columns.relationship.type, EncryptedText)
    assert isinstance(inspect(PatientUser).mapper.columns.email.type, EncryptedText)
    assert isinstance(inspect(PatientInvite).mapper.columns.email.type, EncryptedText)
    assert isinstance(inspect(PatientVerificationChallenge).mapper.columns.email.type, EncryptedText)
    assert isinstance(inspect(OutboxMessage).mapper.columns.payload.type, EncryptedJSON)


def test_patient_encryption_migration_is_the_current_tenant_head():
    """The migration backfills legacy plaintext before replacing its columns."""

    migration = Path(__file__).parents[1] / "migrations/versions/0057_encrypt_patient_phi.py"
    source = migration.read_text()
    assert 'revision = "0057"' in source
    assert 'down_revision = "0056_password_expiry"' in source
    assert "_migrate_encrypted_columns(\n        \"patients\"" in source
    assert "DROP CONSTRAINT IF EXISTS patient_users_email_key" in source
