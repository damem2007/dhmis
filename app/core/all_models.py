# Explicit registration for migrations. Domain models stay in their own modules.
from app.analytics.models import AnalyticsActionItem
from app.billing.models import Invoice, LedgerEntry, Service
from app.care_coordination.models import LabCase, Referral
from app.claims.models import Claim
from app.clinical.models import ChartEntry, PerioExam, RecordAddendum
from app.cms.models import CmsMediaAsset, CmsPublicationPointer, CmsRevision
from app.consents.models import Consent
from app.core.audit import AuditEvent
from app.documents.models import Document
from app.forms.models import FormSubmission, FormTemplate
from app.identity.models import (
    PasswordResetChallenge,
    StaffInviteAssignment,
    StaffLocationAssignment,
    StaffUser,
)
from app.integrations.models import (
    AdapterCustomizationRequest,
    PlatformAdapterDefault,
    TenantAdapterOverride,
)
from app.messaging.models import Message, MessageThread
from app.notifications.models import OutboxMessage
from app.operations.models import ProviderCredential
from app.organizations.models import (
    Location,
    Organization,
    PlatformCommercialAccount,
    PlatformConfiguration,
    TenantSettings,
)
from app.patient_identity.models import (
    PatientInvite,
    PatientSession,
    PatientUser,
    PatientVerificationChallenge,
)
from app.patients.models import Patient
from app.platform_identity.models import (
    PlatformAuditEvent,
    PlatformChallenge,
    PlatformInvite,
    PlatformOutboxMessage,
    PlatformPasswordResetChallenge,
    PlatformSession,
    PlatformUser,
)
from app.prescriptions.models import MedicationSafetyRule, Prescription
from app.regions.models import PlatformRegion
from app.rbac.models import (
    PermissionRegistryRecord,
    PlatformApprovalPolicy,
    PlatformChangeDecision,
    PlatformChangeRequest,
    PlatformFourEyesRule,
    PlatformPolicyVersion,
    PlatformRole,
    PlatformRoleAssignment,
    PlatformRoleGrant,
    PlatformSoDRule,
    TenantApprovalPolicy,
    TenantChangeDecision,
    TenantChangeRequest,
    TenantFourEyesRule,
    TenantPolicyVersion,
    TenantRole,
    TenantRoleAssignment,
    TenantRoleGrant,
    TenantSoDRule,
    PlatformChangeNotificationReceipt,
    TenantChangeNotificationReceipt,
)
from app.scheduling.models import Appointment
from app.surgery.models import DaySurgeryAdmission

__all__ = [
    "Appointment",
    "AnalyticsActionItem",
    "AuditEvent",
    "ChartEntry",
    "RecordAddendum",
    "Claim",
    "CmsMediaAsset",
    "CmsPublicationPointer",
    "CmsRevision",
    "Consent",
    "Invoice",
    "LabCase",
    "LedgerEntry",
    "Location",
    "Organization",
    "PlatformCommercialAccount",
    "PlatformConfiguration",
    "TenantSettings",
    "OutboxMessage",
    "ProviderCredential",
    "Patient",
    "PerioExam",
    "Service",
    "StaffUser",
    "PasswordResetChallenge",
    "StaffLocationAssignment",
    "StaffInviteAssignment",
    "Referral",
    "MedicationSafetyRule",
    "Prescription",
    "PermissionRegistryRecord",
    "PlatformApprovalPolicy",
    "PlatformChangeDecision",
    "PlatformChangeRequest",
    "PlatformFourEyesRule",
    "PlatformPolicyVersion",
    "PlatformRole",
    "PlatformRoleAssignment",
    "PlatformRoleGrant",
    "PlatformSoDRule",
    "TenantApprovalPolicy",
    "TenantChangeDecision",
    "TenantChangeRequest",
    "TenantFourEyesRule",
    "TenantPolicyVersion",
    "TenantRole",
    "TenantRoleAssignment",
    "TenantRoleGrant",
    "TenantSoDRule",
    "PlatformChangeNotificationReceipt",
    "TenantChangeNotificationReceipt",
    "DaySurgeryAdmission",
    "Document",
    "FormSubmission",
    "FormTemplate",
    "Message",
    "MessageThread",
    "PatientInvite",
    "PatientSession",
    "PatientUser",
    "PatientVerificationChallenge",
    "PlatformAuditEvent",
    "PlatformChallenge",
    "PlatformInvite",
    "PlatformOutboxMessage",
    "PlatformPasswordResetChallenge",
    "PlatformSession",
    "PlatformUser",
    "PlatformRegion",
    "AdapterCustomizationRequest",
    "PlatformAdapterDefault",
    "TenantAdapterOverride",
]

from app.billing.models import FeeVersion, JournalLine, PaymentPlan
from app.claims.models import InsurancePlan
from app.clinical.models import Encounter, TreatmentPlan
from app.identity.models import AuthChallenge, AuthRateLimit, StaffInvite, StaffSession
from app.patients.models import GuardianLink

__all__ += [
    "AuthChallenge",
    "StaffSession",
    "StaffInvite",
    "AuthRateLimit",
    "GuardianLink",
    "Encounter",
    "TreatmentPlan",
    "FeeVersion",
    "PaymentPlan",
    "JournalLine",
    "InsurancePlan",
]
