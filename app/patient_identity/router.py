"""Compatibility facade for the patient identity routes.

The route implementations live under :mod:`app.patient_identity.routes`; this
module keeps the historical import path stable for the application and clients.
"""

from .routes import router
from .routes.authentication import (
    AcceptInvite,
    Login,
    VerificationCode,
    VerificationRequest,
    accept_invite,
    login,
    request_verification,
    verify_code,
)
from .routes.invites import (
    InviteInput,
    create_invite,
    patient_invites,
    resend_patient_invite,
    revoke_patient_invite,
)
from .routes.sessions import PasswordChange, change_password, logout, me, revoke_other_sessions, sessions

# Keep Pydantic's generated component names stable for clients that import the
# historical router module and for the OpenAPI compatibility snapshot.
for _model in (InviteInput, AcceptInvite, Login, VerificationRequest, VerificationCode, PasswordChange):
    _model.__module__ = __name__
    _model.model_rebuild(force=True)

__all__ = [
    "router",
    "InviteInput",
    "AcceptInvite",
    "Login",
    "VerificationRequest",
    "VerificationCode",
    "PasswordChange",
    "create_invite",
    "patient_invites",
    "resend_patient_invite",
    "revoke_patient_invite",
    "accept_invite",
    "login",
    "request_verification",
    "verify_code",
    "me",
    "sessions",
    "revoke_other_sessions",
    "change_password",
    "logout",
]
