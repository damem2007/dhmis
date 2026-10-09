from datetime import datetime

from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class PermissionRegistryRecord(Base):
    __tablename__ = "permission_registry"
    __table_args__ = {"schema": "dhmis_control"}

    key: Mapped[str] = mapped_column(String(180), primary_key=True)
    domain: Mapped[str] = mapped_column(String(20), primary_key=True, index=True)
    module_id: Mapped[str] = mapped_column(String(20))
    module_name: Mapped[str] = mapped_column(String(180))
    resource_key: Mapped[str] = mapped_column(String(140), index=True)
    resource_name: Mapped[str] = mapped_column(String(180))
    action: Mapped[str] = mapped_column(String(80))
    action_group: Mapped[str] = mapped_column(String(20))
    risk: Mapped[int] = mapped_column(Integer)
    restricted: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=True)
    retired: Mapped[bool] = mapped_column(Boolean, default=False)
    requires: Mapped[list] = mapped_column(JSON, default=list)
    valid_scopes: Mapped[list] = mapped_column(JSON, default=list)
    registry_version: Mapped[str] = mapped_column(String(40))
    source_digest: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str] = mapped_column(String(100), default="registry-sync")


class PlatformRole(Record, Base):
    __tablename__ = "platform_roles"
    __table_args__ = (
        CheckConstraint("domain = 'platform'", name="ck_platform_role_domain"),
        Index("ix_platform_roles_status", "status"),
        {"schema": "dhmis_control"},
    )
    domain: Mapped[str] = mapped_column(String(20), default="platform")
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(String(1000), default="")
    status: Mapped[str] = mapped_column(String(20), default="draft")
    parent_id: Mapped[str | None] = mapped_column(
        ForeignKey("dhmis_control.platform_roles.id"), nullable=True
    )
    locked: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)


class PlatformRoleGrant(Record, Base):
    __tablename__ = "platform_role_grants"
    __table_args__ = (
        Index("uq_platform_role_grant", "role_id", "permission_key", unique=True),
        CheckConstraint("scope = 'Platform'", name="ck_platform_grant_scope"),
        {"schema": "dhmis_control"},
    )
    role_id: Mapped[str] = mapped_column(ForeignKey("dhmis_control.platform_roles.id"))
    permission_key: Mapped[str] = mapped_column(String(180))
    effect: Mapped[str] = mapped_column(String(10))
    scope: Mapped[str] = mapped_column(String(20))
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)


class PlatformRoleAssignment(Record, Base):
    __tablename__ = "platform_role_assignments"
    __table_args__ = (
        Index("uq_platform_role_assignment", "user_id", "role_id", unique=True),
        CheckConstraint("level = 'Platform'", name="ck_platform_assignment_level"),
        {"schema": "dhmis_control"},
    )
    user_id: Mapped[str] = mapped_column(String(36))
    role_id: Mapped[str] = mapped_column(ForeignKey("dhmis_control.platform_roles.id"))
    level: Mapped[str] = mapped_column(String(20), default="Platform")
    location_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TenantRole(Record, Base):
    __tablename__ = "tenant_roles"
    __table_args__ = (
        CheckConstraint("domain = 'tenant'", name="ck_tenant_role_domain"),
        Index("ix_tenant_roles_status", "status"),
        {"schema": "tenant"},
    )
    domain: Mapped[str] = mapped_column(String(20), default="tenant")
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(String(1000), default="")
    status: Mapped[str] = mapped_column(String(20), default="draft")
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("tenant.tenant_roles.id"), nullable=True)
    locked: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)


class TenantRoleGrant(Record, Base):
    __tablename__ = "tenant_role_grants"
    __table_args__ = (
        Index("uq_tenant_role_grant", "role_id", "permission_key", unique=True),
        CheckConstraint(
            "scope IN ('Organization','Location','Assigned','Own')",
            name="ck_tenant_grant_scope",
        ),
        {"schema": "tenant"},
    )
    role_id: Mapped[str] = mapped_column(ForeignKey("tenant.tenant_roles.id"))
    permission_key: Mapped[str] = mapped_column(String(180))
    effect: Mapped[str] = mapped_column(String(10))
    scope: Mapped[str] = mapped_column(String(20))
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)


class TenantRoleAssignment(Record, Base):
    __tablename__ = "tenant_role_assignments"
    __table_args__ = (
        Index(
            "uq_tenant_role_organization_assignment",
            "user_id",
            "role_id",
            unique=True,
            postgresql_where=text("level = 'Organization'"),
        ),
        Index(
            "uq_tenant_role_location_assignment",
            "user_id",
            "role_id",
            "location_id",
            unique=True,
            postgresql_where=text("level = 'Location'"),
        ),
        CheckConstraint(
            "(level = 'Organization' AND location_id IS NULL) OR "
            "(level = 'Location' AND location_id IS NOT NULL)",
            name="ck_tenant_role_assignment_reach",
        ),
        {"schema": "tenant"},
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    role_id: Mapped[str] = mapped_column(ForeignKey("tenant.tenant_roles.id"))
    level: Mapped[str] = mapped_column(String(20))
    location_id: Mapped[str | None] = mapped_column(
        ForeignKey("tenant.locations.id"), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PlatformChangeRequest(Record, Base):
    __tablename__ = "platform_change_requests"
    __table_args__ = (
        Index("ix_platform_change_request_status_expiry", "status", "expires_at"),
        {"schema": "dhmis_control"},
    )
    domain: Mapped[str] = mapped_column(String(20), default="platform")
    kind: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    maker_id: Mapped[str] = mapped_column(String(36), index=True)
    reason: Mapped[str] = mapped_column(String(1000))
    patch: Mapped[list] = mapped_column(JSON, default=list)
    risk: Mapped[int] = mapped_column(Integer, default=1)
    affected_users: Mapped[int] = mapped_column(Integer, default=0)
    required_approvals: Mapped[int] = mapped_column(Integer, default=1)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    break_glass: Mapped[bool] = mapped_column(Boolean, default=False)
    role_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    role_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    runtime_permission_key: Mapped[str | None] = mapped_column(String(180), nullable=True)
    runtime_payload: Mapped[dict] = mapped_column(JSON, default=dict)
    governing_rule_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    approval_context: Mapped[dict] = mapped_column(JSON, default=dict)


class PlatformChangeDecision(Record, Base):
    __tablename__ = "platform_change_decisions"
    __table_args__ = (
        Index("uq_platform_change_decision", "request_id", "user_id", unique=True),
        {"schema": "dhmis_control"},
    )
    request_id: Mapped[str] = mapped_column(
        ForeignKey("dhmis_control.platform_change_requests.id")
    )
    user_id: Mapped[str] = mapped_column(String(36))
    decision: Mapped[str] = mapped_column(String(10))
    comment: Mapped[str] = mapped_column(String(2000), default="")
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PlatformChangeNotificationReceipt(Record, Base):
    __tablename__ = "platform_change_notification_receipts"
    __table_args__ = (
        Index("uq_platform_change_notification_receipt", "user_id", "request_id", unique=True),
        {"schema": "dhmis_control"},
    )
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    request_id: Mapped[str] = mapped_column(
        ForeignKey("dhmis_control.platform_change_requests.id")
    )
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PlatformPolicyVersion(Record, Base):
    __tablename__ = "platform_policy_versions"
    __table_args__ = {"schema": "dhmis_control"}
    version: Mapped[int] = mapped_column(Integer, index=True)
    author_id: Mapped[str] = mapped_column(String(36))
    approver_ids: Mapped[list] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(String(1000))
    changes: Mapped[list] = mapped_column(JSON, default=list)
    break_glass: Mapped[bool] = mapped_column(Boolean, default=False)


class PlatformApprovalPolicy(Record, Base):
    __tablename__ = "platform_approval_policy"
    __table_args__ = {"schema": "dhmis_control"}
    settings: Mapped[dict] = mapped_column(JSON, default=dict)


class PlatformFourEyesRule(Record, Base):
    __tablename__ = "platform_four_eyes_rules"
    __table_args__ = (
        Index("uq_platform_four_eyes_priority", "priority", unique=True),
        {"schema": "dhmis_control"},
    )
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(180))
    scope: Mapped[str] = mapped_column(String(20))
    priority: Mapped[int] = mapped_column(Integer)
    patterns: Mapped[list] = mapped_column(JSON, default=list)


class PlatformSoDRule(Record, Base):
    __tablename__ = "platform_sod_rules"
    __table_args__ = {"schema": "dhmis_control"}
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    message: Mapped[str] = mapped_column(String(1000))
    side_a: Mapped[list] = mapped_column(JSON, default=list)
    side_b: Mapped[list] = mapped_column(JSON, default=list)


class TenantChangeRequest(Record, Base):
    __tablename__ = "tenant_change_requests"
    __table_args__ = (
        Index("ix_tenant_change_request_status_expiry", "status", "expires_at"),
        {"schema": "tenant"},
    )
    domain: Mapped[str] = mapped_column(String(20), default="tenant")
    kind: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    maker_id: Mapped[str] = mapped_column(String(36), index=True)
    reason: Mapped[str] = mapped_column(String(1000))
    patch: Mapped[list] = mapped_column(JSON, default=list)
    risk: Mapped[int] = mapped_column(Integer, default=1)
    affected_users: Mapped[int] = mapped_column(Integer, default=0)
    required_approvals: Mapped[int] = mapped_column(Integer, default=1)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    break_glass: Mapped[bool] = mapped_column(Boolean, default=False)
    role_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    role_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    runtime_permission_key: Mapped[str | None] = mapped_column(String(180), nullable=True)
    runtime_payload: Mapped[dict] = mapped_column(JSON, default=dict)
    governing_rule_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    approval_context: Mapped[dict] = mapped_column(JSON, default=dict)


class TenantChangeDecision(Record, Base):
    __tablename__ = "tenant_change_decisions"
    __table_args__ = (
        Index("uq_tenant_change_decision", "request_id", "user_id", unique=True),
        {"schema": "tenant"},
    )
    request_id: Mapped[str] = mapped_column(ForeignKey("tenant.tenant_change_requests.id"))
    user_id: Mapped[str] = mapped_column(String(36))
    decision: Mapped[str] = mapped_column(String(10))
    comment: Mapped[str] = mapped_column(String(2000), default="")
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TenantChangeNotificationReceipt(Record, Base):
    __tablename__ = "tenant_change_notification_receipts"
    __table_args__ = (
        Index("uq_tenant_change_notification_receipt", "user_id", "request_id", unique=True),
        {"schema": "tenant"},
    )
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    request_id: Mapped[str] = mapped_column(
        ForeignKey("tenant.tenant_change_requests.id")
    )
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TenantPolicyVersion(Record, Base):
    __tablename__ = "tenant_policy_versions"
    __table_args__ = {"schema": "tenant"}
    version: Mapped[int] = mapped_column(Integer, index=True)
    author_id: Mapped[str] = mapped_column(String(36))
    approver_ids: Mapped[list] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(String(1000))
    changes: Mapped[list] = mapped_column(JSON, default=list)
    break_glass: Mapped[bool] = mapped_column(Boolean, default=False)


class TenantApprovalPolicy(Record, Base):
    __tablename__ = "tenant_approval_policy"
    __table_args__ = {"schema": "tenant"}
    settings: Mapped[dict] = mapped_column(JSON, default=dict)


class TenantFourEyesRule(Record, Base):
    __tablename__ = "tenant_four_eyes_rules"
    __table_args__ = (
        Index("uq_tenant_four_eyes_priority", "priority", unique=True),
        {"schema": "tenant"},
    )
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(180))
    scope: Mapped[str] = mapped_column(String(20))
    priority: Mapped[int] = mapped_column(Integer)
    patterns: Mapped[list] = mapped_column(JSON, default=list)


class TenantSoDRule(Record, Base):
    __tablename__ = "tenant_sod_rules"
    __table_args__ = {"schema": "tenant"}
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    message: Mapped[str] = mapped_column(String(1000))
    side_a: Mapped[list] = mapped_column(JSON, default=list)
    side_b: Mapped[list] = mapped_column(JSON, default=list)
