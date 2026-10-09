"""
DHMIS access-policy model (Python backend authority), v0.3.

This module is the authoritative policy/domain model for RBAC evaluation.
It intentionally contains no FastAPI or SQLAlchemy dependencies so the
authorization engine can be unit-tested independently of transport/persistence.

The frontend may mirror DTOs/types for display, but must not implement or
override authorization decisions.

Permission identity:
    authorization domain = Domain.PLATFORM | Domain.TENANT
    permission key       = <module-or-namespace>.<resource>.<action>

Example:
    domain = Domain.TENANT
    key    = "billing.payment.refund"

Approved semantics:
- Read & Write = read + create + update only.
- Additional actions (archive, disable, refund, publish, etc.) are separate grants.
- A role may inherit from one parent; explicit deny wins.
- Scope is evaluated server-side.
- Four-eyes rules are ordered by explicit priority; lower number wins.
- Rule diagnostics expose Matches / Governed / Overlaps.
- Maker-checker approvers must belong to the same authorization domain.
- System/database/migration operations are outside web RBAC.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Literal, Mapping, Sequence

PermissionKey = str


# ============================================================
# Core enums / primitives
# ============================================================


class Domain(StrEnum):
    PLATFORM = "platform"
    TENANT = "tenant"


class Scope(StrEnum):
    PLATFORM = "Platform"
    ORGANIZATION = "Organization"
    LOCATION = "Location"
    ASSIGNED = "Assigned"
    OWN = "Own"


class Risk(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ActionGroup(StrEnum):
    READ = "read"
    CHANGE = "change"
    ACTION = "action"


class AccessLevel(StrEnum):
    NONE = "none"
    READ = "read"
    READ_WRITE = "readWrite"


class GrantEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class RoleStatus(StrEnum):
    DRAFT = "draft"
    PENDING = "pending"
    PUBLISHED = "published"
    INACTIVE = "inactive"
    ARCHIVED = "archived"


class RequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    APPLIED = "applied"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"
    CONFLICTED = "conflicted"


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class FourEyesScope(StrEnum):
    OFF = "Off"
    TENANT = "Tenant"
    PLATFORM = "Platform"
    BOTH = "Both"


class IssueCode(StrEnum):
    UNKNOWN_PERMISSION = "unknown_permission"
    WRONG_DOMAIN = "wrong_domain"
    INVALID_SCOPE = "invalid_scope"
    DEPENDENCY_UNMET = "dependency_unmet"
    SCOPE_WIDER_THAN_READ = "scope_wider_than_read"
    LOCKED_ROLE = "locked_role"
    INHERITANCE_CYCLE = "inheritance_cycle"
    WRONG_PARENT_DOMAIN = "wrong_parent_domain"
    RETIRED_PERMISSION = "retired_permission"
    UNREVIEWED_PERMISSION = "unreviewed_permission"


BASIC_ACTIONS: dict[AccessLevel, tuple[str, ...]] = {
    AccessLevel.NONE: (),
    AccessLevel.READ: ("read",),
    AccessLevel.READ_WRITE: ("read", "create", "update"),
}

DOMAIN_SCOPES: dict[Domain, tuple[Scope, ...]] = {
    Domain.PLATFORM: (Scope.PLATFORM,),
    Domain.TENANT: (
        Scope.ORGANIZATION,
        Scope.LOCATION,
        Scope.ASSIGNED,
        Scope.OWN,
    ),
}

REACH_SCOPES = frozenset({Scope.ORGANIZATION, Scope.LOCATION})
RELATIONSHIP_SCOPES = frozenset({Scope.ASSIGNED, Scope.OWN})

# Smaller number = broader reach. Assigned/Own are relationship filters; their
# ranks are used only for Read/Change/Action scope comparison and diagnostics.
SCOPE_RANK: dict[Scope, int] = {
    Scope.PLATFORM: 0,
    Scope.ORGANIZATION: 1,
    Scope.LOCATION: 2,
    Scope.ASSIGNED: 3,
    Scope.OWN: 4,
}

APPROVAL_EXPIRY_HOURS = (24, 48, 72, 168)
REJECTION_COMMENT_MIN_CHARS = 5
CHANGE_REASON_MIN_CHARS = 8


# ============================================================
# Registry/domain types
# ============================================================


@dataclass(frozen=True)
class ActionDefinition:
    action: str
    group: ActionGroup
    risk: Risk
    restricted: bool = False
    requires: tuple[str, ...] = ()
    risk_override: bool = False
    reviewed: bool = True
    retired: bool = False


@dataclass(frozen=True)
class ResourceDefinition:
    key: str
    name: str
    valid_scopes: tuple[Scope, ...]
    actions: tuple[ActionDefinition, ...]
    reviewed: bool = True
    retired: bool = False


@dataclass(frozen=True)
class ModuleDefinition:
    id: str
    domain: Domain
    name: str
    resources: tuple[ResourceDefinition, ...]


@dataclass(frozen=True)
class PermissionDefinition:
    key: PermissionKey
    domain: Domain
    module_id: str
    module_name: str
    resource_key: str
    resource_name: str
    action: str
    group: ActionGroup
    risk: Risk
    restricted: bool
    requires: tuple[str, ...]
    valid_scopes: tuple[Scope, ...]
    reviewed: bool = True
    retired: bool = False


# ============================================================
# Roles, grants and assignments
# ============================================================


@dataclass(frozen=True)
class Conditions:
    step_up_mfa_minutes: int | None = None
    requires_approval: bool | None = None
    expires_at: datetime | None = None
    ip_allow_list: tuple[str, ...] = ()


@dataclass(frozen=True)
class Grant:
    effect: GrantEffect
    scope: Scope
    conditions: Conditions | None = None


@dataclass
class Role:
    id: str
    name: str
    domain: Domain
    status: RoleStatus
    grants: dict[PermissionKey, Grant] = field(default_factory=dict)
    description: str | None = None
    parent_id: str | None = None
    locked: bool = False
    version: int = 1

    @property
    def assignable(self) -> bool:
        return self.status is RoleStatus.PUBLISHED


@dataclass(frozen=True)
class Assignment:
    user_id: str
    role_id: str
    level: Literal[
        Scope.PLATFORM,
        Scope.ORGANIZATION,
        Scope.LOCATION,
    ]
    location_id: str | None = None
    expires_at: datetime | None = None


# ============================================================
# Four-eyes + SoD
# ============================================================


@dataclass(frozen=True)
class FourEyesRule:
    id: str
    name: str
    scope: FourEyesScope
    priority: int
    patterns: tuple[str, ...]

    @property
    def enabled(self) -> bool:
        return self.scope is not FourEyesScope.OFF


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    rule_name: str
    priority: int
    governs: bool


@dataclass(frozen=True)
class RuleStats:
    matches: int
    governed: int
    overlaps: int


@dataclass(frozen=True)
class SoDRule:
    id: str
    message: str
    side_a: tuple[str, ...]
    side_b: tuple[str, ...]


# ============================================================
# Approval policy + requests
# ============================================================


@dataclass(frozen=True)
class ApprovalPolicy:
    require_role_grant_critical_or_four_eyes: bool = True
    require_high_risk_assignment: bool = True
    require_sod_conflict: bool = True
    require_every_change: bool = False
    require_superadmin_change: bool = True

    approvers_needed: Literal[1, 2] = 1
    expires_after_hours: int = 72

    tenant_eligible_roles: tuple[str, ...] = (
        "tenant-owner",
        "tenant-super-admin",
    )
    platform_eligible_roles: tuple[str, ...] = (
        "platform-super-admin",
    )

    break_glass_enabled: bool = True
    break_glass_requires_step_up_mfa: bool = True
    break_glass_review_within_hours: int = 24

    def __post_init__(self) -> None:
        if self.expires_after_hours not in APPROVAL_EXPIRY_HOURS:
            raise ValueError(
                f"expires_after_hours must be one of {APPROVAL_EXPIRY_HOURS}"
            )
        if self.approvers_needed not in (1, 2):
            raise ValueError("approvers_needed must be 1 or 2")


@dataclass(frozen=True)
class ChangePatch:
    role_id: str
    permission_key: PermissionKey | None = None
    new_grant: Grant | None = None
    publish: bool | None = None


@dataclass
class ChangeDecision:
    user_id: str
    decision: ApprovalDecision
    comment: str | None = None
    decided_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.decision is ApprovalDecision.REJECT:
            comment = (self.comment or "").strip()
            if len(comment) < REJECTION_COMMENT_MIN_CHARS:
                raise ValueError(
                    f"Rejection comment must be at least "
                    f"{REJECTION_COMMENT_MIN_CHARS} characters"
                )


@dataclass
class ChangeRequest:
    id: str
    domain: Domain
    kind: Literal[
        "role-policy",
        "role-publication",
        "role-assignment",
        "runtime-action",
    ]
    status: RequestStatus
    maker_id: str
    reason: str
    created_at: datetime
    expires_at: datetime
    required_approvals: Literal[1, 2]
    patch: tuple[ChangePatch, ...] = ()
    decisions: list[ChangeDecision] = field(default_factory=list)
    break_glass: bool = False
    role_version: int | None = None

    def __post_init__(self) -> None:
        if len(self.reason.strip()) < CHANGE_REASON_MIN_CHARS:
            raise ValueError(
                f"Change reason must be at least "
                f"{CHANGE_REASON_MIN_CHARS} characters"
            )


@dataclass(frozen=True)
class PolicyVersion:
    version: int
    author_id: str
    approver_ids: tuple[str, ...]
    reason: str
    changes: tuple["GrantChange", ...]
    created_at: datetime
    break_glass: bool = False


# ============================================================
# Decision / validation output
# ============================================================


Reach = Literal[Scope.PLATFORM, Scope.ORGANIZATION, Scope.LOCATION]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reach: Reach | None = None
    filter_scope: Literal[Scope.ASSIGNED, Scope.OWN] | None = None
    conditions: Conditions | None = None
    needs_approval: bool = False
    needs_step_up: bool = False
    governing_rule_id: str | None = None
    matching_rules: tuple[RuleMatch, ...] = ()
    trace: tuple[str, ...] = ()


@dataclass(frozen=True)
class Issue:
    key: str
    code: IssueCode
    message: str


@dataclass(frozen=True)
class GrantChange:
    key: PermissionKey
    before: Grant | None = None
    after: Grant | None = None


@dataclass
class PolicyContext:
    permissions: dict[PermissionKey, PermissionDefinition]
    roles: dict[str, Role]
    rules: list[FourEyesRule]
    sod_rules: list[SoDRule] = field(default_factory=list)
    permissions_by_resource: dict[str, list[PermissionDefinition]] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not self.permissions_by_resource:
            grouped: dict[str, list[PermissionDefinition]] = {}
            for permission in self.permissions.values():
                grouped.setdefault(permission.resource_key, []).append(permission)
            self.permissions_by_resource = grouped


# ============================================================
# Risk / dependency helpers
# ============================================================


CRITICAL_ACTIONS = frozenset(
    {
        "manage_permissions",
        "assign_permissions",
        "assign_role",
        "manage_roles",
        "impersonate_support_access",
        "close_account",
        "suspend",
        "suspend_account",
        "provision",
        "approve_override",
        "activate_override",
        "recover",
        "write_off",
        "reverse",
        "reset_mfa",
    }
)

HIGH_ACTIONS = frozenset(
    {
        "refund",
        "adjust",
        "merge_duplicate",
        "archive",
        "publish",
        "export",
        "reset_password",
        "revoke_sessions",
        "unlock_account",
        "approve",
        "finalize",
        "reopen",
        "add_addendum",
        "download",
        "share",
        "transfer_balance",
        "change_plan",
        "enable",
        "disable",
        "activate",
        "deactivate",
        "resume",
        "revoke",
        "restore",
        "reactivate_account",
    }
)

NEEDS_UPDATE = frozenset(
    {
        "archive",
        "restore",
        "activate",
        "deactivate",
        "enable",
        "disable",
        "reactivate",
        "suspend",
        "resume",
        "revoke",
        "assign",
        "unassign",
        "merge_duplicate",
        "finalize",
        "reopen",
        "add_addendum",
        "publish",
        "submit",
        "resubmit",
        "cancel",
        "reverse",
        "refund",
        "adjust",
        "write_off",
        "retry",
        "resend",
    }
)


def group_of(action: str) -> ActionGroup:
    if action == "read":
        return ActionGroup.READ
    if action in {"create", "update"}:
        return ActionGroup.CHANGE
    return ActionGroup.ACTION


def derive_risk(action: str, restricted: bool = False) -> Risk:
    if action in CRITICAL_ACTIONS:
        base = Risk.CRITICAL
    elif action in HIGH_ACTIONS:
        base = Risk.HIGH
    elif (
        action == "read"
        or action == "preview"
        or action.startswith("view")
        or action.startswith("refresh")
    ):
        base = Risk.LOW
    else:
        base = Risk.MEDIUM

    if restricted and base < Risk.HIGH:
        return Risk(base + 1)
    return base


def compute_requires(
    action: str,
    resource_actions: Sequence[str],
) -> tuple[str, ...]:
    available = set(resource_actions)

    if action in {"read", "create", "update"} or "read" not in available:
        return ()

    if action in NEEDS_UPDATE and "update" in available:
        return ("read", "update")

    return ("read",)


def default_valid_scopes(
    module_id: str,
    resource_name: str,
    domain: Domain,
) -> tuple[Scope, ...]:
    """
    Registry values are authoritative once stored. This helper only mirrors the
    v0.3 default derivation used when introducing a new registry resource.
    """
    if domain is Domain.PLATFORM:
        return (Scope.PLATFORM,)

    name = resource_name.lower()
    section = module_id.split(".", 1)[0]

    if re.search(
        r"role|permission|policy|organization|tenant record|brand|domain|"
        r"retention|numbering|integration",
        name,
    ):
        return (Scope.ORGANIZATION,)

    if module_id == "7.1":
        return (Scope.ORGANIZATION, Scope.LOCATION)

    if section == "3":
        if "location" in name:
            return (Scope.ORGANIZATION, Scope.LOCATION)
        return (Scope.ORGANIZATION, Scope.LOCATION, Scope.OWN)

    if section == "4":
        return (Scope.ORGANIZATION, Scope.LOCATION, Scope.ASSIGNED)

    if section == "5":
        if re.search(r"waitlist|recall|booking|public", name):
            return (Scope.ORGANIZATION, Scope.LOCATION)
        return (
            Scope.ORGANIZATION,
            Scope.LOCATION,
            Scope.ASSIGNED,
            Scope.OWN,
        )

    if section == "6":
        return (
            Scope.ORGANIZATION,
            Scope.LOCATION,
            Scope.ASSIGNED,
            Scope.OWN,
        )

    if section in {"7", "8"}:
        return (Scope.ORGANIZATION, Scope.LOCATION)

    if section == "10":
        return (Scope.ORGANIZATION,)

    if section in {"11", "13"}:
        return (Scope.ORGANIZATION, Scope.LOCATION, Scope.OWN)

    return (Scope.ORGANIZATION, Scope.LOCATION)


# ============================================================
# Exact four-eyes glob semantics
# ============================================================


RESTRICTED_ARCHIVE = "@restricted:archive"


def glob_to_regex(glob: str) -> re.Pattern[str]:
    """
    Exact v0.3 matcher semantics:
    - `*` matches zero or more characters inside ONE dot-separated segment.
    - `{a,b}` is alternation.
    - matching is anchored to the whole permission key.

    Example:
        billing.*.refund
    matches:
        billing.payment.refund
    but not:
        billing.card.payment.refund
    """
    out: list[str] = []
    i = 0

    while i < len(glob):
        ch = glob[i]

        if ch == "*":
            out.append(r"[^.]*")
            i += 1
            continue

        if ch == "{":
            end = glob.find("}", i + 1)
            if end == -1:
                raise ValueError(f"Unclosed alternation in pattern: {glob}")

            raw = glob[i + 1 : end]
            options = [item.strip() for item in raw.split(",") if item.strip()]
            if not options:
                raise ValueError(f"Empty alternation in pattern: {glob}")

            out.append(
                "(?:"
                + "|".join(re.escape(option) for option in options)
                + ")"
            )
            i = end + 1
            continue

        out.append(re.escape(ch))
        i += 1

    return re.compile("^" + "".join(out) + "$")


def pattern_matches(
    pattern: str,
    permission: PermissionDefinition,
) -> bool:
    if pattern == RESTRICTED_ARCHIVE:
        return permission.restricted and permission.action == "archive"

    return bool(glob_to_regex(pattern).match(permission.key))


def rule_applies_to_domain(
    rule: FourEyesRule,
    domain: Domain,
) -> bool:
    return (
        rule.scope is FourEyesScope.BOTH
        or (
            rule.scope is FourEyesScope.PLATFORM
            and domain is Domain.PLATFORM
        )
        or (
            rule.scope is FourEyesScope.TENANT
            and domain is Domain.TENANT
        )
    )


def matching_rules_for(
    permission: PermissionDefinition,
    rules: Sequence[FourEyesRule],
) -> list[FourEyesRule]:
    """
    Only ENABLED rules applicable to the permission's authorization domain
    participate in Matches / Governed / Overlaps.
    """
    matches = [
        rule
        for rule in rules
        if rule.enabled
        and rule_applies_to_domain(rule, permission.domain)
        and any(
            pattern_matches(pattern, permission)
            for pattern in rule.patterns
        )
    ]

    return sorted(matches, key=lambda rule: (rule.priority, rule.id))


def governing_rule_for(
    permission: PermissionDefinition,
    rules: Sequence[FourEyesRule],
) -> FourEyesRule | None:
    matches = matching_rules_for(permission, rules)
    return matches[0] if matches else None


def four_eyes_stats(
    rule: FourEyesRule,
    permissions: Mapping[PermissionKey, PermissionDefinition],
    rules: Sequence[FourEyesRule],
) -> RuleStats:
    matched = [
        permission
        for permission in permissions.values()
        if rule.enabled
        and rule_applies_to_domain(rule, permission.domain)
        and any(
            pattern_matches(pattern, permission)
            for pattern in rule.patterns
        )
    ]

    governed = 0
    overlaps = 0

    for permission in matched:
        matches = matching_rules_for(permission, rules)

        if len(matches) > 1:
            overlaps += 1

        if matches and matches[0].id == rule.id:
            governed += 1

    return RuleStats(
        matches=len(matched),
        governed=governed,
        overlaps=overlaps,
    )


def overlapping_rule_matches(
    permissions: Mapping[PermissionKey, PermissionDefinition],
    rules: Sequence[FourEyesRule],
) -> dict[PermissionKey, tuple[RuleMatch, ...]]:
    output: dict[PermissionKey, tuple[RuleMatch, ...]] = {}

    for permission in permissions.values():
        matches = matching_rules_for(permission, rules)

        if len(matches) < 2:
            continue

        governing = matches[0]

        output[permission.key] = tuple(
            RuleMatch(
                rule_id=rule.id,
                rule_name=rule.name,
                priority=rule.priority,
                governs=rule.id == governing.id,
            )
            for rule in matches
        )

    return output


# ============================================================
# Role inheritance / grant resolution
# ============================================================


def resolve_grant(
    role: Role,
    permission: PermissionDefinition,
    roles: Mapping[str, Role],
    *,
    seen: frozenset[str] = frozenset(),
) -> Grant | None:
    if permission.domain is not role.domain:
        return None

    if permission.retired or not permission.reviewed:
        return None

    if role.locked:
        # Locked Super Admin gets every active/reviewed permission in-domain.
        return Grant(
            effect=GrantEffect.ALLOW,
            scope=(
                Scope.PLATFORM
                if role.domain is Domain.PLATFORM
                else Scope.ORGANIZATION
            ),
        )

    direct = role.grants.get(permission.key)
    if direct is not None:
        return direct

    if role.parent_id is None:
        return None

    if role.id in seen:
        raise ValueError(f"Role inheritance cycle detected at {role.id}")

    parent = roles.get(role.parent_id)
    if parent is None:
        return None

    if parent.domain is not role.domain:
        raise ValueError(
            "Role cannot inherit from a role in another authorization domain"
        )

    return resolve_grant(
        parent,
        permission,
        roles,
        seen=seen | {role.id},
    )


def detect_inheritance_cycle(
    role: Role,
    roles: Mapping[str, Role],
) -> bool:
    seen: set[str] = set()
    current: Role | None = role

    while current is not None and current.parent_id is not None:
        if current.id in seen:
            return True
        seen.add(current.id)
        current = roles.get(current.parent_id)

    return current is not None and current.id in seen


# ============================================================
# Scope / assignment handling
# ============================================================


def active_assignments(
    assignments: Sequence[Assignment],
    roles: Mapping[str, Role],
    domain: Domain,
    *,
    now: datetime | None = None,
) -> list[Assignment]:
    now = now or datetime.now(UTC)
    result: list[Assignment] = []

    for assignment in assignments:
        role = roles.get(assignment.role_id)

        if role is None:
            continue
        if role.domain is not domain:
            continue
        if role.status is not RoleStatus.PUBLISHED:
            continue
        if assignment.expires_at and assignment.expires_at <= now:
            continue

        result.append(assignment)

    return result


def assignment_reach(assignment: Assignment) -> Reach:
    if assignment.level is Scope.PLATFORM:
        return Scope.PLATFORM
    if assignment.level is Scope.ORGANIZATION:
        return Scope.ORGANIZATION
    if assignment.level is Scope.LOCATION:
        return Scope.LOCATION
    raise ValueError("Assignments must use Platform/Organization/Location reach")


def effective_scope(
    grant_scope: Scope,
    assignment: Assignment,
) -> tuple[Reach, Literal[Scope.ASSIGNED, Scope.OWN] | None]:
    assigned_reach = assignment_reach(assignment)

    if grant_scope in RELATIONSHIP_SCOPES:
        return assigned_reach, grant_scope  # type: ignore[return-value]

    if grant_scope is Scope.PLATFORM:
        return Scope.PLATFORM, None

    rank = max(SCOPE_RANK[grant_scope], SCOPE_RANK[assigned_reach])

    for candidate in (
        Scope.ORGANIZATION,
        Scope.LOCATION,
    ):
        if SCOPE_RANK[candidate] == rank:
            return candidate, None

    raise ValueError(
        f"Cannot combine grant scope {grant_scope} "
        f"with assignment reach {assigned_reach}"
    )


def condition_allows(
    conditions: Conditions | None,
    *,
    now: datetime,
    current_ip: str | None,
) -> tuple[bool, str | None]:
    if conditions is None:
        return True, None

    if conditions.expires_at and conditions.expires_at <= now:
        return False, "grant condition has expired"

    if conditions.ip_allow_list:
        if not current_ip:
            return False, "grant requires an allowed IP address"

        address = ipaddress.ip_address(current_ip)
        allowed = False

        for raw in conditions.ip_allow_list:
            try:
                if "/" in raw:
                    if address in ipaddress.ip_network(raw, strict=False):
                        allowed = True
                        break
                elif address == ipaddress.ip_address(raw):
                    allowed = True
                    break
            except ValueError:
                # Invalid policy entries fail closed.
                continue

        if not allowed:
            return False, "IP address is outside the grant allow-list"

    return True, None


# ============================================================
# Effective-access evaluation
# ============================================================


def allowed_actions_for_resource(
    resource_permissions: Sequence[PermissionDefinition],
    assignments: Sequence[Assignment],
    ctx: PolicyContext,
) -> set[str]:
    allowed: set[str] = set()

    for permission in resource_permissions:
        any_allow = False
        any_deny = False

        for assignment in assignments:
            role = ctx.roles.get(assignment.role_id)
            if role is None:
                continue

            grant = resolve_grant(role, permission, ctx.roles)
            if grant is None:
                continue

            if grant.effect is GrantEffect.DENY:
                any_deny = True
            elif grant.scope in permission.valid_scopes:
                any_allow = True

        if any_allow and not any_deny:
            allowed.add(permission.action)

    return allowed


def decide(
    permission_key: PermissionKey,
    assignments: Sequence[Assignment],
    ctx: PolicyContext,
    *,
    now: datetime | None = None,
    mfa_age_minutes: int | None = None,
    current_ip: str | None = None,
) -> Decision:
    now = now or datetime.now(UTC)
    trace: list[str] = []

    permission = ctx.permissions.get(permission_key)

    if permission is None:
        return Decision(
            allowed=False,
            trace=("unknown permission",),
        )

    if permission.retired:
        return Decision(
            allowed=False,
            trace=("retired permission",),
        )

    if not permission.reviewed:
        return Decision(
            allowed=False,
            trace=("permission has not been reviewed",),
        )

    active = active_assignments(
        assignments,
        ctx.roles,
        permission.domain,
        now=now,
    )

    hits: list[
        tuple[
            Reach,
            Literal[Scope.ASSIGNED, Scope.OWN] | None,
            Grant,
            Role,
        ]
    ] = []

    for assignment in active:
        role = ctx.roles.get(assignment.role_id)
        if role is None:
            continue

        grant = resolve_grant(role, permission, ctx.roles)
        if grant is None:
            continue

        if grant.effect is GrantEffect.DENY:
            return Decision(
                allowed=False,
                trace=(
                    *trace,
                    f"{role.name} explicitly denies {permission.key}",
                ),
            )

        if grant.scope not in permission.valid_scopes:
            trace.append(
                f"{role.name}: ignored invalid scope {grant.scope}"
            )
            continue

        conditions_ok, why = condition_allows(
            grant.conditions,
            now=now,
            current_ip=current_ip,
        )

        if not conditions_ok:
            trace.append(f"{role.name}: {why}")
            continue

        reach, filter_scope = effective_scope(grant.scope, assignment)

        hits.append(
            (
                reach,
                filter_scope,
                grant,
                role,
            )
        )

        trace.append(
            f"{role.name} allows {permission.key} at {grant.scope}; "
            f"assignment reach {assignment.level} -> effective {reach}"
            + (
                f" with {filter_scope} filter"
                if filter_scope
                else ""
            )
        )

    if not hits:
        return Decision(
            allowed=False,
            trace=tuple(trace + ["no assigned role grants permission"]),
        )

    resource_permissions = ctx.permissions_by_resource.get(
        permission.resource_key,
        [],
    )

    available_actions = allowed_actions_for_resource(
        resource_permissions,
        active,
        ctx,
    )

    missing = [
        action
        for action in permission.requires
        if action not in available_actions
    ]

    if missing:
        return Decision(
            allowed=False,
            trace=tuple(
                trace
                + [
                    "missing dependency: "
                    + ", ".join(missing)
                ]
            ),
        )

    # Widest valid result wins:
    #   unfiltered > filtered, then broader reach.
    hits.sort(
        key=lambda hit: (
            1 if hit[1] else 0,
            SCOPE_RANK[hit[0]],
        )
    )

    reach, filter_scope, grant, _role = hits[0]

    step_up_minutes = (
        grant.conditions.step_up_mfa_minutes
        if grant.conditions
        else None
    )

    needs_step_up = (
        step_up_minutes is not None
        and (
            mfa_age_minutes is None
            or mfa_age_minutes > step_up_minutes
        )
    )

    matching_rules = matching_rules_for(permission, ctx.rules)
    governing = matching_rules[0] if matching_rules else None

    rule_matches = tuple(
        RuleMatch(
            rule_id=rule.id,
            rule_name=rule.name,
            priority=rule.priority,
            governs=governing is not None and rule.id == governing.id,
        )
        for rule in matching_rules
    )

    needs_approval = (
        governing is not None
        or bool(grant.conditions and grant.conditions.requires_approval)
    )

    return Decision(
        allowed=True,
        reach=reach,
        filter_scope=filter_scope,
        conditions=grant.conditions,
        needs_approval=needs_approval,
        needs_step_up=needs_step_up,
        governing_rule_id=governing.id if governing else None,
        matching_rules=rule_matches,
        trace=tuple(trace),
    )


# ============================================================
# Write-time validation
# ============================================================


def effective_allowed_keys(
    role: Role,
    ctx: PolicyContext,
) -> list[PermissionKey]:
    output: list[PermissionKey] = []

    for permission in ctx.permissions.values():
        if permission.domain is not role.domain:
            continue
        if permission.retired or not permission.reviewed:
            continue

        grant = resolve_grant(role, permission, ctx.roles)

        if grant and grant.effect is GrantEffect.ALLOW:
            output.append(permission.key)

    return sorted(output)


def validate_grants(
    role: Role,
    ctx: PolicyContext,
) -> list[Issue]:
    issues: list[Issue] = []

    if role.locked:
        return [
            Issue(
                key="*",
                code=IssueCode.LOCKED_ROLE,
                message="Super Admin roles cannot be edited",
            )
        ]

    if detect_inheritance_cycle(role, ctx.roles):
        issues.append(
            Issue(
                key="*",
                code=IssueCode.INHERITANCE_CYCLE,
                message="Role inheritance contains a cycle",
            )
        )

    if role.parent_id:
        parent = ctx.roles.get(role.parent_id)
        if parent and parent.domain is not role.domain:
            issues.append(
                Issue(
                    key="*",
                    code=IssueCode.WRONG_PARENT_DOMAIN,
                    message=(
                        "A role cannot inherit from another "
                        "authorization domain"
                    ),
                )
            )

    for key, grant in role.grants.items():
        permission = ctx.permissions.get(key)

        if permission is None:
            issues.append(
                Issue(
                    key=key,
                    code=IssueCode.UNKNOWN_PERMISSION,
                    message=f"{key} is not in the permission registry",
                )
            )
            continue

        if permission.retired:
            issues.append(
                Issue(
                    key=key,
                    code=IssueCode.RETIRED_PERMISSION,
                    message=f"{key} is retired",
                )
            )
            continue

        if not permission.reviewed:
            issues.append(
                Issue(
                    key=key,
                    code=IssueCode.UNREVIEWED_PERMISSION,
                    message=f"{key} has not been reviewed",
                )
            )
            continue

        if permission.domain is not role.domain:
            issues.append(
                Issue(
                    key=key,
                    code=IssueCode.WRONG_DOMAIN,
                    message=(
                        f"{key} belongs to {permission.domain.value}, "
                        f"not {role.domain.value}"
                    ),
                )
            )
            continue

        if grant.effect is not GrantEffect.ALLOW:
            continue

        if grant.scope not in permission.valid_scopes:
            issues.append(
                Issue(
                    key=key,
                    code=IssueCode.INVALID_SCOPE,
                    message=(
                        f"{grant.scope} is not valid for "
                        f"{permission.resource_name}"
                    ),
                )
            )

        synthetic_assignment = Assignment(
            user_id="__validation__",
            role_id=role.id,
            level=(
                Scope.PLATFORM
                if role.domain is Domain.PLATFORM
                else Scope.ORGANIZATION
            ),
        )

        available = allowed_actions_for_resource(
            ctx.permissions_by_resource.get(
                permission.resource_key,
                [],
            ),
            [synthetic_assignment],
            ctx,
        )

        missing = [
            action
            for action in permission.requires
            if action not in available
        ]

        if missing:
            issues.append(
                Issue(
                    key=key,
                    code=IssueCode.DEPENDENCY_UNMET,
                    message=(
                        f"{permission.action} requires "
                        f"{' and '.join(missing)} on "
                        f"{permission.resource_name}"
                    ),
                )
            )

        if permission.group is not ActionGroup.READ:
            read_permission = next(
                (
                    item
                    for item in ctx.permissions_by_resource.get(
                        permission.resource_key,
                        [],
                    )
                    if item.action == "read"
                ),
                None,
            )

            if read_permission is not None:
                read_grant = resolve_grant(
                    role,
                    read_permission,
                    ctx.roles,
                )

                if (
                    read_grant
                    and read_grant.effect is GrantEffect.ALLOW
                    and SCOPE_RANK[grant.scope]
                    < SCOPE_RANK[read_grant.scope]
                ):
                    issues.append(
                        Issue(
                            key=key,
                            code=IssueCode.SCOPE_WIDER_THAN_READ,
                            message=(
                                f"{permission.action} scope {grant.scope} "
                                f"is wider than Read scope "
                                f"{read_grant.scope}"
                            ),
                        )
                    )

    return issues


# ============================================================
# Separation of duties
# ============================================================


def find_conflicts(
    role: Role,
    ctx: PolicyContext,
    rules: Sequence[SoDRule] | None = None,
) -> list[str]:
    if role.locked:
        return []

    sod_rules = list(rules if rules is not None else ctx.sod_rules)
    permissions = [
        ctx.permissions[key]
        for key in effective_allowed_keys(role, ctx)
        if key in ctx.permissions
    ]

    def side_matches(patterns: Sequence[str]) -> bool:
        return any(
            pattern_matches(pattern, permission)
            for permission in permissions
            for pattern in patterns
        )

    return [
        f"{role.name} {rule.message}"
        for rule in sod_rules
        if side_matches(rule.side_a) and side_matches(rule.side_b)
    ]


# ============================================================
# Diff / patch / approval evaluation
# ============================================================


def diff_grants(
    before: Mapping[PermissionKey, Grant],
    after: Mapping[PermissionKey, Grant],
) -> list[GrantChange]:
    keys = sorted(set(before) | set(after))

    return [
        GrantChange(
            key=key,
            before=before.get(key),
            after=after.get(key),
        )
        for key in keys
        if before.get(key) != after.get(key)
    ]


def apply_patch(
    role: Role,
    patch: Sequence[ChangePatch],
) -> Role:
    grants = dict(role.grants)
    publish = role.status

    for change in patch:
        if change.permission_key is not None:
            if change.new_grant is None:
                grants.pop(change.permission_key, None)
            else:
                grants[change.permission_key] = change.new_grant

        if change.publish:
            publish = RoleStatus.PUBLISHED

    return replace(
        role,
        grants=grants,
        status=publish,
        version=role.version + 1,
    )


def requires_approval(
    changed_permissions: Sequence[PermissionDefinition],
    *,
    conflicts: int,
    touches_locked_role: bool,
    high_risk_assignment: bool,
    policy: ApprovalPolicy,
    rules: Sequence[FourEyesRule],
) -> bool:
    if (
        not changed_permissions
        and not touches_locked_role
        and not high_risk_assignment
    ):
        return False

    if touches_locked_role and policy.require_superadmin_change:
        return True

    if policy.require_every_change:
        return True

    if high_risk_assignment and policy.require_high_risk_assignment:
        return True

    if (
        policy.require_role_grant_critical_or_four_eyes
        and any(
            permission.risk is Risk.CRITICAL
            or governing_rule_for(permission, rules) is not None
            for permission in changed_permissions
        )
    ):
        return True

    if policy.require_sod_conflict and conflicts > 0:
        return True

    return False


# ============================================================
# Maker-checker eligibility
# ============================================================


def eligible_approver_roles(
    domain: Domain,
    policy: ApprovalPolicy,
) -> tuple[str, ...]:
    if domain is Domain.TENANT:
        return policy.tenant_eligible_roles

    return policy.platform_eligible_roles


def can_decide(
    request: ChangeRequest,
    *,
    user_id: str,
    user_domain: Domain,
    user_role_keys: set[str],
    policy: ApprovalPolicy,
    now: datetime | None = None,
) -> tuple[bool, str | None]:
    now = now or datetime.now(UTC)

    if request.status is not RequestStatus.PENDING:
        return False, "request is not pending"

    if request.domain is not user_domain:
        return (
            False,
            "approver belongs to a different authorization domain",
        )

    if request.maker_id == user_id:
        return False, "maker cannot approve own request"

    if any(
        decision.user_id == user_id
        for decision in request.decisions
    ):
        return False, "user has already decided"

    if request.expires_at <= now:
        return False, "request has expired"

    eligible_roles = set(
        eligible_approver_roles(request.domain, policy)
    )

    if not eligible_roles.intersection(user_role_keys):
        return (
            False,
            "user is not an eligible approver for this "
            "authorization domain",
        )

    return True, None


def apply_decision(
    request: ChangeRequest,
    decision: ChangeDecision,
    *,
    user_domain: Domain,
    user_role_keys: set[str],
    policy: ApprovalPolicy,
    now: datetime | None = None,
) -> ChangeRequest:
    allowed, reason = can_decide(
        request,
        user_id=decision.user_id,
        user_domain=user_domain,
        user_role_keys=user_role_keys,
        policy=policy,
        now=now,
    )

    if not allowed:
        raise PermissionError(reason or "approval decision is not allowed")

    request.decisions.append(decision)

    if decision.decision is ApprovalDecision.REJECT:
        request.status = RequestStatus.REJECTED
        return request

    approvals = sum(
        item.decision is ApprovalDecision.APPROVE
        for item in request.decisions
    )

    if approvals >= request.required_approvals:
        request.status = RequestStatus.APPLIED

    return request
