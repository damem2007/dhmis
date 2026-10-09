import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from app.rbac.models import PermissionRegistryRecord
from app.rbac.policy import (
    ActionGroup,
    Domain,
    PermissionDefinition,
    Risk,
    Scope,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
APPROVED_REGISTRY_PATH = (
    REPOSITORY_ROOT
    / "docs"
    / "RBAC_complete_Suite_Approved"
    / "permission-registry.v0.3-approved (1).json"
)
PERMISSION_KEY = re.compile(r"^[a-z0-9_]+(?:\.[a-z0-9_]+){2,}$")


@dataclass(frozen=True)
class ApprovedRegistry:
    version: str
    source_digest: str
    permissions: dict[tuple[str, str], PermissionDefinition]
    raw: dict


def load_approved_registry(path: Path = APPROVED_REGISTRY_PATH) -> ApprovedRegistry:
    source = path.read_bytes()
    raw = json.loads(source)
    meta = raw.get("_meta", {})
    if meta.get("status") != "approved-policy-baseline":
        raise ValueError("Permission registry is not an approved policy baseline")
    permissions: dict[tuple[str, str], PermissionDefinition] = {}
    for module in raw.get("modules", []):
        domain = Domain(module["domain"])
        for resource in module.get("resources", []):
            scopes = tuple(Scope(scope) for scope in resource.get("validScopes", []))
            for action in resource.get("actions", []):
                key = f"{resource['key']}.{action['action']}"
                identity = (domain.value, key)
                if not PERMISSION_KEY.fullmatch(key) or identity in permissions:
                    raise ValueError(f"Invalid or duplicate approved permission key: {key}")
                permissions[identity] = PermissionDefinition(
                    key=key,
                    domain=domain,
                    module_id=module["id"],
                    module_name=module["name"],
                    resource_key=resource["key"],
                    resource_name=resource["name"],
                    action=action["action"],
                    group=ActionGroup(action["group"]),
                    risk=Risk(action["risk"]),
                    restricted=bool(action.get("restricted", False)),
                    requires=tuple(action.get("requires", [])),
                    valid_scopes=scopes,
                    reviewed=bool(action.get("reviewed", resource.get("reviewed", False))),
                    retired=bool(action.get("retired", resource.get("retired", False))),
                )
    expected = meta.get("counts", {}).get("permissions")
    if expected != len(permissions):
        raise ValueError(
            f"Approved registry count mismatch: metadata={expected}, parsed={len(permissions)}"
        )
    domains = {
        domain: sum(permission.domain.value == domain for permission in permissions.values())
        for domain in ("platform", "tenant")
    }
    for domain, count in domains.items():
        if meta.get("counts", {}).get(domain) != count:
            raise ValueError(f"Approved registry {domain} count mismatch")
    return ApprovedRegistry(
        version=meta["registryVersion"],
        source_digest=hashlib.sha256(source).hexdigest(),
        permissions=permissions,
        raw=raw,
    )


async def synchronize_permission_registry(db, actor_id: str = "registry-sync") -> dict:
    approved = load_approved_registry()
    existing = {
        (row.domain, row.key): row
        for row in (await db.scalars(select(PermissionRegistryRecord))).all()
    }
    now = datetime.now(UTC)
    inserted = updated = retired = 0
    for identity, permission in approved.permissions.items():
        domain, key = identity
        values = {
            "domain": domain,
            "module_id": permission.module_id,
            "module_name": permission.module_name,
            "resource_key": permission.resource_key,
            "resource_name": permission.resource_name,
            "action": permission.action,
            "action_group": permission.group.value,
            "risk": int(permission.risk),
            "restricted": permission.restricted,
            "reviewed": permission.reviewed,
            "retired": permission.retired,
            "requires": list(permission.requires),
            "valid_scopes": [scope.value for scope in permission.valid_scopes],
            "registry_version": approved.version,
            "source_digest": approved.source_digest,
        }
        row = existing.pop(identity, None)
        if row is None:
            db.add(
                PermissionRegistryRecord(
                    key=key,
                    created_at=now,
                    updated_at=now,
                    updated_by=actor_id,
                    **values,
                )
            )
            inserted += 1
        else:
            changed = any(getattr(row, field) != value for field, value in values.items())
            if changed:
                for field, value in values.items():
                    setattr(row, field, value)
                row.updated_at = now
                row.updated_by = actor_id
                updated += 1
    for row in existing.values():
        if not row.retired or row.reviewed:
            row.retired = True
            row.reviewed = False
            row.updated_at = now
            row.updated_by = actor_id
            retired += 1
    await db.flush()
    return {
        "version": approved.version,
        "source_digest": approved.source_digest,
        "permissions": len(approved.permissions),
        "inserted": inserted,
        "updated": updated,
        "retired": retired,
    }
