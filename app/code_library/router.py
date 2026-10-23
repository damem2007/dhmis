"""Tenant-owned code-library activation, import, lookup, and mapping APIs."""

import base64
import binascii
from pathlib import PurePath
from datetime import UTC, datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import exists, func, select

from app.billing.models import Service
from app.clinical.models import TreatmentCatalogueItem
from app.code_library.models import CodeLibraryActivation, CodeLibraryVersion, ProcedureCode, TreatmentCodeMapping
from app.code_library.schemas import ActivationInput, MappingInput, VersionImportInput
from app.core.audit import audit
from app.core.database import control_session
from app.core.repository import add, required, serialize
from app.identity.service import Actor, db_session
from app.regions.models import PlatformRegion, TenantCodeSetActivation
from app.rbac.dependencies import permit_tenant

router = APIRouter(prefix="/code-library", tags=["Tenant code library"])
ALLOWED_SOURCE_TYPES = {"text/csv", "application/json", ""}
MAX_SOURCE_BYTES = 50_000_000


def _decode_source(filename: str, mime_type: str, encoded: str, declared_size: int = 0) -> bytes | None:
    """Validate a tenant source file and return its decoded bytes."""
    if not filename and not encoded:
        if declared_size:
            raise HTTPException(422, "Code-library source size requires source content")
        return None
    if PurePath(filename).name != filename or filename in {"", ".", ".."}:
        raise HTTPException(422, "Source file name must be a simple file name")
    if mime_type not in ALLOWED_SOURCE_TYPES:
        raise HTTPException(422, "Unsupported code-library source type")
    # Older clients sent source metadata without uploading bytes. Preserve that
    # additive API contract while storing content whenever it is supplied.
    if not encoded:
        return None
    try:
        content = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(422, "Invalid code-library source content") from None
    if not content or len(content) > MAX_SOURCE_BYTES:
        raise HTTPException(422, "Code-library source must contain 1 byte to 50 MB")
    if declared_size and declared_size != len(content):
        raise HTTPException(422, "Code-library source size does not match its content")
    return content


def _safe_value(value: str) -> str:
    """Reject spreadsheet-formula prefixes before storing imported display values."""
    if value.lstrip().startswith(("=", "+", "-", "@")):
        raise HTTPException(422, "Code-library rows cannot contain spreadsheet formulas")
    return value


def _public(record):
    """Serialize code-library metadata without exposing licensed binaries."""
    result = serialize(record)
    result.pop("source_content", None)
    return result


async def configured_code_set_type(region: str) -> str:
    """Resolve a tenant region through the platform-owned region registry."""
    async with control_session() as control_db:
        return (
            await control_db.scalar(
                select(PlatformRegion.code_set_type).where(
                    PlatformRegion.code == region.upper(),
                    PlatformRegion.enabled.is_(True),
                )
            )
            or ""
        )


@router.get("/status")
async def status(db=Depends(db_session), actor: Actor = Depends(permit_tenant("clinical.code_library.read"))):
    """Return activation metadata and the mapped platform code-set type."""
    code_set_type = await configured_code_set_type(actor.organization.region)
    activation = await db.scalar(select(CodeLibraryActivation).where(CodeLibraryActivation.code_set_type == code_set_type)) if code_set_type else None
    return {"code_set_type": code_set_type or None, "activated": bool(activation and activation.status == "active"), "activation": _public(activation) if activation else None}


@router.post("/activate", status_code=201)
async def activate(body: ActivationInput, db=Depends(db_session), actor: Actor = Depends(permit_tenant("clinical.code_library.activate"))):
    """Store a tenant licence attestation and activate its mapped library."""
    code_set_type = await configured_code_set_type(actor.organization.region)
    if not code_set_type:
        raise HTTPException(422, "The tenant region has no supported procedure code set")
    if not body.attested:
        raise HTTPException(422, "A licence attestation is required before activation")
    existing = await db.scalar(select(CodeLibraryActivation).where(CodeLibraryActivation.code_set_type == code_set_type).with_for_update())
    content = _decode_source(body.source_file_name, body.source_mime_type, body.source_content_base64, body.source_file_size)
    values = {
        **body.model_dump(exclude={"source_content_base64"}),
        "source_content": content,
        "code_set_type": code_set_type,
        "status": "active",
        "activated_at": datetime.now(UTC),
        "activated_by": actor.user_id,
    }
    if existing:
        for key, value in values.items():
            setattr(existing, key, value)
        row = existing
    else:
        row = await add(db, CodeLibraryActivation, values, actor.user_id)
    audit(db, actor.user_id, "activate", "code_library", row.id, code_set_type=code_set_type)
    async with control_session() as control_db:
        summary = await control_db.scalar(select(TenantCodeSetActivation).where(TenantCodeSetActivation.organization_id == actor.organization.id).with_for_update())
        if summary is None:
            control_db.add(TenantCodeSetActivation(organization_id=actor.organization.id, code_set_type=code_set_type, active=True, last_status_changed_at=datetime.now(UTC), created_by=actor.user_id, updated_by=actor.user_id))
        else:
            summary.code_set_type = code_set_type
            summary.active = True
            summary.last_status_changed_at = datetime.now(UTC)
            summary.updated_by = actor.user_id
    return _public(row)


@router.post("/deactivate")
async def deactivate(db=Depends(db_session), actor: Actor = Depends(permit_tenant("clinical.code_library.deactivate"))):
    """Soft-deactivate the mapped tenant library while preserving history."""
    code_set_type = await configured_code_set_type(actor.organization.region)
    activation = await db.scalar(
        select(CodeLibraryActivation)
        .where(CodeLibraryActivation.code_set_type == code_set_type)
        .with_for_update()
    )
    if activation is None:
        raise HTTPException(404, "The tenant code library has not been activated")
    activation.status = "inactive"
    activation.updated_by = actor.user_id
    audit(db, actor.user_id, "deactivate", "code_library", activation.id, code_set_type=code_set_type)
    async with control_session() as control_db:
        summary = await control_db.scalar(
            select(TenantCodeSetActivation)
            .where(TenantCodeSetActivation.organization_id == actor.organization.id)
            .with_for_update()
        )
        if summary is not None:
            summary.active = False
            summary.last_status_changed_at = datetime.now(UTC)
            summary.updated_by = actor.user_id
    return _public(activation)


@router.post("/versions", status_code=201)
async def import_version(body: VersionImportInput, db=Depends(db_session), actor: Actor = Depends(permit_tenant("clinical.code_library.import_version"))):
    """Import an idempotent, non-destructive tenant code-library version."""
    code_set_type = await configured_code_set_type(actor.organization.region)
    activation = await db.scalar(select(CodeLibraryActivation).where(CodeLibraryActivation.code_set_type == code_set_type, CodeLibraryActivation.status == "active"))
    if activation is None:
        raise HTTPException(409, "Activate the tenant code library before importing a version")
    duplicate = await db.scalar(select(CodeLibraryVersion).where(CodeLibraryVersion.activation_id == activation.id, CodeLibraryVersion.version == body.version))
    if duplicate:
        return _public(duplicate)
    source_content = _decode_source(body.source_file_name, body.source_mime_type, body.source_content_base64, body.source_file_size)
    normalized = sorted({_safe_value(item.code.strip().upper()) for item in body.codes})
    if len(normalized) != len(body.codes):
        raise HTTPException(422, "Code values must be unique within a version")
    version = await add(db, CodeLibraryVersion, {"activation_id": activation.id, "version": body.version, "source_file_name": body.source_file_name, "source_file_size": body.source_file_size or len(source_content or b""), "source_mime_type": body.source_mime_type, "source_content": source_content, "imported_at": datetime.now(UTC), "imported_by": actor.user_id, "active": True}, actor.user_id)
    for item in body.codes:
        db.add(ProcedureCode(version_id=version.id, code=_safe_value(item.code.strip().upper()), description=_safe_value(item.description.strip()), category=_safe_value(item.category.strip()), status=item.status, retired_at=datetime.now(UTC) if item.status == "retired" else None, created_by=actor.user_id, updated_by=actor.user_id))
    await db.flush()
    audit(db, actor.user_id, "import-version", "code_library", version.id, version=body.version, count=len(body.codes))
    return {"version": _public(version), "codes": len(body.codes)}


@router.get("/versions")
async def versions(db=Depends(db_session), actor: Actor = Depends(permit_tenant("clinical.code_library.read"))):
    """List tenant-owned imported versions without exposing code content."""
    code_set_type = await configured_code_set_type(actor.organization.region)
    activation = await db.scalar(
        select(CodeLibraryActivation).where(CodeLibraryActivation.code_set_type == code_set_type)
    )
    if activation is None:
        return []
    rows = (
        await db.scalars(
            select(CodeLibraryVersion)
            .where(CodeLibraryVersion.activation_id == activation.id)
            .order_by(CodeLibraryVersion.imported_at.desc())
        )
    ).all()
    audit(db, actor.user_id, "read", "code_library_versions", count=len(rows))
    return [_public(row) for row in rows]


@router.get("/codes")
async def codes(
    q: str = Query("", max_length=120),
    category: str = Query("", max_length=120),
    mapping: str = Query("all", pattern="^(all|mapped|unmapped)$"),
    status: str = Query("all", pattern="^(all|active|retired)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=1000),
    db=Depends(db_session),
    actor: Actor = Depends(permit_tenant("clinical.code_library.read")),
):
    """Search active tenant-owned codes without exposing control-plane content."""
    code_set_type = await configured_code_set_type(actor.organization.region)
    activation = await db.scalar(select(CodeLibraryActivation).where(CodeLibraryActivation.code_set_type == code_set_type, CodeLibraryActivation.status == "active"))
    if activation is None:
        raise HTTPException(409, "The tenant code library is not activated")
    latest = await db.scalar(select(CodeLibraryVersion).where(CodeLibraryVersion.activation_id == activation.id).order_by(CodeLibraryVersion.imported_at.desc()))
    if latest is None:
        return {"items": [], "total": 0, "page": page, "page_size": page_size, "pages": 0}
    query = select(ProcedureCode).where(ProcedureCode.version_id == latest.id)
    if q.strip():
        needle = f"%{q.strip()}%"
        query = query.where(ProcedureCode.code.ilike(needle) | ProcedureCode.description.ilike(needle))
    if category.strip():
        query = query.where(ProcedureCode.category == category.strip())
    if status != "all":
        query = query.where(ProcedureCode.status == status)
    mapping_exists = exists().where(
        TreatmentCodeMapping.procedure_code_id == ProcedureCode.id,
        TreatmentCodeMapping.status == "active",
    )
    if mapping == "mapped":
        query = query.where(mapping_exists)
    elif mapping == "unmapped":
        query = query.where(~mapping_exists)
    total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (await db.scalars(query.order_by(ProcedureCode.code).offset((page - 1) * page_size).limit(page_size))).all()
    categories = (
        await db.scalars(
            select(ProcedureCode.category)
            .where(ProcedureCode.version_id == latest.id, ProcedureCode.category != "")
            .distinct()
            .order_by(ProcedureCode.category)
        )
    ).all()
    retired_total = await db.scalar(
        select(func.count()).select_from(ProcedureCode).where(
            ProcedureCode.version_id == latest.id,
            ProcedureCode.status == "retired",
        )
    ) or 0
    code_ids = [row.id for row in rows]
    mappings = []
    if code_ids:
        mappings = (
            await db.execute(
                select(TreatmentCodeMapping.procedure_code_id, TreatmentCatalogueItem.name, Service.name)
                .join(Service, Service.id == TreatmentCodeMapping.service_id)
                .outerjoin(
                    TreatmentCatalogueItem,
                    (TreatmentCatalogueItem.service_id == Service.id)
                    & (TreatmentCatalogueItem.item_type == "treatment"),
                )
                .where(
                    TreatmentCodeMapping.procedure_code_id.in_(code_ids),
                    TreatmentCodeMapping.status == "active",
                )
                .order_by(Service.name)
            )
        ).all()
    mapped_names: dict[str, list[str]] = {}
    for procedure_code_id, treatment_name, service_name in mappings:
        mapped_names.setdefault(procedure_code_id, []).append(treatment_name or service_name)
    mapped_names = {
        procedure_code_id: list(dict.fromkeys(names))
        for procedure_code_id, names in mapped_names.items()
    }
    audit(db, actor.user_id, "read", "code_library", latest.id, count=len(rows))
    return {
        "items": [
            {
                **serialize(row),
                "used_by_treatments": mapped_names.get(row.id, []),
            }
            for row in rows
        ],
        "categories": list(categories),
        "retired_total": retired_total,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.post("/mappings", status_code=201)
async def mapping(body: MappingInput, db=Depends(db_session), actor: Actor = Depends(permit_tenant("clinical.code_library.map_code"))):
    """Map an existing tenant service to an existing tenant procedure code."""
    await required(db, Service, body.service_id)
    code = await required(db, ProcedureCode, body.procedure_code_id)
    if code.status == "retired":
        raise HTTPException(409, "Retired codes require review before mapping")
    existing = await db.scalar(select(TreatmentCodeMapping).where(TreatmentCodeMapping.service_id == body.service_id, TreatmentCodeMapping.procedure_code_id == body.procedure_code_id))
    if existing:
        return serialize(existing)
    row = await add(db, TreatmentCodeMapping, {**body.model_dump(), "status": "active"}, actor.user_id)
    audit(db, actor.user_id, "map", "code_library", row.id, procedure_code_id=code.id)
    return serialize(row)
