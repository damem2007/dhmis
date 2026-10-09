import base64
import binascii
import io

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.documents.models import Document
from app.identity.service import db_session, permit
from app.patients.models import Patient

router = APIRouter(prefix="/documents", tags=["Documents and imaging"])
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp", "application/pdf"}


class Upload(BaseModel):
    patient_id: str
    category: str = Field(pattern="^(image|document)$")
    filename: str = Field(min_length=1, max_length=220)
    mime_type: str
    content_base64: str
    description: str = Field(default="", max_length=500)
    comparison_group: str = Field(default="", max_length=80)


@router.post("", status_code=201)
async def upload(body: Upload, db=Depends(db_session), actor=Depends(permit("clinical"))):
    patient = await required(db, Patient, body.patient_id)
    if body.mime_type not in ALLOWED_TYPES:
        raise HTTPException(422, "Unsupported document type")
    try:
        content = base64.b64decode(body.content_base64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(422, "Invalid base64 document content") from None
    if not content or len(content) > 10 * 1024 * 1024:
        raise HTTPException(422, "Document must contain 1 byte to 10 MB")
    row = await add(
        db,
        Document,
        {
            "patient_id": patient.id,
            "location_id": patient.location_id,
            "category": body.category,
            "filename": body.filename,
            "mime_type": body.mime_type,
            "description": body.description,
            "comparison_group": body.comparison_group,
            "content": content,
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "upload", "documents", row.id, patient_id=patient.id)
    result = serialize(row)
    result.pop("content", None)
    return result


@router.get("/{patient_id}")
async def list_documents(patient_id: str, db=Depends(db_session), actor=Depends(permit("clinical"))):
    await required(db, Patient, patient_id)
    rows = (
        await db.scalars(select(Document).where(Document.patient_id == patient_id).order_by(Document.created_at.desc()))
    ).all()
    audit(db, actor.user_id, "read", "documents", patient_id, patient_id=patient_id)
    return [{key: value for key, value in serialize(row).items() if key != "content"} for row in rows]


@router.get("/file/{identifier}")
async def file(identifier: str, db=Depends(db_session), actor=Depends(permit("clinical"))):
    row = await required(db, Document, identifier)
    audit(db, actor.user_id, "download", "documents", row.id, patient_id=row.patient_id)
    return StreamingResponse(
        io.BytesIO(row.content),
        media_type=row.mime_type,
        headers={"Content-Disposition": f'inline; filename="{row.filename.replace(chr(34), "")}"'},
    )
