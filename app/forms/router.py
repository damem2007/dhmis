from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.forms.models import FormSubmission, FormTemplate
from app.identity.service import db_session, permit
from app.patients.models import Patient

router = APIRouter(prefix="/forms", tags=["Digital forms"])


class TemplateInput(BaseModel):
    title: str = Field(min_length=2, max_length=180)
    version: str = Field(min_length=1, max_length=30)
    fields: list[dict]


@router.get("/templates")
async def templates(db=Depends(db_session), actor=Depends(permit("consents"))):
    rows = (await db.scalars(select(FormTemplate).order_by(FormTemplate.title, FormTemplate.version))).all()
    return [serialize(row) for row in rows]


@router.post("/templates", status_code=201)
async def create_template(
    body: TemplateInput, db=Depends(db_session), actor=Depends(permit("settings"))
):
    names = [str(field.get("name", "")) for field in body.fields]
    if not names or any(not name for name in names) or len(names) != len(set(names)):
        from fastapi import HTTPException

        raise HTTPException(422, "Form fields require unique names")
    row = await add(db, FormTemplate, body.model_dump(), actor.user_id)
    audit(db, actor.user_id, "create", "form_templates", row.id)
    return serialize(row)


@router.get("/submissions/{patient_id}")
async def submissions(
    patient_id: str, db=Depends(db_session), actor=Depends(permit("consents"))
):
    await required(db, Patient, patient_id)
    rows = (
        await db.scalars(
            select(FormSubmission).where(FormSubmission.patient_id == patient_id).order_by(FormSubmission.created_at.desc())
        )
    ).all()
    audit(db, actor.user_id, "read", "form_submissions", patient_id, patient_id=patient_id)
    return [serialize(row) for row in rows]
