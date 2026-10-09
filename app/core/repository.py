from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.inspection import inspect


def serialize(record):
    return {column.key: getattr(record, column.key) for column in inspect(record).mapper.column_attrs}


async def required(db, model, identifier, lock=False):
    query = select(model).where(model.id == identifier)
    if lock:
        query = query.with_for_update()
    result = await db.scalar(query)
    if result is None:
        raise HTTPException(404, "Record not found")
    return result


async def add(db, model, values, actor):
    record = model(**values, created_by=actor, updated_by=actor)
    db.add(record)
    await db.flush()
    from app.billing.models import JournalLine, LedgerEntry

    if isinstance(record, LedgerEntry):
        contra = {
            "charge": "revenue",
            "payment": "cash",
            "insurance": "cash",
            "refund": "cash",
            "adjustment": "adjustments",
        }[record.kind]
        for account, amount in [("accounts_receivable", record.amount_cents), (contra, -record.amount_cents)]:
            db.add(
                JournalLine(
                    posting_id=record.id,
                    account=account,
                    amount_cents=amount,
                    location_id=record.location_id,
                    created_by=actor,
                    updated_by=actor,
                )
            )
        await db.flush()
    return record
