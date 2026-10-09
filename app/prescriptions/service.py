from sqlalchemy import select

from app.prescriptions.models import MedicationSafetyRule, Prescription


def normalized(value: str) -> str:
    return " ".join(value.lower().split())


async def safety_flags(db, patient, medication: str):
    medication_key = normalized(medication)
    allergies = [normalized(value) for value in patient.allergies]
    history = normalized(patient.medical_history)
    active_medications = [
        normalized(row.medication)
        for row in (
            await db.scalars(
                select(Prescription).where(
                    Prescription.patient_id == patient.id,
                    Prescription.status == "issued",
                )
            )
        ).all()
    ]
    flags = []
    if any(allergy in medication_key or medication_key in allergy for allergy in allergies):
        flags.append(
            {
                "type": "allergy",
                "severity": "block",
                "message": "Medication conflicts with a recorded patient allergy",
            }
        )
    rules = (
        await db.scalars(
            select(MedicationSafetyRule).where(MedicationSafetyRule.active)
        )
    ).all()
    for rule in rules:
        if normalized(rule.medication) != medication_key:
            continue
        matched = [
            conflict
            for conflict in rule.conflicts
            if normalized(str(conflict)) in history
            or any(normalized(str(conflict)) in current for current in active_medications)
            or any(normalized(str(conflict)) in allergy for allergy in allergies)
        ]
        if matched:
            flags.append(
                {
                    "type": "interaction",
                    "severity": rule.severity,
                    "message": rule.message,
                    "matched": matched,
                    "rule_id": rule.id,
                }
            )
    return flags

