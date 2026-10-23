"""Tenant-owned treatment catalogue defaults used by planning and charting.

The caller supplies a session already scoped to one tenant schema. Keeping the
seed definitions independent of organization ids means the same routine can be
used during provisioning and for legacy tenants without a tenant enumeration
or a tenant-specific configuration file.
"""

from sqlalchemy import select

from app.billing.defaults import ensure_default_services
from app.billing.models import Service
from app.clinical.models import TreatmentCatalogueItem, TreatmentCatalogueOption


# These are deliberately catalogue entries, not frontend constants. Clinics may
# edit, archive, or relink them after provisioning while historical plans keep
# their saved snapshots.
DEFAULT_TREATMENTS = (
    {
        "code": "COMPOSITE-RESTORATION",
        "name": "Composite restoration",
        "category": "Restorative",
        "description": "Tooth-coloured restoration for cavities and chips.",
        "service_code": "FILLINGS",
        "applies_to": "tooth_surface",
        "allowed_surfaces": ["mesial", "occlusal", "distal", "buccal", "lingual"],
        "quick_chart": False,
    },
    {
        "code": "AMALGAM-RESTORATION",
        "name": "Amalgam restoration",
        "category": "Restorative",
        "description": "Metal restoration for a prepared tooth.",
        "service_code": "FILLINGS",
        "applies_to": "tooth_surface",
        "allowed_surfaces": ["mesial", "occlusal", "distal", "buccal", "lingual"],
        "quick_chart": False,
    },
    {
        "code": "CROWN",
        "name": "Crown",
        "category": "Restorative",
        "description": "Full-coverage restoration for a tooth.",
        "service_code": None,
        "applies_to": "tooth",
        "allowed_surfaces": ["whole"],
        "quick_chart": False,
    },
    {
        "code": "ROOT-CANAL",
        "name": "Root canal",
        "category": "Endodontic",
        "description": "Endodontic treatment for an infected or inflamed pulp.",
        "service_code": None,
        "applies_to": "tooth",
        "allowed_surfaces": ["whole"],
        "quick_chart": False,
    },
    {
        "code": "EXTRACTION",
        "name": "Extraction",
        "category": "Surgical",
        "description": "Removal of a tooth.",
        "service_code": None,
        "applies_to": "tooth",
        "allowed_surfaces": ["whole"],
        "quick_chart": False,
    },
    # PDF section A starter procedures. They intentionally start at zero so a
    # clinic can link Services & fees where available or enter a procedure fee.
    *(
        {
            "code": code,
            "name": name,
            "category": category,
            "description": "",
            "service_code": None,
            "applies_to": applies_to,
            "allowed_surfaces": ["whole"] if applies_to != "tooth_surface" else ["mesial", "occlusal", "distal", "buccal", "lingual"],
            "quick_chart": False,
        }
        for code, name, category, applies_to in (
            ("COMPREHENSIVE-EXAM", "Comprehensive exam", "Diagnostic", "whole_mouth"),
            ("PERIODIC-EXAM", "Periodic exam", "Diagnostic", "whole_mouth"),
            ("EMERGENCY-EXAM", "Emergency exam", "Diagnostic", "whole_mouth"),
            ("RADIOGRAPH-BITEWING", "Radiograph - bitewing", "Diagnostic", "whole_mouth"),
            ("RADIOGRAPH-PERIAPICAL", "Radiograph - periapical", "Diagnostic", "tooth"),
            ("RADIOGRAPH-PANORAMIC", "Radiograph - panoramic", "Diagnostic", "whole_mouth"),
            ("CLEANING-PROPHYLAXIS", "Cleaning / prophylaxis", "Preventive", "whole_mouth"),
            ("FLUORIDE-TREATMENT", "Fluoride treatment", "Preventive", "whole_mouth"),
            ("SEALANT", "Sealant", "Preventive", "tooth"),
            ("ORAL-HYGIENE-INSTRUCTION", "Oral hygiene instruction", "Preventive", "whole_mouth"),
            ("INLAY-ONLAY", "Inlay / onlay", "Restorative", "tooth_surface"),
            ("VENEER", "Veneer", "Restorative", "tooth"),
            ("STAINLESS-STEEL-CROWN-PRIMARY", "Stainless steel crown - primary", "Restorative", "tooth"),
            ("CORE-BUILD-UP", "Core build-up", "Restorative", "tooth"),
            ("ROOT-CANAL-RETREATMENT", "Root canal retreatment", "Endodontic", "tooth"),
            ("PULPOTOMY-PRIMARY", "Pulpotomy - primary", "Endodontic", "tooth"),
            ("PULPECTOMY", "Pulpectomy", "Endodontic", "tooth"),
            ("SCALING-ROOT-PLANING", "Scaling and root planing", "Periodontal", "quadrant"),
            ("PERIODONTAL-MAINTENANCE", "Periodontal maintenance", "Periodontal", "whole_mouth"),
            ("GINGIVAL-GRAFT", "Gingival graft", "Periodontal", "tooth"),
            ("COMPLETE-DENTURE", "Complete denture", "Prosthodontic", "arch"),
            ("PARTIAL-DENTURE", "Partial denture", "Prosthodontic", "arch"),
            ("BRIDGE", "Bridge", "Prosthodontic", "tooth"),
            ("DENTURE-REPAIR-RELINE", "Denture repair or reline", "Prosthodontic", "arch"),
            ("EXTRACTION-SURGICAL", "Extraction - surgical", "Oral surgery", "tooth"),
            ("IMPACTED-TOOTH-REMOVAL", "Impacted tooth removal", "Oral surgery", "tooth"),
            ("IMPLANT-PLACEMENT", "Implant placement", "Implant", "tooth"),
            ("IMPLANT-ABUTMENT", "Implant abutment", "Implant", "tooth"),
            ("IMPLANT-CROWN", "Implant crown", "Implant", "tooth"),
            ("ORTHODONTIC-CONSULTATION", "Orthodontic consultation", "Orthodontic", "whole_mouth"),
            ("RETAINER", "Retainer", "Orthodontic", "arch"),
            ("NIGHT-GUARD", "Night guard", "Adjunctive", "arch"),
            ("TEETH-WHITENING", "Teeth whitening", "Adjunctive", "whole_mouth"),
            ("EMERGENCY-PALLIATIVE", "Emergency palliative treatment", "Adjunctive", "tooth"),
            ("SEDATION", "Sedation", "Adjunctive", "whole_mouth"),
        )
    ),
)

DEFAULT_CONDITIONS = (
    ("CARIES", "Caries", "Hard tissue", "tooth_surface", "caries", "surface", "COMPOSITE-RESTORATION"),
    ("FRACTURE-CRACKED-TOOTH", "Fracture / cracked tooth", "Hard tissue", "tooth", "fracture", "whole", "CROWN"),
    ("WEAR-EROSION", "Wear / erosion", "Hard tissue", "tooth_surface", "healthy", "surface", ""),
    ("DEFECTIVE-RESTORATION", "Defective restoration", "Hard tissue", "tooth_surface", "healthy", "surface", "COMPOSITE-RESTORATION"),
    ("DISCOLOURATION", "Discolouration", "Hard tissue", "tooth", "healthy", "crown", ""),
    ("ABSCESS", "Abscess", "Pulp and periapical", "tooth", "abscess", "root", "ROOT-CANAL"),
    ("PERIAPICAL-LESION", "Periapical lesion", "Pulp and periapical", "tooth", "healthy", "root", "ROOT-CANAL"),
    ("GINGIVAL-RECESSION", "Gingival recession", "Periodontal", "tooth", "healthy", "surface", ""),
    ("TOOTH-MOBILITY", "Tooth mobility", "Periodontal", "tooth", "healthy", "whole", ""),
    ("PERIODONTAL-DISEASE", "Periodontal disease", "Periodontal", "whole_mouth", "healthy", "whole", "PERIODONTAL-MAINTENANCE"),
    ("CALCULUS-PLAQUE", "Calculus / plaque", "Periodontal", "whole_mouth", "healthy", "whole", "CLEANING-PROPHYLAXIS"),
    ("MALOCCLUSION", "Malocclusion", "Occlusion", "whole_mouth", "healthy", "whole", ""),
)

DEFAULT_TOOTH_STATUSES = (
    ("PRESENT", "Present (erupted)", "healthy", "present"),
    ("UNVERIFIED", "Unverified", "unverified", "unverified"),
    ("UNERUPTED", "Unerupted", "unerupted", "unerupted"),
    ("ERUPTING", "Erupting", "unverified", "erupting"),
    ("IMPACTED", "Impacted", "unverified", "impacted"),
    ("MISSING-EXTRACTED", "Missing - extracted", "missing", "missing"),
    ("MISSING-NEVER-DEVELOPED", "Missing - never developed", "missing", "missing"),
    ("SHED", "Shed (exfoliated)", "missing", "shed"),
    ("RETAINED-PRIMARY", "Retained primary tooth", "healthy", "present"),
    ("IMPLANT", "Implant", "implant", "implant"),
    ("RETAINED-ROOT", "Retained root", "healthy", "present"),
    ("BRIDGE-PONTIC", "Bridge pontic", "healthy", "present"),
    ("SUPERNUMERARY", "Supernumerary", "healthy", "present"),
)


# Approved starter values from the treatment-catalogue proposal. The rows live
# in each tenant schema so categories remain tenant-owned and editable.
DEFAULT_CATALOGUE_OPTIONS = (
    ("type", "treatment", "treatment", "Procedure", 10),
    ("type", "condition", "condition", "Condition", 20),
    ("type", "tooth_status", "tooth_status", "Tooth status", 30),
    ("category", "treatment", "Diagnostic", "Diagnostic", 10),
    ("category", "treatment", "Preventive", "Preventive", 20),
    ("category", "treatment", "Restorative", "Restorative", 30),
    ("category", "treatment", "Endodontic", "Endodontic", 40),
    ("category", "treatment", "Periodontal", "Periodontal", 50),
    ("category", "treatment", "Prosthodontic", "Prosthodontic", 60),
    ("category", "treatment", "Oral surgery", "Oral surgery", 70),
    ("category", "treatment", "Implant", "Implant", 80),
    ("category", "treatment", "Orthodontic", "Orthodontic", 90),
    ("category", "treatment", "Adjunctive", "Adjunctive", 100),
    ("category", "condition", "Hard tissue", "Hard tissue", 10),
    ("category", "condition", "Pulp and periapical", "Pulp and periapical", 20),
    ("category", "condition", "Periodontal", "Periodontal", 30),
    ("category", "condition", "Occlusion", "Occlusion", 40),
    ("category", "condition", "Soft tissue", "Soft tissue", 50),
)


async def ensure_catalogue_options(db, actor="tenant-defaults"):
    """Seed the approved type/category table in the current tenant schema."""
    existing = {
        (row.option_type, row.item_type, row.value)
        for row in (await db.scalars(select(TreatmentCatalogueOption))).all()
    }
    added = 0
    for option_type, item_type, value, label, sort_order in DEFAULT_CATALOGUE_OPTIONS:
        key = (option_type, item_type, value)
        if key in existing:
            continue
        db.add(
            TreatmentCatalogueOption(
                option_type=option_type,
                item_type=item_type,
                value=value,
                label=label,
                sort_order=sort_order,
                active=True,
                created_by=actor,
                updated_by=actor,
            )
        )
        existing.add(key)
        added += 1
    if added:
        await db.flush()
    return added


async def ensure_default_treatments(db, actor="tenant-defaults"):
    """Ensure default treatments exist in the current tenant's catalogue."""
    await ensure_default_services(db, actor=actor)
    existing_keys = {
        (row.item_type, row.code)
        for row in (
            await db.execute(
                select(TreatmentCatalogueItem.item_type, TreatmentCatalogueItem.code)
            )
        ).all()
    }
    services = {
        row.code: row.id
        for row in (await db.scalars(select(Service))).all()
    }
    added = 0
    for item in DEFAULT_TREATMENTS:
        if ("treatment", item["code"]) in existing_keys:
            continue
        db.add(
            TreatmentCatalogueItem(
                item_type="treatment",
                code=item["code"],
                name=item["name"],
                description=item["description"],
                category=item["category"],
                service_id=services.get(item["service_code"]) if item["service_code"] else None,
                fee_cents=0,
                applies_to=item["applies_to"],
                allowed_surfaces=item["allowed_surfaces"],
                quick_chart=item["quick_chart"],
                active=True,
                created_by=actor,
                updated_by=actor,
            )
        )
        existing_keys.add(("treatment", item["code"]))
        added += 1
    if added:
        await db.flush()
    existing_keys = {
        (row.item_type, row.code)
        for row in (await db.scalars(select(TreatmentCatalogueItem))).all()
    }
    for code, name, category, applies_to, appearance_key, draw_on, resolved_by in DEFAULT_CONDITIONS:
        if ("condition", code) in existing_keys:
            continue
        db.add(TreatmentCatalogueItem(item_type="condition", code=code, name=name, category=category, service_id=None, fee_cents=0, fee_source="none", applies_to=applies_to, allowed_surfaces=["mesial", "occlusal", "distal", "buccal", "lingual"] if applies_to == "tooth_surface" else ["whole"], appearance_key=appearance_key, draw_on=draw_on, resolved_by=resolved_by, active=True, created_by=actor, updated_by=actor))
        added += 1
    for code, name, appearance_key, effect in DEFAULT_TOOTH_STATUSES:
        if ("tooth_status", code) in existing_keys:
            continue
        db.add(TreatmentCatalogueItem(item_type="tooth_status", code=code, name=name, category="", service_id=None, fee_cents=0, fee_source="none", applies_to="tooth", allowed_surfaces=["whole"], appearance_key=appearance_key, draw_on="whole", tooth_status_effect=effect, active=True, created_by=actor, updated_by=actor))
        added += 1
    if added:
        await db.flush()
    return added
