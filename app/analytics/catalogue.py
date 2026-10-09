from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class MetricDefinition:
    key: str
    label: str
    definition: str
    unit: str
    source: str
    version: str = "1.0"


DEFINITIONS = {
    item.key: item
    for item in [
        MetricDefinition("production", "Production", "Billable invoice value net of adjustments created in the selected range.", "currency", "invoices"),
        MetricDefinition("collections", "Collections", "Payments and insurance receipts posted in the selected range.", "currency", "ledger_entries"),
        MetricDefinition("collection_rate", "Collection rate", "Collections divided by production for the selected range.", "percent", "invoices + ledger_entries"),
        MetricDefinition("ar_balance", "A/R balance", "Open invoiced value less applied payments across authorized records.", "currency", "invoices"),
        MetricDefinition("visits", "Visits", "Appointments in the selected range excluding cancelled appointments.", "count", "appointments"),
        MetricDefinition("no_show_rate", "No-show rate", "No-show appointments divided by non-cancelled appointments in the selected range.", "percent", "appointments"),
        MetricDefinition("chair_utilization", "Chair utilization", "Scheduled appointment minutes divided by configured chair capacity in the selected range.", "percent", "appointments + locations"),
        MetricDefinition("case_acceptance", "Case acceptance", "Accepted treatment plans divided by presented treatment plans in the selected range.", "percent", "treatment_plans"),
        MetricDefinition("pending_claims", "Pending claims", "Claims not yet paid or denied.", "count", "claims"),
        MetricDefinition("denied_claims", "Denied claims", "Claims currently denied.", "count", "claims"),
        MetricDefinition("active_staff", "Active staff", "Active staff accounts in authorized locations.", "count", "staff_users"),
        MetricDefinition("failed_notifications", "Failed notifications", "Notification jobs in failed or retry state.", "count", "outbox_messages"),
        MetricDefinition("completed_encounters", "Completed encounters", "Clinical encounters completed in the selected range.", "count", "encounters"),
    ]
}


def public_catalogue():
    return [asdict(item) for item in DEFINITIONS.values()]
