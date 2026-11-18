"""Keep only Back Office implicit on legacy plans until an operator authors a bundle."""

from alembic import context, op


revision = "0064_legacy_plan_features"
down_revision = "0063_commercial_domains"
branch_labels = None
depends_on = None


def upgrade():
    if context.config.attributes["schema"] != "dhmis_control":
        return

    # Migration 0062 introduced catalogue entries before plan authoring was
    # available and temporarily assigned them to every legacy plan.  Only
    # those migration-created rows are disabled here.  Operator-authored
    # assignments retain their reviewed state.
    op.execute(
        """
        UPDATE dhmis_control.platform_plan_features AS assignment
        SET enabled = FALSE,
            value = NULL,
            included_quantity = NULL,
            public_label = '',
            updated_by = 'migration'
        FROM dhmis_control.platform_features AS feature
        WHERE assignment.feature_id = feature.id
          AND assignment.created_by = 'migration'
          AND feature.key IN (
              'experience.tenant_website',
              'capability.appointment_booking',
              'limit.appointment_widget_origins'
          )
        """
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
