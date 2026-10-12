"""Store tenant brand defaults and the public logo in tenant settings."""

import sqlalchemy as sa
from alembic import context, op

revision = "0031_tenant_brand_defaults"
down_revision = "0030_default_services"
branch_labels = None
depends_on = None


DEFAULT_BRANDING = (
    '{"--sage":"#0ea968","--sage-deep":"#076b41",'
    '"--sage-tint":"#d3f3e4","--amber":"#e8a93b",'
    '"--paper":"#f3f6f4","--surface":"#ffffff",'
    '"--ink":"#0f1b17","--font-ui":"IBM Plex Sans, sans-serif",'
    '"--font-display":"Fraunces, Georgia, serif"}'
)
DEFAULT_LOGO_URL = "/assets/dhmis-logo-v2/svg/dhmis-lockup-website.svg"


def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.add_column(
        "tenant_settings",
        sa.Column("logo_url", sa.String(1000), nullable=False, server_default=DEFAULT_LOGO_URL),
        schema=schema,
    )
    op.execute(
        sa.text(
            f"""
            UPDATE "{schema}".tenant_settings
            SET branding = CAST((CAST(:defaults AS jsonb) || COALESCE(branding::jsonb, '{{}}'::jsonb)) AS json),
                logo_url = COALESCE(NULLIF(logo_url, ''), :logo),
                updated_by = 'tenant-brand-defaults-migration'
            WHERE id = 'organization-settings'
            """
        ).bindparams(defaults=DEFAULT_BRANDING, logo=DEFAULT_LOGO_URL)
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
