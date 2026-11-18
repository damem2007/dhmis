"""Reserve the published rule key separately from its UUID primary key."""

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


# Run the upgrade entry point for this module.
def upgrade():
    # Fresh installations receive UUID primary keys and a separate ``key``
    # column from migration 0015.  This revision remains in the chain so an
    # updated history can be replayed without introducing a second migration.
    return


# Run the downgrade entry point for this module.
def downgrade():
    return
