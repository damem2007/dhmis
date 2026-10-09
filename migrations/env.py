from alembic import context

config = context.config
connection = config.attributes["connection"]
schema = config.attributes["schema"]
context.configure(connection=connection, version_table_schema=schema)
with context.begin_transaction():
    context.run_migrations()
