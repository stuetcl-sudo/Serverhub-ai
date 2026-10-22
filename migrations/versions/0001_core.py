"""Initial control plane schema and PostgreSQL append-only audit protection.

Revision ID: 0001_core
Revises:
"""
from alembic import op
from serverhub.models import Base

revision = "0001_core"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    if bind.dialect.name == "postgresql":
        op.execute("""
        CREATE FUNCTION serverhub_reject_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            RAISE EXCEPTION 'ServerHub audit records are append-only';
        END $$
        """)
        op.execute("""CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit
                       FOR EACH ROW EXECUTE FUNCTION serverhub_reject_audit_mutation()""")


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_append_only ON audit")
        op.execute("DROP FUNCTION IF EXISTS serverhub_reject_audit_mutation()")
    Base.metadata.drop_all(bind=bind)
