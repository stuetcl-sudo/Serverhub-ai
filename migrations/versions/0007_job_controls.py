"""Separate mutable job accounting from protected system state."""
from alembic import op
import sqlalchemy as sa

revision = "0007_job_controls"
down_revision = "0006_pause_clock"
branch_labels = None
depends_on = None


def upgrade():
    if not sa.inspect(op.get_bind()).has_table("job_control_state"):
        op.create_table("job_control_state",
            sa.Column("key", sa.String(100), primary_key=True),
            sa.Column("value", sa.JSON(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False))


def downgrade():
    op.drop_table("job_control_state")
