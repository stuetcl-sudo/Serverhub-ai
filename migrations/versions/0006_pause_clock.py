"""Exclude explicit approval/manual pauses from execution deadlines."""
from alembic import op
import sqlalchemy as sa

revision = "0006_pause_clock"
down_revision = "0005_priority"
branch_labels = None
depends_on = None


def upgrade():
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("jobs")}
    if "paused_at" not in columns:
        op.add_column("jobs", sa.Column("paused_at", sa.DateTime(), nullable=True))
    if "paused_seconds" not in columns:
        op.add_column("jobs", sa.Column("paused_seconds", sa.Float(), nullable=False, server_default="0"))
    # Preserve the known start of existing pauses; no change to policy expiration.
    op.execute(sa.text("UPDATE jobs SET paused_at = updated_at WHERE state IN ('paused', 'waiting_approval') AND paused_at IS NULL"))


def downgrade():
    op.drop_column("jobs", "paused_seconds")
    op.drop_column("jobs", "paused_at")
