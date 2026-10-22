"""Durable owner-defined interval schedules with least-privilege worker updates."""
from alembic import op
from serverhub.models import Schedule

revision = "0003_schedules"
down_revision = "0002_oauth"
branch_labels = None
depends_on = None


def upgrade():
    Schedule.__table__.create(op.get_bind(), checkfirst=True)


def downgrade():
    Schedule.__table__.drop(op.get_bind(), checkfirst=True)
