"""Owner-managed models, worker liveness and explicit policy environments."""

from alembic import op
import sqlalchemy as sa
from serverhub.models import ModelRoute, WorkerHeartbeat

revision = "0004_runtime"
down_revision = "0003_schedules"
branch_labels = None
depends_on = None


def upgrade():
    ModelRoute.__table__.create(op.get_bind(), checkfirst=True)
    WorkerHeartbeat.__table__.create(op.get_bind(), checkfirst=True)
    # 0001 historically creates current metadata on a fresh database; upgrades
    # from an installed 0003 schema still need the additive column.
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("policies")}
    if "environment" not in columns:
        op.add_column(
            "policies", sa.Column("environment", sa.String(30), nullable=False, server_default="any")
        )


def downgrade():
    op.drop_column("policies", "environment")
    WorkerHeartbeat.__table__.drop(op.get_bind(), checkfirst=True)
    ModelRoute.__table__.drop(op.get_bind(), checkfirst=True)
