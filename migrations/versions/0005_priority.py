"""Priority ordering for the durable queue; additive upgrade."""
from alembic import op
import sqlalchemy as sa

revision = '0005_priority'
down_revision = '0004_runtime'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if 'priority' not in {column['name'] for column in inspector.get_columns('jobs')}:
        op.add_column('jobs', sa.Column('priority', sa.Integer(), nullable=False, server_default='0'))
    if 'ix_jobs_priority' not in {index['name'] for index in sa.inspect(op.get_bind()).get_indexes('jobs')}:
        op.create_index('ix_jobs_priority', 'jobs', ['priority'])


def downgrade():
    op.drop_index('ix_jobs_priority', table_name='jobs')
    op.drop_column('jobs','priority')
