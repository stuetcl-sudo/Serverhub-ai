"""Persist audience-bound MCP OAuth authorization and refresh grants."""
from alembic import op
from serverhub.oauth_models import OAuthClient, OAuthPending, OAuthCode, OAuthRefresh

revision = "0002_oauth"
down_revision = "0001_core"
branch_labels = None
depends_on = None


def upgrade():
    for model in (OAuthClient, OAuthPending, OAuthCode, OAuthRefresh):
        model.__table__.create(op.get_bind(), checkfirst=True)


def downgrade():
    for model in (OAuthRefresh, OAuthCode, OAuthPending, OAuthClient):
        model.__table__.drop(op.get_bind(), checkfirst=True)
