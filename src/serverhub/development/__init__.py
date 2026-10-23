"""Policy-controlled development of owner-configured projects."""
from .workflow import register as register_workflow


def register():
    register_workflow()
    from .autonomous import autonomous_development
    from serverhub.jobs import register_handler
    register_handler("development_autonomous", autonomous_development)

__all__ = ["register"]
