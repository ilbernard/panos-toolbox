"""Connection helper for Strata Cloud Manager."""
from panos_toolbox.common.config import scm_settings


def connect():
    """Return an authenticated ``scm.client.Scm`` built from the environment."""
    from scm.client import Scm  # imported lazily: optional dependency

    return Scm(**scm_settings())
