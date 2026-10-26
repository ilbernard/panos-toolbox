"""Connection helper for PAN-OS devices."""
from panos_toolbox.common.config import firewall_settings


def connect():
    """Return a ``panos.firewall.Firewall`` built from the environment."""
    from panos.firewall import Firewall  # imported lazily: optional dependency

    cfg = firewall_settings()
    return Firewall(cfg["hostname"], api_key=cfg["api_key"])
