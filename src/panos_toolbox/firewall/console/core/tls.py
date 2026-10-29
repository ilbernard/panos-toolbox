"""TLS settings for Panorama connections.

pan-os-python (through pan-python) never verifies the server certificate and
offers no switch for it, so the console builds the SSL context itself and
injects it (see ``panorama.py``). Verification is ON unless explicitly disabled.
"""
from __future__ import annotations

import ssl


def build_ssl_context(verify=True, ca_file=None):
    """Return an SSL context.

    ``verify=True`` validates the certificate and host name against the system
    trust store, or against ``ca_file`` (PEM) when given. ``verify=False`` is the
    explicit opt-out for self-signed certificates.
    """
    if verify:
        return ssl.create_default_context(cafile=ca_file or None)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context
