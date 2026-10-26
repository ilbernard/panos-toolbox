"""Credentials and endpoints, read from environment variables.

Secrets are never passed on the command line or stored in the repo; put them
in a local ``.env`` (git-ignored, see ``.env.example``) or export them.
"""
import os


def _load_dotenv(path=".env"):
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def require(name):
    _load_dotenv()
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"missing environment variable {name} (see .env.example)")
    return value


def firewall_settings():
    """Hostname plus API key for a PAN-OS firewall or Panorama."""
    return {"hostname": require("PANOS_HOSTNAME"), "api_key": require("PANOS_API_KEY")}


def scm_settings():
    """OAuth2 client credentials for Strata Cloud Manager."""
    return {
        "client_id": require("SCM_CLIENT_ID"),
        "client_secret": require("SCM_CLIENT_SECRET"),
        "tsg_id": require("SCM_TSG_ID"),
    }
