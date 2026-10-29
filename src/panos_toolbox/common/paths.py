"""Per-user locations for tool settings (stdlib only, Windows/macOS/Linux)."""
import os
import sys
from pathlib import Path

APP_DIR_NAME = "panos-toolbox"


def user_config_dir(app=APP_DIR_NAME):
    """Return the per-user configuration directory (not created)."""
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming"
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / app
