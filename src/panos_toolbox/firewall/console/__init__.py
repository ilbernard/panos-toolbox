"""Panorama console: desktop GUI to list the firewalls managed by Panorama and act on them.

Run with ``panos-toolbox firewall console`` or ``python -m panos_toolbox.firewall.console``.
The GUI-independent logic is in ``core/``, GUI code in ``gui/``, actions in ``actions/``.
"""
import argparse
import sys

from panos_toolbox.common.log import get_logger


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="panos-toolbox firewall console",
        description="Desktop console: connect to Panorama, list managed firewalls, run actions.",
    )
    parser.add_argument(
        "--profiles-file",
        help="JSON file for saved connection profiles (default: per-user config directory)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)
    get_logger("panos_toolbox", args.verbose)

    try:
        from .gui.app import run
    except ImportError as exc:
        print(
            "The console needs PySide6 and pan-os-python: pip install 'panos-toolbox[console]'\n"
            f"({exc})",
            file=sys.stderr,
        )
        return 1
    return run(args.profiles_file)
