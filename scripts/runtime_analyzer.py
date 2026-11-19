#!/usr/bin/env python3
"""Run the runtime analyzer straight from a checkout.

    python scripts/runtime_analyzer.py capture --host FW --user USER [--duration 300]
    python scripts/runtime_analyzer.py report runtime_FW_20260101T000000Z [--open]

``capture`` needs paramiko (pip install paramiko); ``report`` is standard library only.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from panos_toolbox.cli import main

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("capture", "report"):
        print(__doc__)
        sys.exit(2)
    sys.exit(main(["runtime"] + sys.argv[1:]))
