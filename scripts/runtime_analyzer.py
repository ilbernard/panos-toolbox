#!/usr/bin/env python3
"""Runtime analyzer straight from a checkout, with no installation.

Capture (then the HTML report is built automatically; Ctrl+C stops the capture cleanly
and the report is still generated):

    python scripts/runtime_analyzer.py --host FW --user USER [--duration 0] [--open]

Report only, from an existing capture folder:

    python scripts/runtime_analyzer.py report runtime_FW_20260101T000000Z [--open]

``capture`` needs paramiko (pip install paramiko); ``report`` is standard library only.
The word ``capture`` before the options is accepted and optional.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from panos_toolbox.cli import main

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help") and len(args) == 1:
        print(__doc__)
        sys.exit(2)
    if args[0] not in ("capture", "report"):
        args = ["capture"] + args
    sys.exit(main(["runtime"] + args))
