#!/usr/bin/env python3
"""Run the GlobalProtect log analyzer straight from a checkout, with no installation.

    python scripts/gp_analyzer.py GlobalProtectLogs.zip [more.zip ...] [-o OUTDIR] [--open]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from panos_toolbox.gp.analyzer import main

if __name__ == "__main__":
    sys.exit(main())
