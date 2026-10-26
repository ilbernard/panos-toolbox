"""Single entry point: ``panos-toolbox <area> <tool> [args...]``.

Tools are registered in TOOLS as ``(area, name) -> (module path, help)``.
Each tool module exposes ``main(argv=None)`` and is imported lazily, so a
tool's optional dependencies are only required when that tool is run.
"""
import argparse
import importlib
import sys

from panos_toolbox import __version__

TOOLS = {
    ("tsf", "analyze"): (
        "panos_toolbox.tsf.analyzer",
        "Throughput/CPU HTML report from a Tech Support File (dp-monitor.*)",
    ),
}


def _usage():
    areas = {}
    for (area, name), (_, desc) in sorted(TOOLS.items()):
        areas.setdefault(area, []).append((name, desc))
    lines = ["usage: panos-toolbox <area> <tool> [args...]", "", "available tools:"]
    for area, tools in areas.items():
        for name, desc in tools:
            lines.append(f"  {area} {name:<12} {desc}")
    lines += ["", "Run 'panos-toolbox <area> <tool> -h' for tool options."]
    return "\n".join(lines)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("-V", "--version"):
        print(f"panos-toolbox {__version__}")
        return 0
    if len(argv) < 2 or argv[0] in ("-h", "--help"):
        print(_usage(), file=sys.stderr if argv else sys.stdout)
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    key = (argv[0], argv[1])
    if key not in TOOLS:
        print(f"unknown tool: {' '.join(argv[:2])}\n\n{_usage()}", file=sys.stderr)
        return 2
    module = importlib.import_module(TOOLS[key][0])
    return module.main(argv[2:]) or 0


if __name__ == "__main__":
    sys.exit(main())
