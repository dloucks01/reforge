"""Command-line entry point.

Everything the GUI can do is meant to be reachable headless; Phase 0 wires up
the skeleton subcommands so the surface exists and is testable.
"""

from __future__ import annotations

import argparse
import logging
import sys

from reforge.constants import APP_NAME, TAGLINE, VERSION
from reforge.logging_setup import setup_logging


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reforge", description=f"{APP_NAME} — {TAGLINE}")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    sub = p.add_subparsers(dest="command")

    sub.add_parser("gui", help="launch the graphical interface (default)")

    d = sub.add_parser("doctor", help="run self-test / diagnostics checks")
    d.add_argument("--json", action="store_true", help="machine-readable output")

    lst = sub.add_parser("backends", help="list available capture backends")
    lst.add_argument("--json", action="store_true", help="machine-readable output")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(logging.DEBUG if args.verbose else logging.INFO)

    command = args.command or "gui"

    if command == "gui":
        from reforge.gui.app import run_gui

        return run_gui()

    if command == "doctor":
        from reforge.diagnostics.doctor import run_doctor

        return run_doctor(as_json=args.json)

    if command == "backends":
        from reforge.capture.registry import list_backends

        for name, available, note in list_backends():
            mark = "ok " if available else "-- "
            print(f"{mark}{name:12s} {note}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
