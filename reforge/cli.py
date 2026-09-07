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

    br = sub.add_parser("bridge", help="run the userspace transparent bridge (root)")
    br.add_argument("--a", required=True, metavar="IFACE", help="first interface")
    br.add_argument("--b", required=True, metavar="IFACE", help="second interface")
    br.add_argument("--session", metavar="FILE", help="load rules from a session file")
    br.add_argument("--fail-closed", action="store_true",
                    help="drop links on failure instead of kernel-bridge fallback")
    br.add_argument("--no-prep", action="store_true",
                    help="skip interface prep (offloads/promisc/host-stack)")
    br.add_argument("--seq-fixup", action="store_true",
                    help="keep TCP flows in sync after length-changing edits (cumulative)")
    br.add_argument("--flow-rewrite", action="store_true",
                    help="position-aware seq/ack fix-ups (R3; retransmit-correct)")
    br.add_argument("--fix-checksums", action="store_true",
                    help="recompute IP/TCP/UDP checksums on every forwarded packet")

    sc = sub.add_parser("scenario", help="run a scripted engagement scenario + report")
    sc.add_argument("file", help="scenario file (.json / .yaml)")
    sc.add_argument("--dry-run", action="store_true", help="validate + log without attacking")
    sc.add_argument("--json", action="store_true", help="emit the report as JSON")
    sc.add_argument("--out", metavar="FILE", help="write the report to a file")
    sc.add_argument("--encrypt", metavar="PASSPHRASE",
                    help="encrypt the --out report at rest (AES-256-GCM)")

    vt = sub.add_parser("vault", help="encrypt/decrypt an engagement artifact at rest")
    vt.add_argument("mode", choices=["encrypt", "decrypt"])
    vt.add_argument("src")
    vt.add_argument("dst")
    vt.add_argument("--passphrase", required=True)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(logging.DEBUG if args.verbose else logging.INFO)

    from reforge.core.scapy_init import warmup
    warmup()

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

    if command == "bridge":
        return _run_bridge(args)

    if command == "scenario":
        from reforge.scenario.runner import ScenarioRunner, load_scenario

        spec = load_scenario(args.file)
        report = ScenarioRunner(dry_run=args.dry_run).run(spec)
        text = report.to_json() if args.json else report.to_markdown()
        if args.out:
            from pathlib import Path

            if args.encrypt:
                from reforge.core.vault import encrypt_bytes

                Path(args.out).write_bytes(encrypt_bytes(text.encode(), args.encrypt))
                print(f"encrypted report written to {args.out}")
            else:
                Path(args.out).write_text(text)
                print(f"report written to {args.out}")
        else:
            print(text)
        return 0

    if command == "vault":
        from reforge.core.vault import decrypt_file, encrypt_file

        fn = encrypt_file if args.mode == "encrypt" else decrypt_file
        out = fn(args.src, args.dst, args.passphrase)
        print(f"{args.mode}ed -> {out}")
        return 0

    return 1


def _run_bridge(args) -> int:
    import os
    import time as _time

    from reforge.core.bridge import UserspaceBridge
    from reforge.core.watchdog import Watchdog
    from reforge.privhelper.netconfig import (
        RevertJournal,
        fail_closed_commands,
        fail_open_commands,
        prepare_bridge,
    )
    from reforge.rules.engine import RuleEngine
    from reforge.rules.spec import build_rules

    log = logging.getLogger("reforge.cli")
    if os.geteuid() != 0:
        log.error("bridge mode needs root (CAP_NET_RAW/CAP_NET_ADMIN)")
        return 2

    rules = []
    if args.session:
        from reforge.core.session import Session

        rules = build_rules(Session.load(args.session).rules)
        log.info("loaded %d rule(s) from %s", len(rules), args.session)

    journal = RevertJournal()
    if not args.no_prep:
        prepare_bridge(args.a, args.b, journal, apply=True)

    engine = RuleEngine(rules)
    bridge = UserspaceBridge(args.a, args.b, engine, fail_open=not args.fail_closed,
                             seq_fixup=args.seq_fixup, flow_rewrite=args.flow_rewrite,
                             checksum_fixup=args.fix_checksums)

    def enact_fail_policy() -> None:
        if args.fail_closed:
            fail_closed_commands(args.a, args.b, journal, apply=True)
        else:
            fail_open_commands(args.a, args.b, journal, apply=True)

    watchdog = Watchdog(bridge.heartbeat_age, timeout=2.0, on_trip=enact_fail_policy)

    # Warm scapy so opening L2 sockets in the loop is fast (keeps the watchdog
    # from counting a slow first import as a stall).
    import scapy.all  # noqa: F401

    bridge.start()
    if not bridge.wait_ready(8.0):
        log.error("bridge failed to start (could not open ports on %s/%s)", args.a, args.b)
        bridge.stop()
        journal.revert(lambda cmd: __import__("subprocess").run(cmd, check=False))
        return 3
    watchdog.start()  # only arm the watchdog once the loop is actually ticking
    log.info("bridge running: %s <-> %s (fail-%s). Ctrl-C to stop.",
             args.a, args.b, "closed" if args.fail_closed else "open")
    try:
        while bridge.running:
            _time.sleep(1.0)
            c = bridge.counters
            log.info("fwd=%d drop=%d mod=%d a->b=%d b->a=%d",
                     c.forwarded, c.dropped, c.modified, c.a_to_b, c.b_to_a)
    except KeyboardInterrupt:
        pass
    finally:
        watchdog.stop()
        bridge.stop()
        journal.revert(lambda cmd: __import__("subprocess").run(cmd, check=False))
        log.info("bridge torn down; host state reverted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
