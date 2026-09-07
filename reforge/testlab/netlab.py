"""Real veth network lab for live testing (needs root).

Creates isolated virtual interfaces so the real capture/inject/bridge paths can
be exercised with actual kernel sockets, without touching a production NIC.

Two shapes:
- a single veth pair (capture on one end, inject on the other), and
- a bridge lab: two veth pairs whose inner ends (lab-a, lab-b) the userspace
  bridge sits between, and whose outer ends (lab-a-p, lab-b-p) are the client
  and server sides for injecting and observing traffic.

CLI:  sudo python -m reforge.testlab.netlab up      # create the bridge lab
      sudo python -m reforge.testlab.netlab down    # remove it

The GUI can then run Bridge mode on lab-a / lab-b.
"""

from __future__ import annotations

import os
import subprocess
from typing import Self

BRIDGE_LAB = [("lab-a", "lab-a-p"), ("lab-b", "lab-b-p")]


def _ip(*args: str) -> None:
    subprocess.run(["ip", *args], check=True, capture_output=True)


def is_root() -> bool:
    return os.geteuid() == 0


def iface_exists(name: str) -> bool:
    return subprocess.run(["ip", "link", "show", name],
                          capture_output=True, check=False).returncode == 0


def add_pair(a: str, b: str) -> None:
    """Create an up veth pair a<->b (idempotent)."""
    if not iface_exists(a):
        _ip("link", "add", a, "type", "veth", "peer", "name", b)
    _ip("link", "set", a, "up")
    _ip("link", "set", b, "up")


def del_iface(name: str) -> None:
    if iface_exists(name):
        subprocess.run(["ip", "link", "del", name], capture_output=True, check=False)


class VethPair:
    """A single up veth pair, cleaned up on exit (root required)."""

    def __init__(self, a: str = "rf-a", b: str = "rf-b"):
        self.a, self.b = a, b

    def __enter__(self) -> Self:
        add_pair(self.a, self.b)
        return self

    def __exit__(self, *exc) -> None:
        del_iface(self.a)          # deleting one end removes the pair


def up_bridge_lab() -> list[str]:
    """Create the two-pair bridge lab. Returns the interface names."""
    for a, b in BRIDGE_LAB:
        add_pair(a, b)
    return [n for pair in BRIDGE_LAB for n in pair]


def down_bridge_lab() -> None:
    for a, _b in BRIDGE_LAB:
        del_iface(a)


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Reforge veth test lab (needs root).")
    ap.add_argument("action", choices=["up", "down", "status"])
    args = ap.parse_args(argv)

    if args.action in ("up", "down") and not is_root():
        print("needs root: re-run with sudo")
        return 1
    if args.action == "up":
        names = up_bridge_lab()
        print("bridge lab up:", ", ".join(names))
        print("run the GUI, Bridge mode on lab-a / lab-b; inject on lab-a-p, watch lab-b-p")
    elif args.action == "down":
        down_bridge_lab()
        print("bridge lab removed")
    else:
        for _a, _b in BRIDGE_LAB:
            for n in (_a, _b):
                print(f"{n}: {'present' if iface_exists(n) else 'absent'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
