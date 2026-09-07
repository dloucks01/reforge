"""Generate demo capture data for exploring the tool offline.

`write_demo_pcap` writes the mixed synthetic scenario to a pcap the operator can
open via 'Open pcap', so a first-time user has realistic traffic — logins,
credentials, a large HTTP body, DNS, ARP — to explore without a NIC.
"""

from __future__ import annotations

from pathlib import Path


def write_demo_pcap(path: str | Path) -> int:
    """Write the mixed synthetic scenario to a pcap. Returns frames written."""
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    from reforge.testlab.traffic import mixed_scenario

    pkts = []
    for ts, data in mixed_scenario():
        pkt = Ether(data)
        pkt.time = float(ts)
        pkts.append(pkt)
    wrpcap(str(path), pkts)
    return len(pkts)


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Write a Reforge demo pcap.")
    ap.add_argument("path", nargs="?", default="reforge-demo.pcap")
    args = ap.parse_args(argv)
    n = write_demo_pcap(args.path)
    print(f"wrote {n} frames to {args.path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
