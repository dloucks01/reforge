"""Offline troubleshooting knowledge base.

Bundled with the app (no internet). Each entry maps a symptom to its cause and
fix, and links to the Doctor check that detects it. The GUI lets the operator
search these.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class KBEntry:
    id: str
    symptom: str
    cause: str
    fix: str
    check: str = ""      # related Doctor check name


ENTRIES: list[KBEntry] = [
    KBEntry(
        "offloads",
        "Captured packets are huge (e.g. 30 KB on a 1500-MTU link) or checksums look wrong",
        "NIC offloads (TSO/GSO/GRO/LRO/checksum) make the stack show pre-segmentation "
        "super-packets, not what's on the wire.",
        "Disable offloads on the capture interfaces: "
        "ethtool -K <iface> tso off gso off gro off lro off rx off tx off. "
        "Reforge does this automatically in bridge prep.",
        "offloads",
    ),
    KBEntry(
        "host-rst",
        "Connections through the inline host get reset, or the host answers ARP itself",
        "The host kernel sees traffic it doesn't own and injects RSTs/ARP replies.",
        "Keep capture NICs IP-less, disable IPv6 autoconf, and drop host-originated "
        "RST/ARP on those interfaces (Reforge's host-stack suppression does this).",
        "cli-tools",
    ),
    KBEntry(
        "rule-no-match",
        "A rule never matches / manipulation seems to do nothing",
        "The match condition doesn't fit the packets, the layer isn't present, or the "
        "bridge is not armed (pass-through).",
        "Use the packet-path Tracer on a sample packet to see why each rule did/didn't "
        "match, and confirm the bridge is ARMED.",
        "",
    ),
    KBEntry(
        "no-throughput",
        "No or very low throughput at 10G+",
        "AF_PACKET/libpcap can't keep up at line rate.",
        "Use the AF_XDP/PF_RING/DPDK backend and enable CPU pinning + hugepages "
        "(Phase 8).",
        "backends",
    ),
    KBEntry(
        "bridge-loop",
        "Traffic storm / duplicate packets when bridging in userspace",
        "The listen socket also sees frames we transmit, so re-injected frames get "
        "re-captured and forwarded in a loop.",
        "Reforge suppresses its own transmitted frames; if you build a custom loop, "
        "filter outgoing frames or dedup recently-sent bytes.",
        "",
    ),
    KBEntry(
        "wire-dark",
        "The link goes dead when Reforge stops or crashes",
        "A userspace bridge owns forwarding; if it dies, nothing forwards.",
        "Run with the watchdog (default) so fail-open hands the link to a kernel bridge, "
        "or use a hardware bypass NIC.",
        "",
    ),
    KBEntry(
        "multicast-pruned",
        "Multicast traffic doesn't cross the bridge",
        "Kernel IGMP/MLD multicast snooping prunes multicast to ports with no listeners; "
        "or the NIC isn't in allmulti.",
        "Disable multicast snooping on any kernel bridge and ensure promisc + allmulti "
        "are set (Reforge sets allmulti in prep).",
        "",
    ),
]


def search(query: str) -> list[KBEntry]:
    q = query.lower().strip()
    if not q:
        return list(ENTRIES)
    return [e for e in ENTRIES
            if q in e.symptom.lower() or q in e.cause.lower()
            or q in e.fix.lower() or q in e.id.lower()]
