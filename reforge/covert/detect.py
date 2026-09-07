"""Covert-channel detector — flag likely exfiltration/tunneling in traffic.

Heuristic, passive: high-entropy oversized DNS subdomains (DNS tunneling),
high-entropy ICMP echo payloads (ICMP exfil). Runs over captured packets.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass


@dataclass
class Finding:
    channel: str
    detail: str
    count: int
    confidence: str


def entropy(data) -> float:
    """Shannon entropy in bits per symbol."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _first(field):
    if field is None:
        return None
    try:
        return field[0] if len(field) else None
    except TypeError:
        return field


def detect(pkts, dns_label_min: int = 20, dns_entropy_min: float = 3.3,
           icmp_size_min: int = 16, icmp_entropy_min: float = 4.5) -> list[Finding]:
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP
    from scapy.packet import Raw

    dns_hits = 0
    icmp_hits = 0
    for p in pkts:
        # DNS tunneling: long high-entropy leftmost label
        if p.haslayer(DNS) and p[DNS].qr == 0:
            qd = _first(p[DNS].qd)
            if qd is not None:
                name = qd.qname.decode("latin-1", "replace") if isinstance(qd.qname, bytes) else str(qd.qname)
                label = name.rstrip(".").split(".")[0]
                if len(label) >= dns_label_min and entropy(label) >= dns_entropy_min:
                    dns_hits += 1
        # ICMP exfil: high-entropy oversized echo payload
        if p.haslayer(ICMP) and int(p[ICMP].type) in (8, 0) and p.haslayer(Raw):
            load = bytes(p[Raw].load)
            if len(load) >= icmp_size_min and entropy(load) >= icmp_entropy_min:
                icmp_hits += 1

    out: list[Finding] = []
    if dns_hits:
        out.append(Finding("dns-tunnel",
                           f"{dns_hits} queries with long high-entropy subdomains",
                           dns_hits, "high" if dns_hits > 3 else "medium"))
    if icmp_hits:
        out.append(Finding("icmp-exfil",
                           f"{icmp_hits} ICMP echoes with high-entropy payloads",
                           icmp_hits, "high" if icmp_hits > 3 else "medium"))
    return out
