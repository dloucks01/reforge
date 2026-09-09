"""Flow tracker — group captured packets into conversations.

A flat packet list is hard to triage; operators think in connections. This folds
frames into bidirectional flows keyed by the canonical 5-tuple (so A->B and B->A
are one flow), tracking per-direction packets/bytes, first/last time, and a coarse
TCP state. Pure over bytes, so it is unit-tested without a NIC.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Flow:
    proto: str
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    packets: int = 0
    bytes: int = 0
    a_to_b: int = 0            # packets a->b
    b_to_a: int = 0
    first: float = 0.0
    last: float = 0.0
    _flags: set = field(default_factory=set)   # TCP flags seen across the flow

    @property
    def endpoints(self) -> str:
        ap = f"{self.a_ip}:{self.a_port}" if self.a_port else self.a_ip
        bp = f"{self.b_ip}:{self.b_port}" if self.b_port else self.b_ip
        return f"{ap} ↔ {bp}"

    @property
    def duration(self) -> float:
        return max(0.0, self.last - self.first)

    @property
    def state(self) -> str:
        if self.proto != "TCP":
            return "-"
        f = self._flags
        if "R" in f:
            return "reset"
        if "F" in f:
            return "closing"
        if "S" in f and "A" in f:
            return "established"
        if "S" in f:
            return "opening"
        return "active"


def _dissect(data: bytes):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether

    eth = Ether(data)
    ip = eth.getlayer(IP) or eth.getlayer(IPv6)
    if ip is None:
        return None
    l4 = ip.getlayer(TCP) or ip.getlayer(UDP)
    if l4 is not None:
        proto = l4.__class__.__name__
        return proto, str(ip.src), int(l4.sport), str(ip.dst), int(l4.dport), l4
    proto = (ip.getlayer("ICMP") and "ICMP") or ip.__class__.__name__
    return (proto if isinstance(proto, str) else "IP"), str(ip.src), 0, str(ip.dst), 0, None


class FlowTracker:
    def __init__(self):
        self._flows: dict[tuple, Flow] = {}

    def observe(self, ts: float, data: bytes) -> None:
        try:
            info = _dissect(data)
        except Exception:
            return
        if info is None:
            return
        proto, src, sport, dst, dport, l4 = info
        # canonical, direction-independent key
        ends = tuple(sorted([(src, sport), (dst, dport)]))
        key = (proto, ends)
        flow = self._flows.get(key)
        if flow is None:
            (aip, ap), (bip, bp) = ends
            flow = Flow(proto, aip, ap, bip, bp, first=ts, last=ts)
            self._flows[key] = flow
        flow.packets += 1
        flow.bytes += len(data)
        flow.last = ts
        if flow.first == 0.0:
            flow.first = ts
        if (src, sport) == (flow.a_ip, flow.a_port):
            flow.a_to_b += 1
        else:
            flow.b_to_a += 1
        if l4 is not None and proto == "TCP":
            try:
                flow._flags |= set(str(l4.flags))
            except Exception:
                pass

    def flows(self) -> list[Flow]:
        """Flows, most-recently-active first."""
        return sorted(self._flows.values(), key=lambda f: f.last, reverse=True)

    def count(self) -> int:
        return len(self._flows)

    def clear(self) -> None:
        self._flows.clear()
