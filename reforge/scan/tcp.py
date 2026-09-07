"""TCP port scanning — SYN scan (raw) and connect scan (sockets).

The SYN scanner separates packet crafting + response classification from the
send/receive step (an injectable `prober`), so classification is fully testable
without root or a network. The connect scanner uses ordinary sockets.
"""

from __future__ import annotations

import socket
from typing import Callable

OPEN, CLOSED, FILTERED = "open", "closed", "filtered"


def build_syn(dst: str, dport: int, sport: int = 44444, seq: int = 0):
    from scapy.layers.inet import IP, TCP

    return IP(dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq)


def classify(reply) -> str:
    """Classify a SYN-scan reply into open / closed / filtered."""
    if reply is None:
        return FILTERED
    from scapy.layers.inet import ICMP, TCP

    if reply.haslayer(TCP):
        flags = int(reply[TCP].flags)
        if (flags & 0x12) == 0x12:          # SYN+ACK
            return OPEN
        if flags & 0x04:                    # RST
            return CLOSED
    if reply.haslayer(ICMP):
        return FILTERED                     # unreachable / admin-prohibited
    return FILTERED


class SynScanner:
    def __init__(self, prober: Callable, sport: int = 44444):
        self.prober = prober                # prober(pkt) -> reply|None
        self.sport = sport

    def scan_port(self, host: str, port: int) -> str:
        return classify(self.prober(build_syn(host, port, self.sport)))

    def scan(self, host: str, ports: list[int]) -> dict[int, str]:
        return {p: self.scan_port(host, p) for p in ports}


class ConnectScanner:
    """Full TCP connect scan (no root needed)."""

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    def scan_port(self, host: str, port: int) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            rc = s.connect_ex((host, port))
        except socket.timeout:
            return FILTERED
        except OSError:
            return FILTERED
        finally:
            s.close()
        if rc == 0:
            return OPEN
        if rc in (111,):                    # ECONNREFUSED
            return CLOSED
        return FILTERED

    def scan(self, host: str, ports: list[int]) -> dict[int, str]:
        return {p: self.scan_port(host, p) for p in ports}


def default_prober(timeout: float = 1.0):  # pragma: no cover (needs root/net)
    """Real SYN prober using Scapy sr1."""
    def prober(pkt):
        from scapy.sendrecv import sr1

        return sr1(pkt, timeout=timeout, verbose=False)
    return prober
