"""Host discovery — ARP sweep (local) and ICMP ping sweep.

Builders + an injectable prober so classification/aggregation is testable; the
real prober uses Scapy srp/sr1.
"""

from __future__ import annotations

from typing import Callable


def build_arp_request(ip: str):
    from scapy.layers.l2 import ARP, Ether

    return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)


def build_ping(ip: str):
    from scapy.layers.inet import ICMP, IP

    return IP(dst=ip) / ICMP()


def arp_sweep(ips: list[str], prober: Callable) -> dict[str, str]:
    """Return {ip: mac} for hosts that answered ARP. prober(pkt)->reply|None."""
    alive: dict[str, str] = {}
    for ip in ips:
        reply = prober(build_arp_request(ip))
        if reply is not None:
            from scapy.layers.l2 import ARP

            if reply.haslayer(ARP):
                alive[ip] = reply.getlayer(ARP).hwsrc
    return alive


def ping_sweep(ips: list[str], prober: Callable) -> list[str]:
    """Return IPs that answered ICMP echo."""
    alive: list[str] = []
    for ip in ips:
        reply = prober(build_ping(ip))
        if reply is not None:
            from scapy.layers.inet import ICMP

            if reply.haslayer(ICMP) and int(reply.getlayer(ICMP).type) == 0:  # echo-reply
                alive.append(ip)
    return alive


def default_arp_prober(iface: str | None = None, timeout: float = 1.0):  # pragma: no cover
    def prober(pkt):
        from scapy.sendrecv import srp1

        return srp1(pkt, iface=iface, timeout=timeout, verbose=False)
    return prober
