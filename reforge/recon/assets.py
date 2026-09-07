"""Asset inventory built passively from observed traffic.

Tracks hosts (IP/MAC), their OS guess, discovered services, and requested
hostnames (from TLS SNI / HTTP Host), so an operator gets a live network map
without sending a single packet.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from reforge.recon.fingerprint import os_from_syn, service_from_packet


@dataclass
class Host:
    ip: str
    mac: str = ""
    os_family: str = ""
    os_confidence: str = ""
    services: dict = field(default_factory=dict)     # port -> "service version"
    hostnames: set = field(default_factory=set)
    last_seen: float = 0.0


class AssetInventory:
    def __init__(self):
        from reforge.core.scapy_init import warmup
        warmup()
        self.hosts: dict[str, Host] = {}

    def _host(self, ip: str, mac: str = "") -> Host:
        h = self.hosts.get(ip)
        if h is None:
            h = Host(ip=ip)
            self.hosts[ip] = h
        if mac and not h.mac:
            h.mac = mac
        h.last_seen = time.time()
        return h

    def observe(self, pkt) -> None:
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether

        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None:
            return
        eth = pkt.getlayer(Ether)
        smac = eth.src if eth else ""
        src = self._host(str(ip.src), smac)
        self._host(str(ip.dst))

        # OS guess from the sender's SYN
        guess = os_from_syn(pkt)
        if guess and not src.os_family:
            src.os_family = guess.family
            src.os_confidence = guess.confidence

        # services/banners advertised by the sender
        for svc in service_from_packet(pkt):
            self._host(svc.host).services[svc.port] = (svc.service + " " + svc.version).strip()

        # requested hostnames (TLS SNI / HTTP Host)
        for name in _hostnames(pkt):
            src.hostnames.add(name)

    def list_hosts(self) -> list[Host]:
        return sorted(self.hosts.values(), key=lambda h: h.ip)


def _hostnames(pkt) -> list[str]:
    from scapy.packet import Raw

    names: list[str] = []
    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        # TLS SNI (ClientHello)
        from reforge.attacks.tls_sni import extract_sni

        sni = extract_sni(payload)
        if sni:
            names.append(sni)
        # HTTP Host header
        import re

        m = re.search(rb"(?im)^Host:\s*(.+?)\s*$", payload)
        if m and payload[:3] in (b"GET", b"POS", b"PUT", b"HEA", b"DEL", b"OPT", b"PAT"):
            names.append(m.group(1).decode("latin-1", "replace"))
    return names
