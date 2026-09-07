"""Passive fingerprinting — OS guess from TCP SYNs, service/version from banners.

p0f-style: infer the OS from the SYN's initial TTL, TCP window, and options
(MSS, window scale, SACK, timestamps). Service detection reads cleartext banners
(SSH/FTP/SMTP) and HTTP Server headers, plus TLS SNI. Passive; heuristic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class OSGuess:
    family: str
    initial_ttl: int
    window: int
    mss: int | None
    confidence: str
    detail: str = ""


def _initial_ttl(ttl: int) -> int:
    for base in (64, 128, 255):
        if ttl <= base:
            return base
    return 255


def os_from_syn(pkt) -> OSGuess | None:
    """Guess the sender OS from a bare TCP SYN (not SYN-ACK)."""
    from scapy.layers.inet import IP, TCP

    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return None
    tcp = pkt[TCP]
    flags = int(tcp.flags)
    if not (flags & 0x02) or (flags & 0x10):        # SYN set, ACK clear
        return None

    ttl = int(pkt[IP].ttl)
    itl = _initial_ttl(ttl)
    win = int(tcp.window)
    opts = dict((o[0], o[1]) if isinstance(o, tuple) else (o, None) for o in tcp.options)
    mss = opts.get("MSS")
    has_ts = "Timestamp" in opts
    has_sack = "SAckOK" in opts
    has_ws = "WScale" in opts

    if itl == 128:
        fam, conf = "Windows", "high" if has_ws else "medium"
    elif itl == 255:
        fam, conf = "network device / Solaris", "medium"
    elif itl == 64:
        if has_ts and has_sack and has_ws:
            fam, conf = "Linux", "high"
        elif not has_ts and has_sack:
            fam, conf = "macOS / *BSD", "medium"
        else:
            fam, conf = "Linux / Unix", "low"
    else:
        fam, conf = "unknown", "low"

    detail = f"ttl={ttl}(itl={itl}) win={win} mss={mss} ts={has_ts} sack={has_sack} ws={has_ws}"
    return OSGuess(fam, itl, win, mss, conf, detail)


@dataclass
class ServiceInfo:
    host: str
    port: int
    service: str
    version: str = ""


_SSH = re.compile(rb"^SSH-\d+\.\d+-(\S+)")
_HTTP_SERVER = re.compile(rb"(?im)^Server:\s*(.+?)\s*$")


def service_from_packet(pkt) -> list[ServiceInfo]:
    """Detect a service/version from a packet's cleartext banner/headers."""
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return []
    payload = bytes(pkt[Raw].load)
    src = pkt[IP].src
    sport = int(pkt[TCP].sport)
    out: list[ServiceInfo] = []

    m = _SSH.match(payload)
    if m:
        out.append(ServiceInfo(src, sport, "ssh", m.group(1).decode("latin-1", "replace")))

    m = _HTTP_SERVER.search(payload)
    if payload[:5] == b"HTTP/" and m:
        out.append(ServiceInfo(src, sport, "http", m.group(1).decode("latin-1", "replace")))

    if payload[:4] == b"220 " or payload[:4] == b"220-":
        banner = payload.split(b"\r\n", 1)[0][4:].decode("latin-1", "replace")
        svc = {21: "ftp", 25: "smtp", 587: "smtp"}.get(sport, "banner")
        out.append(ServiceInfo(src, sport, svc, banner))

    return out
