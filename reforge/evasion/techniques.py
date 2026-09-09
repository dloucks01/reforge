"""IDS/IPS evasion techniques (insertion/evasion, Ptacek-Newsham style).

Each generator takes a base packet and returns a list of on-wire frames (bytes)
that a naive IDS reconstructs differently from the target host — for testing
whether detection reassembles correctly. Techniques:

- ip_fragment: split into IP fragments (optionally reversed / tiny).
- overlapping_fragments: a decoy fragment overlapping the real data (first-wins
  IDS sees the decoy; last-wins host sees the real bytes).
- tcp_segments: split the TCP payload into many small segments (optionally
  reordered / overlapping with a decoy).
- ttl_decoy: a decoy segment whose TTL expires before the target (the IDS
  inserts it into its stream, the host never receives it).
- bad_checksum_decoy: a decoy with an invalid checksum (accepted by a lax IDS,
  dropped by the host).

For authorized testing only.
"""

from __future__ import annotations


def _split_eth(pkt):
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether

    return pkt.getlayer(Ether), pkt.getlayer(IP)


def _wrap(eth, ip) -> bytes:
    from scapy.layers.l2 import Ether

    if eth is not None:
        return bytes(Ether(src=eth.src, dst=eth.dst, type=eth.type) / ip)
    return bytes(ip)


def _recompute(ip):
    for lyr, fields in ((ip, ("len", "chksum")),):
        for f in fields:
            if hasattr(lyr, f):
                try:
                    delattr(lyr, f)
                except Exception:
                    pass
    from scapy.layers.inet import TCP, UDP

    for L in (TCP, UDP):
        if ip.haslayer(L):
            try:
                delattr(ip[L], "chksum")
            except Exception:
                pass
            if L is UDP:
                try:
                    delattr(ip[L], "len")
                except Exception:
                    pass
    return ip


# ---- IP fragmentation ------------------------------------------------------
def ip_fragment(pkt, fragsize: int = 8, reverse: bool = False) -> list[bytes]:
    from scapy.layers.inet import fragment

    fragsize = max(8, (fragsize // 8) * 8)              # must be a multiple of 8
    eth, ip = _split_eth(pkt)
    frags = fragment(ip, fragsize=fragsize)
    if reverse:
        frags = list(reversed(frags))
    return [_wrap(eth, f) for f in frags]


def overlapping_fragments(pkt, decoy: bytes = b"EVILEVIL") -> list[bytes]:
    """A decoy fragment at offset 0 overlapping the real first fragment."""
    from scapy.layers.inet import IP, fragment

    eth, ip = _split_eth(pkt)
    real = fragment(ip, fragsize=8)
    if not real:
        return [_wrap(eth, ip)]
    payload = bytes(ip.payload)
    # decoy fragment: offset 0, MF=1, carrying the decoy bytes (padded to 8)
    d = decoy[:8].ljust(8, b"\x00")
    decoy_ip = IP(src=ip.src, dst=ip.dst, proto=ip.proto, id=ip.id, flags="MF", frag=0) / d
    out = [_wrap(eth, decoy_ip)]                        # IDS (first-wins) keeps decoy
    out += [_wrap(eth, f) for f in real]               # host (last-wins) keeps real
    _ = payload
    return out


# ---- TCP segmentation ------------------------------------------------------
def _resegment(ip, seq, chunk: bytes):
    from scapy.layers.inet import TCP
    from scapy.packet import Raw

    seg = ip.copy()
    tcp = seg[TCP]
    tcp.remove_payload()
    tcp.add_payload(Raw(chunk))
    tcp.seq = seq
    return _recompute(seg)


def tcp_segments(pkt, seg: int = 1, reverse: bool = False) -> list[bytes]:
    from scapy.layers.inet import TCP

    eth, ip = _split_eth(pkt)
    if ip is None or not ip.haslayer(TCP):
        return [_wrap(eth, ip)]
    payload = bytes(ip[TCP].payload)
    base = int(ip[TCP].seq)
    seg = max(1, seg)
    out = []
    for i in range(0, len(payload), seg):
        out.append(_wrap(eth, _resegment(ip, (base + i) & 0xFFFFFFFF, payload[i:i + seg])))
    if reverse:
        out = list(reversed(out))
    return out or [_wrap(eth, ip)]


def overlapping_segments(pkt, decoy: bytes = b"EVIL") -> list[bytes]:
    """Emit a decoy segment then the real segment at the SAME sequence number."""
    from scapy.layers.inet import TCP

    eth, ip = _split_eth(pkt)
    if ip is None or not ip.haslayer(TCP):
        return [_wrap(eth, ip)]
    base = int(ip[TCP].seq)
    real = bytes(ip[TCP].payload)
    decoy_seg = _wrap(eth, _resegment(ip, base, decoy.ljust(len(real), b"\x00")[:max(len(real), 1)]))
    real_seg = _wrap(eth, _resegment(ip, base, real))
    return [decoy_seg, real_seg]


def ttl_decoy(pkt, decoy: bytes = b"EVILDATA", low_ttl: int = 1) -> list[bytes]:
    """Decoy segment with a TTL that expires before the target, then the real one."""
    from scapy.layers.inet import IP, TCP

    eth, ip = _split_eth(pkt)
    if ip is None or not ip.haslayer(TCP):
        return [_wrap(eth, ip)]
    base = int(ip[TCP].seq)
    decoy_ip = _resegment(ip, base, decoy)
    decoy_ip[IP].ttl = low_ttl
    _recompute(decoy_ip)
    return [_wrap(eth, decoy_ip), _wrap(eth, ip)]


def bad_checksum_decoy(pkt, decoy: bytes = b"EVILDATA", bad: int = 0xDEAD) -> list[bytes]:
    """Decoy segment with an invalid TCP checksum, then the real (valid) one."""
    from scapy.layers.inet import TCP

    eth, ip = _split_eth(pkt)
    if ip is None or not ip.haslayer(TCP):
        return [_wrap(eth, ip)]
    base = int(ip[TCP].seq)
    decoy_ip = _resegment(ip, base, decoy)
    decoy_ip[TCP].chksum = bad                          # pinned invalid checksum
    return [_wrap(eth, decoy_ip), _wrap(eth, ip)]


TECHNIQUES = {
    "ip_fragment": ip_fragment,
    "ip_fragment_reverse": lambda p: ip_fragment(p, reverse=True),
    "overlapping_fragments": overlapping_fragments,
    "tcp_segments": tcp_segments,
    "overlapping_segments": overlapping_segments,
    "ttl_decoy": ttl_decoy,
    "bad_checksum_decoy": bad_checksum_decoy,
}


def apply_evasion(pkt, technique: str, **opts) -> list[bytes]:
    fn = TECHNIQUES.get(technique)
    if fn is None:
        raise KeyError(f"unknown evasion technique: {technique}")
    return fn(pkt, **opts) if opts else fn(pkt)
