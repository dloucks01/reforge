"""IDS/IPS evasion technique generators."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.evasion import techniques as E


def _tcp_pkt(payload: bytes, seq: int = 1000):
    return Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=1234, dport=80, seq=seq) / payload


# ---- IP fragmentation ------------------------------------------------------
def test_ip_fragment_reassembles_to_original():
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / (b"X" * 40)
    frags = E.ip_fragment(pkt, fragsize=8)
    assert len(frags) >= 5
    # reassemble with scapy's defragment
    from scapy.layers.inet import defragment

    reasm = defragment([Ether(f)[IP] for f in frags])
    assert bytes(reasm[0].payload) == b"X" * 40


def test_ip_fragment_reverse_order():
    pkt = Ether() / IP() / (b"Y" * 32)
    a = E.ip_fragment(pkt, fragsize=8)
    b = E.ip_fragment(pkt, fragsize=8, reverse=True)
    assert a == list(reversed(b))


def test_overlapping_fragments_have_conflicting_offset0():
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / (b"REALDATA" + b"Z" * 16)
    frags = [Ether(f) for f in E.overlapping_fragments(pkt, decoy=b"EVILEVIL")]
    at0 = [f for f in frags if f[IP].frag == 0]
    assert len(at0) >= 2                                  # decoy + real both at offset 0
    payloads = {bytes(f[IP].payload)[:8] for f in at0}
    assert b"EVILEVIL" in payloads and b"REALDATA" in payloads


# ---- TCP segmentation ------------------------------------------------------
def test_tcp_segments_cover_payload_in_order():
    pkt = _tcp_pkt(b"ABCDEFGHIJ", seq=5000)
    segs = [Ether(s) for s in E.tcp_segments(pkt, seg=2)]
    assert len(segs) == 5
    ordered = sorted(segs, key=lambda s: s[TCP].seq)
    joined = b"".join(bytes(s[TCP].payload) for s in ordered)
    assert joined == b"ABCDEFGHIJ"
    assert ordered[0][TCP].seq == 5000 and ordered[1][TCP].seq == 5002


def test_tcp_segments_checksums_valid():
    segs = E.tcp_segments(_tcp_pkt(b"HELLO", seq=1), seg=1)
    for s in segs:
        pkt = Ether(s)
        stored = pkt[TCP].chksum
        del pkt[TCP].chksum
        assert Ether(bytes(pkt))[TCP].chksum == stored


def test_overlapping_segments_same_seq_conflicting_data():
    segs = [Ether(s) for s in E.overlapping_segments(_tcp_pkt(b"GETXY", seq=42), decoy=b"EVIL")]
    assert len(segs) == 2
    assert segs[0][TCP].seq == segs[1][TCP].seq == 42
    assert bytes(segs[0][TCP].payload) != bytes(segs[1][TCP].payload)


# ---- TTL / checksum decoys -------------------------------------------------
def test_ttl_decoy():
    segs = [Ether(s) for s in E.ttl_decoy(_tcp_pkt(b"REAL", seq=7), decoy=b"EVIL", low_ttl=1)]
    decoy, real = segs
    assert decoy[IP].ttl == 1 and real[IP].ttl != 1
    assert decoy[TCP].seq == real[TCP].seq == 7
    assert bytes(real[TCP].payload) == b"REAL"


def test_bad_checksum_decoy():
    segs = [Ether(s) for s in E.bad_checksum_decoy(_tcp_pkt(b"REAL", seq=9), decoy=b"EVIL")]
    decoy, real = segs
    # decoy carries the pinned invalid checksum; real is valid
    assert decoy[TCP].chksum == 0xDEAD
    r = real
    stored = r[TCP].chksum
    del r[TCP].chksum
    assert Ether(bytes(r))[TCP].chksum == stored


def test_registry_and_apply():
    assert "ttl_decoy" in E.TECHNIQUES
    out = E.apply_evasion(_tcp_pkt(b"data"), "tcp_segments", seg=2)
    assert isinstance(out, list) and out
