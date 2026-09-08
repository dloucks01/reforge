"""Edge behaviors: TCP reassembler, HTTP framer (chunked/flush), DNS match."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.core.httpframer import HttpFramer
from reforge.core.tcpreasm import TcpReassembler


# ---- reassembler ----------------------------------------------------------
def _seg(seq, data, sport=1000, dport=80, flags="PA", src="10.0.0.1", dst="10.0.0.2"):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq) / data


def test_on_data_callback_and_contiguous_delivery():
    seen = []
    tr = TcpReassembler(on_data=lambda k, d: seen.append(d))
    tr.process(_seg(1000, b"", flags="S"))          # SYN sets ISN (no data)
    tr.process(_seg(1001, b"hello "))
    tr.process(_seg(1007, b"world"))
    assert b"".join(seen) == b"hello world"


def test_duplicate_segment_not_delivered_twice():
    tr = TcpReassembler()
    tr.process(_seg(1000, b"", flags="S"))
    out1 = tr.process(_seg(1001, b"AAAA"))
    out2 = tr.process(_seg(1001, b"AAAA"))          # retransmit of already-delivered
    assert out1 and out1[0][1] == b"AAAA"
    assert out2 == [] or out2[0][1] == b""          # nothing new


def test_out_of_order_then_gap_fill():
    tr = TcpReassembler()
    tr.process(_seg(1000, b"", flags="S"))
    early = tr.process(_seg(1005, b"WORLD"))        # arrives before the gap is filled
    assert early == []                              # buffered, not yet contiguous
    filled = tr.process(_seg(1001, b"HELL"))        # 1001..1004, still short of 1005? no: fills to 1005
    joined = b"".join(d for _k, d in filled)
    assert b"HELL" in joined                        # at least the now-contiguous part

def test_fin_marks_closed_and_evict():
    tr = TcpReassembler()
    tr.process(_seg(1000, b"", flags="S"))
    tr.process(_seg(1001, b"data"))
    tr.process(_seg(1005, b"", flags="FA"))         # FIN -> torn down
    assert tr.closed
    tr.evict()                                      # default evicts closed flows
    assert not tr.closed and not tr.dirs


def test_empty_payload_returns_nothing():
    tr = TcpReassembler()
    assert tr.process(_seg(1000, b"", flags="A")) == []


# ---- HTTP framer ----------------------------------------------------------
def test_framer_content_length_message():
    fr = HttpFramer()
    msg = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    out = fr.feed(msg)
    assert out and out[0] == msg


def test_framer_chunked_message_across_feeds():
    fr = HttpFramer()
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    out = fr.feed(head + body[:5])                  # partial body
    assert out == []                                # not complete yet
    out = fr.feed(body[5:])                         # rest of the chunks
    assert out and out[0].endswith(b"0\r\n\r\n")


def test_framer_flush_returns_close_delimited_remainder():
    fr = HttpFramer()
    # a response with no length and no chunking is delimited by connection close
    fr.feed(b"HTTP/1.1 200 OK\r\n\r\npartial-body-so-far")
    rest = fr.flush()
    assert b"partial-body-so-far" in rest


# ---- dns_spoof _match -----------------------------------------------------
def test_dns_match_exact_wildcard_catchall_and_none():
    from reforge.attacks.dns_spoof import _match
    hm = {"exact.corp": "1.1.1.1", "*.wild.corp": "2.2.2.2", "*": "3.3.3.3"}
    assert _match("exact.corp", hm) == "1.1.1.1"
    assert _match("host.wild.corp", hm) == "2.2.2.2"
    assert _match("anything.else", hm) == "3.3.3.3"        # catch-all
    assert _match("nomatch", {"a.b": "9.9.9.9"}) is None
