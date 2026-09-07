"""TCP reassembler, HTTP framer, and stream-aware credential harvesting."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.attacks.stream_harvester import StreamHarvester
from reforge.core.httpframer import HttpFramer
from reforge.core.tcpreasm import DirectionBuffer, TcpReassembler


# ---- DirectionBuffer -------------------------------------------------------
def test_in_order():
    b = DirectionBuffer()
    assert b.add(1000, b"AAAA") == b"AAAA"
    assert b.add(1004, b"BBBB") == b"BBBB"


def test_out_of_order_then_gap_fill():
    b = DirectionBuffer()
    b.set_isn(1000)
    assert b.add(1004, b"BBBB") == b""        # future segment buffered
    assert b.add(1000, b"AAAA") == b"AAAABBBB"  # gap fills, both delivered


def test_pure_retransmit_ignored():
    b = DirectionBuffer()
    assert b.add(1000, b"AAAA") == b"AAAA"
    assert b.add(1000, b"AAAA") == b""         # duplicate: nothing new


def test_front_overlap_trimmed():
    b = DirectionBuffer()
    assert b.add(1000, b"AAAA") == b"AAAA"
    # retransmit overlapping the last 2 bytes plus 2 new bytes
    assert b.add(1002, b"AACC") == b"CC"


def test_seq_wraparound():
    b = DirectionBuffer()
    start = (1 << 32) - 3
    assert b.add(start, b"AAAAA") == b"AAAAA"  # wraps 0xFFFFFFFD..+5
    assert b.next == 2


# ---- TcpReassembler --------------------------------------------------------
def _seg(seq, payload, sport=1234, dport=80, flags="A"):
    return Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=sport, dport=dport,
                                                              seq=seq, flags=flags) / payload


def test_reassembler_reorders_segments():
    r = TcpReassembler()
    r.process(_seg(5000, b"", flags="S"))            # SYN -> ISN 5001
    out2 = r.process(_seg(5007, b"world"))           # out of order (5007..5011)
    out1 = r.process(_seg(5001, b"hello "))          # fills gap (5001..5006)
    assert out2 == []
    assert out1 and out1[0][1] == b"hello world"


# ---- HttpFramer ------------------------------------------------------------
def test_framer_content_length_across_feeds():
    f = HttpFramer()
    assert f.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHE") == []
    msgs = f.feed(b"LLO")
    assert len(msgs) == 1 and msgs[0].endswith(b"\r\n\r\nHELLO")


def test_framer_chunked():
    f = HttpFramer()
    msg = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5\r\nHELLO\r\n5\r\nWORLD\r\n0\r\n\r\n")
    got = f.feed(msg)
    assert len(got) == 1 and got[0] == msg


def test_framer_response_body_delimited_by_close():
    f = HttpFramer()
    # HTTP/1.0-style response: no Content-Length, no chunked -> body until close
    assert f.feed(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n<html>") == []
    assert f.feed(b"<body>page</body></html>") == []          # still buffering
    msg = f.flush()                                            # connection closed
    assert msg.endswith(b"\r\n\r\n<html><body>page</body></html>")


def test_framer_request_without_length_has_no_body():
    f = HttpFramer()
    got = f.feed(b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n")
    assert len(got) == 1 and got[0].endswith(b"\r\n\r\n")      # emitted, no body waited on


def test_framer_chunked_with_extension_and_trailers():
    f = HttpFramer()
    msg = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5;name=v\r\nHELLO\r\n0\r\nX-Trailer: v\r\n\r\n")   # chunk ext + trailer
    got = f.feed(msg)
    assert len(got) == 1 and got[0] == msg


def test_reassembler_overlapping_out_of_order():
    from reforge.core.tcpreasm import DirectionBuffer

    b = DirectionBuffer()
    assert b.add(1000, b"AAAA") == b"AAAA"        # 1000-1003
    assert b.add(1006, b"CCCC") == b""            # buffered (gap at 1004-1005)
    # overlaps the tail of the first seg and fills the gap up to the buffered seg
    assert b.add(1002, b"AABB") == b"BBCCCC"
    assert b.next == 1010


def test_framer_pipelined_requests():
    f = HttpFramer()
    stream = (b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
              b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n")
    got = f.feed(stream)
    assert len(got) == 2
    assert got[0].startswith(b"GET /a") and got[1].startswith(b"GET /b")


# ---- stream credential harvesting (multi-segment) --------------------------
def test_multisegment_ftp_creds():
    h = StreamHarvester()
    # USER and PASS split into separate segments of the same flow
    assert h.add_frame(bytes(_seg(100, b"USER alice\r\n", sport=5000, dport=21))) == []
    creds = h.add_frame(bytes(_seg(112, b"PASS s3cr3t\r\n", sport=5000, dport=21)))
    c = next(c for c in creds if c.proto == "FTP")
    assert c.username == "alice" and c.secret == "s3cr3t"


def test_multisegment_http_basic():
    import base64

    h = StreamHarvester()
    tok = base64.b64encode(b"root:toor").decode()
    req = f"GET / HTTP/1.1\r\nHost: t\r\nAuthorization: Basic {tok}\r\n\r\n".encode()
    # deliver the request split mid-header across two segments
    assert h.add_frame(bytes(_seg(200, req[:20], sport=6000, dport=80))) == []
    creds = h.add_frame(bytes(_seg(200 + 20, req[20:], sport=6000, dport=80)))
    c = next(c for c in creds if c.kind == "http-basic")
    assert c.username == "root" and c.secret == "toor"
