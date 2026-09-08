"""TPACKET_V3 ring parsing — pure block walking + stats decode (no root)."""

from __future__ import annotations

import struct

from reforge.capture import mmap_ring as ring


def _tp3_hdr(next_off: int, sec: int, nsec: int, snaplen: int, tp_mac: int) -> bytes:
    # tpacket3_hdr: next_offset,sec,nsec,snaplen,len,status (u32 x6), tp_mac,tp_net (u16)
    # + variant1 (rxhash u32, vlan_tci u32, vlan_tpid u16, pad u16) + tp_padding[8] = 48 bytes
    hdr = struct.pack("<IIIIIIHH", next_off, sec, nsec, snaplen, snaplen, 1, tp_mac, tp_mac)
    return hdr + b"\x00" * (48 - len(hdr))


def _build_block(frames: list[bytes]) -> bytearray:
    """Hand-build a TPACKET_V3 block descriptor + frames for the walker."""
    tp_mac = 48                       # frame bytes start right after the 48-byte header
    offset_to_first = 48              # block descriptor header size we use
    buf = bytearray(65536)
    # descriptor: version@0, offset_to_priv@4, block_status@8, num_pkts@12,
    #             offset_to_first_pkt@16
    struct.pack_into("<I", buf, 8, ring.TP_STATUS_USER)      # block_status
    struct.pack_into("<I", buf, 12, len(frames))             # num_pkts
    struct.pack_into("<I", buf, 16, offset_to_first)         # offset_to_first_pkt
    off = offset_to_first
    for i, data in enumerate(frames):
        last = (i == len(frames) - 1)
        entry = _tp3_hdr(0 if last else (48 + len(data) + 8), 100 + i, 500 + i,
                         len(data), tp_mac)
        buf[off:off + len(entry)] = entry
        buf[off + tp_mac:off + tp_mac + len(data)] = data
        off += 48 + len(data) + 8     # advance past header+data (+pad) for next frame
    return buf


def test_walk_block_yields_frames_in_order():
    frames = [b"\xaa\xbb" + b"first-frame", b"\xcc\xdd" + b"second-frame-longer"]
    buf = _build_block(frames)
    out = list(ring.walk_block(buf, 0))
    assert [f.data for f in out] == frames
    assert out[0].sec == 100 and out[0].nsec == 500
    assert out[1].sec == 101 and out[1].nsec == 501


def test_walk_block_empty():
    buf = bytearray(65536)
    struct.pack_into("<I", buf, 12, 0)         # num_pkts = 0
    assert list(ring.walk_block(buf, 0)) == []


def test_block_status_roundtrip():
    buf = _build_block([b"x" * 10])
    assert ring.block_status(buf, 0) & ring.TP_STATUS_USER
    ring.set_block_status(buf, 0, ring.TP_STATUS_KERNEL)
    assert ring.block_status(buf, 0) == ring.TP_STATUS_KERNEL


def test_parse_tpacket_stats():
    assert ring.parse_tpacket_stats(struct.pack("<II", 1000, 37)) == (1000, 37)
    # v3 struct (adds freeze count) still decodes the first two counters
    assert ring.parse_tpacket_stats(struct.pack("<III", 1000, 37, 2)) == (1000, 37)
    assert ring.parse_tpacket_stats(b"\x00\x00") == (0, 0)      # short / empty


def test_build_tpacket_req3():
    req = ring.build_tpacket_req3(1 << 20, 8, 2048)
    bs, bn, fs, fn, _tov, _priv, _feat = struct.unpack("<7I", req)
    assert bs == 1 << 20 and bn == 8 and fs == 2048
    assert fn == (1 << 20) * 8 // 2048        # frame count derived
