"""TPACKET_V3 (PACKET_MMAP) ring structures and block walking.

The raw AF_PACKET backend can read frames from a kernel-mapped RX ring instead
of one `recv()` per packet: the kernel fills shared memory in blocks and we walk
them, which is the standard high-rate capture path on Linux and cuts syscall and
copy overhead sharply under load.

The ring *setup* (mmap, PACKET_RX_RING) needs a live socket and root, but the
byte-level walking — following `tp_next_offset` through a block, decoding the
per-frame TPACKET_V3 header, reading the kernel drop counters — is pure and
unit-tested here against hand-built buffers, so the hot-path parsing is verified
without a NIC. Layout per linux/if_packet.h (tpacket_block_desc / tpacket3_hdr).
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import NamedTuple

# setsockopt / ring constants (Linux, SOL_PACKET = 263)
SOL_PACKET = 263
PACKET_RX_RING = 5
PACKET_STATISTICS = 6
PACKET_VERSION = 10
TPACKET_V3 = 2

# block_status / tp_status ownership flags
TP_STATUS_KERNEL = 0          # kernel owns the block
TP_STATUS_USER = 1            # userspace may read the block

# tpacket_block_desc: version(u32) offset_to_priv(u32) then tpacket_hdr_v1:
#   block_status(u32) num_pkts(u32) offset_to_first_pkt(u32) blk_len(u32)
#   seq_num(u64) ts_first(8) ts_last(8)
_BLOCK_STATUS_OFF = 8         # block_status u32 at offset 8 of the block descriptor
_NUM_PKTS_OFF = 12
_OFFSET_TO_FIRST_OFF = 16

# tpacket3_hdr (48 bytes): next_offset, sec, nsec, snaplen, len, status(u32),
#   tp_mac(u16), tp_net(u16), then variant + padding.
_TP3_HDR = struct.Struct("<IIIIIIHH")   # up to tp_net; rest unused for walking


class RingFrame(NamedTuple):
    data: bytes
    sec: int
    nsec: int


def block_status(buf, block_off: int) -> int:
    """Ownership word of the block at `block_off` (TP_STATUS_USER == ready)."""
    return struct.unpack_from("<I", buf, block_off + _BLOCK_STATUS_OFF)[0]


def set_block_status(buf, block_off: int, value: int) -> None:
    """Hand a block back to the kernel (value=TP_STATUS_KERNEL) after reading."""
    struct.pack_into("<I", buf, block_off + _BLOCK_STATUS_OFF, value)


def walk_block(buf, block_off: int) -> Iterator[RingFrame]:
    """Yield every frame in the ready block at `block_off`.

    Follows `tp_next_offset` for `num_pkts` frames; each frame's on-wire bytes
    start at `pkt_off + tp_mac` and run `tp_snaplen` bytes. Pure over `buf`.
    """
    num_pkts = struct.unpack_from("<I", buf, block_off + _NUM_PKTS_OFF)[0]
    if not num_pkts:
        return
    off = block_off + struct.unpack_from("<I", buf, block_off + _OFFSET_TO_FIRST_OFF)[0]
    for _ in range(num_pkts):
        next_off, sec, nsec, snaplen, _tlen, _status, tp_mac, _tp_net = \
            _TP3_HDR.unpack_from(buf, off)
        start = off + tp_mac
        yield RingFrame(bytes(buf[start:start + snaplen]), sec, nsec)
        if not next_off:            # last frame in the block
            break
        off += next_off


def parse_tpacket_stats(raw: bytes) -> tuple[int, int]:
    """Decode a PACKET_STATISTICS getsockopt result -> (packets, drops).

    tpacket_stats is (tp_packets, tp_drops); the v3 struct appends
    tp_freeze_q_cnt. Both start with the two counters we care about.
    """
    if len(raw) < 8:
        return (0, 0)
    packets, drops = struct.unpack_from("<II", raw, 0)
    return (packets, drops)


def build_tpacket_req3(block_size: int, block_count: int,
                       frame_size: int, timeout_ms: int = 60) -> bytes:
    """Pack a tpacket_req3 for setsockopt(PACKET_RX_RING).

    struct tpacket_req3 { unsigned tp_block_size, tp_block_nr, tp_frame_size,
    tp_frame_nr, tp_retire_blk_tov, tp_sizeof_priv, tp_feature_req_word; }.
    """
    frame_nr = (block_size * block_count) // frame_size
    return struct.pack("<7I", block_size, block_count, frame_size, frame_nr,
                       timeout_ms, 0, 0)
