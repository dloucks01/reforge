"""AF_PACKET PACKET_FANOUT multi-core capture backend (fast-path data plane)."""

from __future__ import annotations

import struct

import pytest

from reforge.capture import registry as R
from reforge.capture.base import Frame
from reforge.capture.fanout import (
    FanoutRingBackend,
    configure_fanout,
    fanout_arg,
)


# --- fanout argument encoding -----------------------------------------------
def test_fanout_arg_encodes_id_mode_and_defrag():
    arg = fanout_arg(0x1234, "hash", defrag=False)
    assert arg & 0xFFFF == 0x1234           # group id in the low 16 bits
    assert (arg >> 16) & 0xFF == 0          # hash = mode 0
    lb = fanout_arg(7, "lb", defrag=False)
    assert (lb >> 16) & 0xFF == 1           # lb = mode 1
    # defrag sets the flag in the high half
    assert (fanout_arg(7, "hash", defrag=True) >> 16) & 0x8000


def test_fanout_arg_rejects_unknown_mode():
    with pytest.raises(ValueError):
        fanout_arg(1, "nope")


def test_configure_fanout_sets_the_right_sockopt():
    calls = []

    class _Sock:
        def setsockopt(self, level, opt, val):
            calls.append((level, opt, val))

    configure_fanout(_Sock(), 0x0042, "cpu", defrag=False)
    level, opt, val = calls[0]
    assert level == 263 and opt == 18       # SOL_PACKET, PACKET_FANOUT
    (arg,) = struct.unpack("=I", val)
    assert arg & 0xFFFF == 0x0042 and (arg >> 16) & 0xFF == 2   # cpu = mode 2


# --- registration + selection ----------------------------------------------
def test_registered_and_runnable():
    names = {n for n, _, _ in R.list_backends()}
    assert "af_packet_fanout" in names
    assert R.get_backend("af_packet_fanout").caps.has_dataplane is True


def test_recommended_for_mid_high_rate():
    # only meaningful where fanout is actually available (Linux)
    avail = {n for n, ok, _ in R.list_backends() if ok and R._runnable(n)}
    if "af_packet_fanout" in avail:
        assert R.recommend_backend(8000) == "af_packet_fanout"


# --- aggregation + delegation (no root needed) ------------------------------
def test_recv_burst_aggregates_queued_frames():
    be = FanoutRingBackend(["eth0"], workers=3)
    for i in range(5):
        be._q.put(Frame(data=bytes([i]), ingress="eth0"))
    got = be.recv_burst(max_frames=4, timeout=0.1)
    assert len(got) == 4                    # respects max_frames
    assert be.recv_burst(max_frames=10, timeout=0.1)[0].data == bytes([4])  # the rest


def test_send_burst_delegates_to_a_member():
    sent = []

    class _FakeMember:
        def send_burst(self, frames):
            n = list(frames)
            sent.extend(n)
            return len(n)

    be = FanoutRingBackend(["eth0", "eth1"], member_factory=_FakeMember)
    n = be.send_burst([Frame(data=b"x", egress="eth1")])
    assert n == 1 and len(sent) == 1


def test_capture_stats_aggregate_across_members():
    class _M:
        def __init__(self, r, d):
            self._r, self._d = r, d

        def capture_stats(self):
            return {"received": self._r, "dropped": self._d}

    be = FanoutRingBackend(["eth0"])
    be._members = [_M(100, 2), _M(150, 3)]
    st = be.capture_stats()
    assert st["received"] == 250 and st["dropped"] == 5


def test_invalid_mode_and_no_iface_raise():
    with pytest.raises(ValueError):
        FanoutRingBackend(["eth0"], mode="bogus")
    with pytest.raises(ValueError):
        FanoutRingBackend([])
