"""Capture backend registry: recommendation, lookup, listing, interfaces."""

from __future__ import annotations

import pytest

from reforge.capture import registry as R


def test_recommend_prefers_afpacket_for_low_rate():
    assert R.recommend_backend(100) == "af_packet"


def test_recommend_steps_up_when_link_exceeds_afpacket():
    # >2G exceeds af_packet's ceiling; raw_afpacket (always available) carries 5G
    assert R.recommend_backend(3000) == "raw_afpacket"


def test_recommend_returns_a_known_backend_for_huge_rate():
    # 200G exceeds every available ceiling -> fastest available fallback
    assert R.recommend_backend(200000) in {"af_packet", "raw_afpacket", "af_packet_fanout",
                                           "af_xdp", "pf_ring", "dpdk"}


def test_get_backend_and_unknown_raises():
    from reforge.capture.afpacket import AfPacketBackend
    assert R.get_backend("af_packet") is AfPacketBackend
    with pytest.raises(KeyError):
        R.get_backend("no-such-backend")


def test_list_backends_includes_planned_nfqueue():
    names = {n for n, _ok, _note in R.list_backends()}
    assert {"af_packet", "raw_afpacket", "nfqueue"} <= names


def test_list_interfaces_returns_list():
    ifs = R.list_interfaces()
    assert (isinstance(ifs, list) and "lo" not in ifs) or ifs == ["lo"]
