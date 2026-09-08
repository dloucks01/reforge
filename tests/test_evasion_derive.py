"""Evasion techniques (decoys + dispatch) and derive_actions field path."""

from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.evasion import techniques as E


def _pkt(payload=b"REALDATA-1234567890"):
    return Ether() / IP(dst="10.0.0.9") / TCP(sport=1000, dport=80, seq=100) / payload


def test_ttl_decoy_emits_decoy_then_real():
    out = E.ttl_decoy(_pkt(), decoy=b"EVILDATA", low_ttl=1)
    assert len(out) == 2
    decoy, real = Ether(out[0]), Ether(out[1])
    assert decoy[IP].ttl == 1                       # decoy expires early
    assert decoy[IP].ttl != real[IP].ttl


def test_bad_checksum_decoy_has_pinned_bad_checksum():
    out = E.bad_checksum_decoy(_pkt(), decoy=b"EVILDATA", bad=0xDEAD)
    assert len(out) == 2
    assert Ether(out[0])[TCP].chksum == 0xDEAD      # decoy's checksum is invalid


def test_apply_evasion_dispatch_and_unknown():
    for tech in ("ip_fragment", "tcp_segments", "ttl_decoy", "bad_checksum_decoy",
                 "overlapping_fragments", "overlapping_segments", "ip_fragment_reverse"):
        out = E.apply_evasion(_pkt(), tech)
        assert isinstance(out, list) and out
    with pytest.raises(KeyError):
        E.apply_evasion(_pkt(), "nope")


def test_apply_evasion_passes_opts():
    out = E.apply_evasion(_pkt(), "ip_fragment", fragsize=8)
    assert len(out) > 1


# ---- derive_actions: header field edit -> SetField ------------------------
def test_derive_field_change_reproduces_on_fresh_packet():
    from reforge.core.apply import apply_engine
    from reforge.rules.base import Rule
    from reforge.rules.derive import derive_actions, describe_actions
    from reforge.rules.engine import RuleEngine
    from reforge.rules.matchers import AllMatch

    original = bytes(Ether() / IP(dst="10.0.0.1") / TCP(dport=80) / b"body")
    edited = bytes(Ether() / IP(dst="10.0.0.9") / TCP(dport=80) / b"body")
    actions = derive_actions(original, edited)
    assert actions, "expected a derived action for the changed IP.dst"
    assert describe_actions(actions)

    eng = RuleEngine([Rule("x", AllMatch(), actions)])
    res = apply_engine(eng, original)
    assert Ether(res.out)[IP].dst == "10.0.0.9"     # the edit reproduced


def test_derive_identical_is_empty():
    from reforge.rules.derive import derive_actions
    raw = bytes(Ether() / IP() / TCP() / b"same")
    assert derive_actions(raw, raw) == []
