"""NDP (IPv6) MITM engine — pure logic (router parse, NA poison/restore batches)."""

from __future__ import annotations

from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6

from reforge.attacks.ndp_mitm import NdpMitm, na_packet, parse_default_router6


def test_parse_default_router6():
    rt = ("default via fe80::1 dev eth0 proto ra metric 100\n"
          "fd00::/64 dev eth0 proto kernel metric 256\n")
    assert parse_default_router6(rt) == "fe80::1"
    assert parse_default_router6("fd00::/64 dev eth0") is None
    assert parse_default_router6("") is None


def test_na_packet_sets_override_and_lladdr():
    na = na_packet("fd00::1", "aa:aa:aa:aa:aa:aa", "aa:aa:aa:aa:aa:aa",
                   "fd00::50", "11:11:11:11:11:11")
    assert na[IPv6].src == "fd00::1" and na[IPv6].dst == "fd00::50"
    assert na[ICMPv6ND_NA].tgt == "fd00::1"
    assert int(na[ICMPv6ND_NA].O) == 1 and int(na[ICMPv6ND_NA].S) == 1
    assert na[ICMPv6NDOptDstLLAddr].lladdr == "aa:aa:aa:aa:aa:aa"


def _session():
    m = NdpMitm("eth0", ["fd00::50", "fd00::51"], router="fd00::1")
    m.our_mac = "aa:aa:aa:aa:aa:aa"
    m.router_mac = "bb:bb:bb:bb:bb:bb"
    m.victim_macs = {"fd00::50": "11:11:11:11:11:11", "fd00::51": "22:22:22:22:22:22"}
    return m


def test_poison_batch_both_directions():
    m = _session()
    b = m.poison_batch()
    assert len(b) == 4                       # 2 victims x 2 directions
    # first: victim ::50 told the router (fd00::1) is at our MAC
    assert b[0][IPv6].dst == "fd00::50"
    assert b[0][ICMPv6ND_NA].tgt == "fd00::1"
    assert b[0][ICMPv6NDOptDstLLAddr].lladdr == "aa:aa:aa:aa:aa:aa"
    # second: router told victim ::50 is at our MAC
    assert b[1][IPv6].dst == "fd00::1"
    assert b[1][ICMPv6ND_NA].tgt == "fd00::50"
    assert b[1][ICMPv6NDOptDstLLAddr].lladdr == "aa:aa:aa:aa:aa:aa"


def test_restore_batch_uses_real_macs():
    m = _session()
    r = m.restore_batch()
    assert len(r) == 4
    assert r[0][ICMPv6NDOptDstLLAddr].lladdr == "bb:bb:bb:bb:bb:bb"   # real router MAC
    assert r[1][ICMPv6NDOptDstLLAddr].lladdr == "11:11:11:11:11:11"   # real victim MAC


def test_unresolved_victims_skipped():
    m = _session()
    m.victim_macs.pop("fd00::51")
    assert len(m.poison_batch()) == 2
    assert m.active_targets() == ["fd00::50"]
    st = m.status()
    assert st["router"] == "fd00::1"
    assert st["targets"] == ["fd00::50"]
    assert st["unresolved"] == ["fd00::51"]
    assert st["running"] is False


def test_no_batch_without_router_mac():
    m = NdpMitm("eth0", ["fd00::50"], router="fd00::1")
    m.our_mac = "aa:aa:aa:aa:aa:aa"
    m.victim_macs = {"fd00::50": "11:11:11:11:11:11"}
    assert m.poison_batch() == []            # router_mac unresolved -> nothing


def test_dedupes_victims():
    m = NdpMitm("eth0", ["fd00::50", "fd00::50", "", "fd00::51"])
    assert m.victims == ["fd00::50", "fd00::51"]


def test_rogue_ra_flag_default_off():
    m = NdpMitm("eth0", ["fd00::50"])
    assert m.rogue_ra is False
    assert NdpMitm("eth0", ["fd00::50"], rogue_ra=True).rogue_ra is True
