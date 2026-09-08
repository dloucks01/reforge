"""ARP MITM engine — pure logic (gateway parse, subnet, poison/restore batches)."""

from __future__ import annotations

from scapy.layers.l2 import ARP

from reforge.attacks.arp_mitm import ArpMitm, parse_default_gateway, subnet_hosts


def test_parse_default_gateway():
    rt = ("default via 10.0.0.1 dev eth0 proto dhcp metric 100\n"
          "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.50\n")
    assert parse_default_gateway(rt) == "10.0.0.1"
    assert parse_default_gateway("10.0.0.0/24 dev eth0") is None


def test_subnet_hosts():
    assert subnet_hosts("10.0.0.50", 30) == ["10.0.0.49"]        # excludes self
    assert "10.0.0.50" not in subnet_hosts("10.0.0.50", 24)
    assert len(subnet_hosts("10.0.0.50", 24)) == 253
    assert len(subnet_hosts("10.0.0.50", 22, cap=100)) == 100    # capped


def _session():
    m = ArpMitm("eth0", ["10.0.0.51", "10.0.0.52"], gateway="10.0.0.1")
    m.our_mac = "aa:aa:aa:aa:aa:aa"
    m.gateway_mac = "bb:bb:bb:bb:bb:bb"
    m.victim_macs = {"10.0.0.51": "11:11:11:11:11:11", "10.0.0.52": "22:22:22:22:22:22"}
    return m


def test_poison_batch_both_directions():
    m = _session()
    b = m.poison_batch()
    assert len(b) == 4                       # 2 victims x 2 directions
    # first frame: victim 51 is told the gateway (10.0.0.1) is at our MAC
    assert b[0][ARP].pdst == "10.0.0.51"
    assert b[0][ARP].psrc == "10.0.0.1"
    assert b[0][ARP].hwsrc == "aa:aa:aa:aa:aa:aa"
    # second: gateway is told victim 51 is at our MAC
    assert b[1][ARP].pdst == "10.0.0.1"
    assert b[1][ARP].psrc == "10.0.0.51"
    assert b[1][ARP].hwsrc == "aa:aa:aa:aa:aa:aa"


def test_restore_batch_heals_caches():
    m = _session()
    r = m.restore_batch()
    assert len(r) == 4
    # restore tells victim 51 the gateway's REAL mac
    assert r[0][ARP].psrc == "10.0.0.1" and r[0][ARP].hwsrc == "bb:bb:bb:bb:bb:bb"


def test_unresolved_victim_skipped():
    m = _session()
    m.victim_macs.pop("10.0.0.52")
    assert len(m.poison_batch()) == 2
    assert m.active_targets() == ["10.0.0.51"]
    assert m.status()["unresolved"] == ["10.0.0.52"]


def test_status_shape():
    m = _session()
    st = m.status()
    assert st["gateway"] == "10.0.0.1"
    assert set(st["targets"]) == {"10.0.0.51", "10.0.0.52"}
    assert st["forwarding_on"] is False and st["sent"] == 0
