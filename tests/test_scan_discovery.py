"""Host discovery: ARP/ping sweeps with injectable probers (no network)."""

from __future__ import annotations

from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether

from reforge.scan import discovery as D


def test_build_arp_and_ping():
    arp = D.build_arp_request("10.0.0.5")
    assert arp.haslayer(ARP) and arp[ARP].pdst == "10.0.0.5"
    assert arp[Ether].dst == "ff:ff:ff:ff:ff:ff"
    ping = D.build_ping("10.0.0.5")
    assert ping.haslayer(ICMP) and ping[IP].dst == "10.0.0.5"


def test_arp_sweep_collects_responders():
    macs = {"10.0.0.1": "aa:aa:aa:aa:aa:01", "10.0.0.2": "aa:aa:aa:aa:aa:02"}

    def prober(pkt):
        ip = pkt[ARP].pdst
        if ip in macs:
            return Ether() / ARP(op=2, psrc=ip, hwsrc=macs[ip])
        return None                                  # no answer

    alive = D.arp_sweep(["10.0.0.1", "10.0.0.2", "10.0.0.9"], prober)
    assert alive == macs                             # .9 didn't answer


def test_ping_sweep_only_counts_echo_replies():
    def prober(pkt):
        ip = pkt[IP].dst
        if ip == "10.0.0.1":
            return IP() / ICMP(type=0)               # echo-reply -> alive
        if ip == "10.0.0.2":
            return IP() / ICMP(type=3)               # dest-unreach -> not alive
        return None

    assert D.ping_sweep(["10.0.0.1", "10.0.0.2", "10.0.0.3"], prober) == ["10.0.0.1"]
