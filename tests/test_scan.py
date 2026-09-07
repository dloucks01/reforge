"""Active scanning: target parsing, SYN classification, connect scan, engine."""

from __future__ import annotations

import socket

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import ARP, Ether

from reforge.scan import discovery, tcp
from reforge.scan.engine import ScanEngine
from reforge.scan.targets import expand_targets, parse_ports


# ---- targets ---------------------------------------------------------------
def test_expand_cidr_and_range():
    assert expand_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert expand_targets("192.168.1.5-7") == ["192.168.1.5", "192.168.1.6", "192.168.1.7"]
    assert expand_targets("10.0.0.1, 10.0.0.1") == ["10.0.0.1"]      # de-duped


def test_parse_ports():
    assert parse_ports("22,80,443,8000-8002") == [22, 80, 443, 8000, 8001, 8002]


# ---- SYN classification ----------------------------------------------------
def test_classify_open_closed_filtered():
    assert tcp.classify(IP() / TCP(flags="SA")) == tcp.OPEN
    assert tcp.classify(IP() / TCP(flags="R")) == tcp.CLOSED
    assert tcp.classify(IP() / ICMP(type=3, code=3)) == tcp.FILTERED
    assert tcp.classify(None) == tcp.FILTERED


def test_syn_scanner_with_fake_prober():
    replies = {22: IP() / TCP(flags="SA"), 23: IP() / TCP(flags="R"), 80: None}

    def prober(pkt):
        return replies[int(pkt[TCP].dport)]

    states = tcp.SynScanner(prober).scan("10.0.0.9", [22, 23, 80])
    assert states == {22: "open", 23: "closed", 80: "filtered"}


def test_build_syn_fields():
    pkt = tcp.build_syn("10.0.0.9", 443, sport=40000)
    assert pkt[IP].dst == "10.0.0.9" and pkt[TCP].dport == 443
    assert int(pkt[TCP].flags) & 0x02 and pkt[TCP].sport == 40000


# ---- connect scan (real sockets, localhost) --------------------------------
def test_connect_scan_open_and_closed():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    open_port = srv.getsockname()[1]
    try:
        sc = tcp.ConnectScanner(timeout=1.0)
        assert sc.scan_port("127.0.0.1", open_port) == tcp.OPEN
        # an unbound high port on loopback refuses -> closed
        assert sc.scan_port("127.0.0.1", 1) in (tcp.CLOSED, tcp.FILTERED)
    finally:
        srv.close()


# ---- discovery builders ----------------------------------------------------
def test_arp_request_and_sweep():
    req = discovery.build_arp_request("10.0.0.9")
    assert req[ARP].pdst == "10.0.0.9" and req[Ether].dst == "ff:ff:ff:ff:ff:ff"

    def prober(pkt):
        ip = pkt[ARP].pdst
        return Ether() / ARP(op=2, psrc=ip, hwsrc="aa:bb:cc:dd:ee:ff") if ip == "10.0.0.9" else None

    alive = discovery.arp_sweep(["10.0.0.9", "10.0.0.10"], prober)
    assert alive == {"10.0.0.9": "aa:bb:cc:dd:ee:ff"}


# ---- engine aggregation ----------------------------------------------------
def test_engine_feeds_inventory():
    class FakeScanner:
        def scan(self, host, ports):
            return {p: ("open" if p in (22, 80) else "closed") for p in ports}

    eng = ScanEngine()
    results = eng.scan_ports(["10.0.0.9"], [22, 80, 81], FakeScanner(),
                             banners=True, banner_fn=lambda h, p: f"svc{p}")
    assert eng.open_ports(results) == {"10.0.0.9": [22, 80]}
    host = eng.inv.hosts["10.0.0.9"]
    assert host.services[22] == "open svc22" and 81 not in host.services
