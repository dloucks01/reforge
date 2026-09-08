"""Test-lab building blocks: traffic builders, replay backend, demo pcap."""

from __future__ import annotations

import time

from scapy.layers.dns import DNS
from scapy.layers.inet import TCP
from scapy.layers.l2 import ARP, Ether

from reforge.testlab import traffic as T
from reforge.testlab.synthetic import SyntheticBackend


def test_tcp_flow_has_handshake_and_teardown():
    frames = T.tcp_flow("10.0.0.1", "10.0.0.2", 80, b"hello", b"world")
    flags = [int(Ether(fb)[TCP].flags) for _ts, fb in frames]
    assert flags[0] & 0x02              # SYN
    assert flags[1] & 0x12 == 0x12      # SYN-ACK
    assert flags[-1] & 0x01             # FIN somewhere at the end


def test_builders_produce_expected_protocols():
    assert Ether(T.dns_lookup()[0][1]).haslayer(DNS)
    assert Ether(T.arp_who_has()[0][1]).haslayer(ARP)


def test_mixed_scenario_ordered_and_nonempty():
    m = T.mixed_scenario()
    assert len(m) > 20
    assert [t for t, _ in m] == sorted(t for t, _ in m)


def test_synthetic_backend_paces_and_exhausts():
    b = SyntheticBackend(speed=1000.0)
    b.open()
    time.sleep(0.05)
    total = 0
    for _ in range(30):
        total += len(b.recv_burst(1000))
        if b.exhausted:
            break
        time.sleep(0.01)
    assert total > 20 and b.exhausted


def test_synthetic_backend_loops():
    b = SyntheticBackend(speed=1000.0, loop=True)
    b.open()
    time.sleep(0.05)
    for _ in range(5):
        b.recv_burst(1000)
        time.sleep(0.005)
    assert not b.exhausted


def test_write_demo_pcap(tmp_path):
    from reforge.capture.pcap import PcapFileBackend
    from reforge.testlab.demo import write_demo_pcap

    path = tmp_path / "demo.pcap"
    n = write_demo_pcap(path)
    backend = PcapFileBackend(path)
    backend.open()
    assert len(backend.recv_burst(1000)) == n and n > 20
    backend.close()


# ---- high-fidelity builders (IPv6 / TLS / out-of-order / ICMP / UDP) -------
def test_ipv6_flow_is_ipv6():
    from scapy.layers.inet6 import IPv6
    p = Ether(T.http6_login()[0][1])
    assert p.haslayer(IPv6)


def test_tls_client_hello_carries_parseable_sni():
    from reforge.attacks.tls_sni import extract_sni
    assert extract_sni(T.tls_client_hello("host.example")) == "host.example"


def test_https_flow_segment_has_sni():
    from scapy.packet import Raw

    from reforge.attacks.tls_sni import extract_sni
    seen = None
    for _t, fb in T.https_client_hello(sni="wiki.corp.local"):
        p = Ether(fb)
        if p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == 443:
            seen = extract_sni(bytes(p[Raw].load))
    assert seen == "wiki.corp.local"


def test_out_of_order_flow_reassembles_exactly():
    from reforge.core.tcpreasm import TcpReassembler
    tr = TcpReassembler()
    streams: dict = {}
    for _t, fb in T.tcp_flow_out_of_order():
        for key, data in tr.process(Ether(fb)):
            streams[key] = streams.get(key, b"") + data
    body = b"".join(streams.values())
    assert b"PART1PART2PART3" in body
    assert body.count(b"PART1") == 1          # retransmit collapsed, not duplicated


def test_icmp_and_udp_builders():
    from scapy.layers.inet import ICMP, UDP
    assert Ether(T.icmp_echo()[0][1]).haslayer(ICMP)
    assert Ether(T.udp_syslog()[0][1]).haslayer(UDP)


def test_mixed_scenario_now_spans_ipv6_and_more_protocols():
    from scapy.layers.inet6 import IPv6
    m = T.mixed_scenario()
    assert any(Ether(fb).haslayer(IPv6) for _t, fb in m)
    assert len(m) > 30
