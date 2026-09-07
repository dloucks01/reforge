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
