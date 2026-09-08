"""SYN classification + connect scan (localhost) — no root."""

from __future__ import annotations

import socket

from scapy.layers.inet import ICMP, IP, TCP

from reforge.scan.tcp import CLOSED, FILTERED, OPEN, ConnectScanner, SynScanner, classify


def test_classify_all_cases():
    assert classify(None) == FILTERED
    assert classify(IP() / TCP(flags="SA")) == OPEN
    assert classify(IP() / TCP(flags="R")) == CLOSED
    assert classify(IP() / ICMP(type=3, code=3)) == FILTERED
    assert classify(IP()) == FILTERED                      # no TCP/ICMP


def test_syn_scanner_with_injected_prober():
    open_ports = {80, 443}

    def prober(pkt):
        dport = int(pkt[TCP].dport)
        if dport in open_ports:
            return IP() / TCP(flags="SA")
        if dport == 22:
            return IP() / TCP(flags="R")
        return None                                        # filtered

    sc = SynScanner(prober)
    res = sc.scan("10.0.0.9", [80, 443, 22, 8080])
    assert res == {80: OPEN, 443: OPEN, 22: CLOSED, 8080: FILTERED}


def test_connect_scan_closed_port_on_localhost():
    # bind+close a socket to get a definitely-closed port
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    result = ConnectScanner(timeout=0.5).scan_port("127.0.0.1", port)
    assert result in (CLOSED, FILTERED)                    # nothing listening


def test_connect_scan_open_port_on_localhost():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert ConnectScanner(timeout=0.5).scan_port("127.0.0.1", port) == OPEN
    finally:
        srv.close()
