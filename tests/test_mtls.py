"""Mutual TLS on the distributed collector transport."""

from __future__ import annotations

import socket
import time

from reforge.distributed.collector import Collector
from reforge.distributed.network import CollectorServer, NetworkSink
from reforge.distributed.tls import dev_mtls
from reforge.distributed.sensor import Sensor


def _base32frame():
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    import base64

    tok = base64.b64encode(b"root:toor").decode()
    req = f"GET / HTTP/1.1\r\nHost: t\r\nAuthorization: Basic {tok}\r\n\r\n".encode()
    return bytes(Ether() / IP(src="10.0.0.9", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / req)


def test_mtls_authenticated_sensor_reports():
    server_ctx, client_ctx, _ = dev_mtls()
    c = Collector()
    srv = CollectorServer(c, bind=("127.0.0.1", 0), ssl_context=server_ctx)
    port = srv.start()
    try:
        from scapy.layers.l2 import Ether

        sink = NetworkSink("127.0.0.1", port, ssl_context=client_ctx, server_hostname="collector")
        Sensor("remote", sink).observe(Ether(_base32frame()))
        time.sleep(0.3)
        sink.close()
    finally:
        srv.stop()
    assert any(cr["username"] == "root" for cr in c.report().credentials)


def test_mtls_rejects_plaintext_client():
    server_ctx, _client_ctx, _ = dev_mtls()
    c = Collector()
    srv = CollectorServer(c, bind=("127.0.0.1", 0), ssl_context=server_ctx)
    port = srv.start()
    try:
        # a plaintext client (no cert, no TLS) must not be able to inject anything
        raw = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            raw.sendall(b'{"sensor":"evil","kind":"cred","data":{"username":"attacker"}}\n')
        except OSError:
            pass
        time.sleep(0.3)
        raw.close()
    finally:
        srv.stop()
    assert c.report().credentials == []          # injection rejected by the TLS layer


def test_mtls_rejects_wrong_ca_client():
    server_ctx, _c1, _ca1 = dev_mtls()
    _s2, client_ctx_other, _ca2 = dev_mtls()      # client cert from a DIFFERENT CA
    c = Collector()
    srv = CollectorServer(c, bind=("127.0.0.1", 0), ssl_context=server_ctx)
    port = srv.start()
    rejected = False
    try:
        try:
            NetworkSink("127.0.0.1", port, ssl_context=client_ctx_other, server_hostname="collector")
        except Exception:
            rejected = True
    finally:
        srv.stop()
    assert rejected                               # untrusted client cert refused
