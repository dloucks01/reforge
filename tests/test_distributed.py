"""Distributed multi-sensor: in-process merge + network transport."""

from __future__ import annotations

import base64
import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.distributed.collector import Collector
from reforge.distributed.network import CollectorServer, NetworkSink
from reforge.distributed.protocol import Message
from reforge.distributed.sensor import Sensor


def _http_basic(src, dst, user_pass):
    tok = base64.b64encode(user_pass).decode()
    req = f"GET / HTTP/1.1\r\nHost: t\r\nAuthorization: Basic {tok}\r\n\r\n".encode()
    return Ether() / IP(src=src, dst=dst) / TCP(sport=5000, dport=80, flags="PA") / req


def _syn(src, ttl):
    return Ether() / IP(src=src, ttl=ttl) / TCP(dport=80, flags="S",
                                                options=[("MSS", 1460), ("SAckOK", b""),
                                                         ("Timestamp", (1, 0)), ("WScale", 7)])


# ---- in-process merge ------------------------------------------------------
def test_two_sensors_merge_into_collector():
    c = Collector()
    s1 = Sensor("edge-1", c.ingest)
    s2 = Sensor("edge-2", c.ingest)

    s1.observe(_syn("10.0.0.5", 64))                       # Linux host at sensor 1
    s1.observe(_http_basic("10.0.0.5", "10.0.0.9", b"admin:pw1"))
    s2.observe(_http_basic("10.0.0.7", "10.0.0.9", b"bob:pw2"))  # cred at sensor 2

    report = c.report()
    ips = {h["ip"] for h in report.hosts}
    assert {"10.0.0.5", "10.0.0.7", "10.0.0.9"} <= ips
    linux = next(h for h in report.hosts if h["ip"] == "10.0.0.5")
    assert linux["os_family"] == "Linux"
    users = {cr["username"] for cr in report.credentials}
    assert {"admin", "bob"} <= users
    assert c.sensors == {"edge-1", "edge-2"}


def test_cred_dedup_across_sensors():
    c = Collector()
    same = {"kind": "http-basic", "username": "admin", "secret": "x",
            "src": "10.0.0.5", "dst": "10.0.0.9", "proto": "HTTP"}
    c.ingest(Message("a", "cred", same))
    c.ingest(Message("b", "cred", same))                   # duplicate from another sensor
    assert len(c.report().credentials) == 1


# ---- network transport -----------------------------------------------------
def test_network_sensor_to_collector():
    c = Collector()
    srv = CollectorServer(c, bind=("127.0.0.1", 0))
    port = srv.start()
    try:
        sink = NetworkSink("127.0.0.1", port)
        sensor = Sensor("remote", sink)
        sensor.observe(_http_basic("10.9.9.9", "10.0.0.9", b"carol:secret"))
        sensor.event("beacon")
        time.sleep(0.3)                                    # let the server ingest
        sink.close()
    finally:
        srv.stop()

    report = c.report()
    assert any(cr["username"] == "carol" for cr in report.credentials)
    assert any(e.get("text") == "beacon" for e in report.events)
    assert "remote" in c.sensors
