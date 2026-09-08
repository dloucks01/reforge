"""Sensor observation + a real sensor->collector network round-trip (loopback)."""

from __future__ import annotations

import time

from scapy.layers.l2 import Ether

from reforge.distributed.collector import Collector
from reforge.distributed.network import CollectorServer, NetworkSink
from reforge.distributed.protocol import Message
from reforge.distributed.sensor import Sensor
from reforge.testlab import traffic as T


def test_sensor_emits_creds_and_hosts_in_process():
    msgs: list[Message] = []
    sensor = Sensor("s1", msgs.append)
    for _ts, fb in T.http_login(user="admin", password="pw"):
        sensor.observe(Ether(fb))
    kinds = {m.kind for m in msgs}
    assert "cred" in kinds and "host" in kinds
    creds = [m.data for m in msgs if m.kind == "cred"]
    assert any(c.get("username") == "admin" for c in creds)
    # a repeated observation does not re-emit the same credential
    for _ts, fb in T.http_login(user="admin", password="pw"):
        sensor.observe(Ether(fb))
    assert len([m for m in msgs if m.kind == "cred"]) == len(creds)  # deduped


def test_sensor_event_message():
    msgs: list[Message] = []
    Sensor("s2", msgs.append).event("started capture")
    assert msgs and msgs[0].kind == "event" and msgs[0].data["text"] == "started capture"


def test_network_roundtrip_sensor_to_collector():
    col = Collector()
    srv = CollectorServer(col, bind=("127.0.0.1", 0))
    port = srv.start()
    sink = None
    try:
        sink = NetworkSink("127.0.0.1", port)
        sensor = Sensor("remote-1", sink)
        for _ts, fb in T.http_login(user="carol", password="pw"):
            sensor.observe(Ether(fb))

        # the collector ingests asynchronously; poll for the credential
        end = time.time() + 3.0
        while time.time() < end and not any(c.get("username") == "carol"
                                            for c in col.creds):
            time.sleep(0.05)
        assert any(c.get("username") == "carol" for c in col.creds)
        assert "remote-1" in col.sensors
    finally:
        if sink is not None:
            sink.close()
        srv.stop()
