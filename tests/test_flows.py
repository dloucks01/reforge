"""Flow tracker — conversation grouping, direction, TCP state."""

from __future__ import annotations

from reforge.core.flows import FlowTracker
from reforge.testlab import traffic as T


def test_mixed_scenario_groups_into_flows():
    ft = FlowTracker()
    for ts, data in T.mixed_scenario():
        ft.observe(ts, data)
    # richer scenario: HTTP x3, large HTTP, FTP, DNS, TLS, out-of-order, ICMP,
    # UDP syslog, plus an IPv6 HTTP flow — grouped into distinct conversations
    assert ft.count() >= 9
    flows = ft.flows()
    protos = {f.proto for f in flows}
    assert {"TCP", "UDP", "ICMP"} <= protos
    assert any(":" in f.a_ip for f in flows)     # an IPv6 conversation is tracked
    # most-recently-active first
    assert flows == sorted(flows, key=lambda f: f.last, reverse=True)


def test_bidirectional_and_state():
    ft = FlowTracker()
    for ts, data in T.http_login():
        ft.observe(ts, data)
    assert ft.count() == 1                        # A->B and B->A are one flow
    f = ft.flows()[0]
    assert f.proto == "TCP" and f.a_to_b > 0 and f.b_to_a > 0
    assert f.state == "closing"                   # the login flow FINs
    assert f.packets == f.a_to_b + f.b_to_a


def test_dns_one_flow_two_packets():
    ft = FlowTracker()
    for ts, data in T.dns_lookup():
        ft.observe(ts, data)
    f = ft.flows()[0]
    assert f.proto == "UDP" and f.packets == 2 and f.state == "-"


def test_clear_and_bad_input():
    ft = FlowTracker()
    ft.observe(0.0, b"\x00\x00")                  # junk: ignored, no crash
    assert ft.count() == 0
    for ts, data in T.http_login():
        ft.observe(ts, data)
    ft.clear()
    assert ft.count() == 0
