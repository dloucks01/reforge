"""Flow tracker — conversation grouping, direction, TCP state."""

from __future__ import annotations

from reforge.core.flows import FlowTracker
from reforge.testlab import traffic as T


def test_mixed_scenario_groups_into_flows():
    ft = FlowTracker()
    for ts, data in T.mixed_scenario():
        ft.observe(ts, data)
    assert ft.count() == 5                       # 2 HTTP, 1 large HTTP, 1 FTP, 1 DNS
    flows = ft.flows()
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
