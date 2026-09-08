"""Scenario step registry + the offline-safe step bodies (note/sleep/covert)."""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from reforge.scenario import steps as ST
from reforge.scenario.context import ScenarioContext


def test_step_registry_tags():
    assert ST.STEPS["note"].needs_root is False
    assert ST.STEPS["arp_spoof"].needs_root is True
    assert ST.STEPS["analyze_pcap"].attack == "T1040"
    assert ST.STEPS["scan"].attack == "T1046"
    assert ST.STEPS["detect_covert"].attack == "T1048"
    # every registered step carries a callable
    assert all(callable(s.fn) for s in ST.STEPS.values())


def test_note_and_sleep_record_events():
    ctx = ScenarioContext()
    ST.s_note(ctx, {"text": "authorized lab"})
    assert ctx.notes == ["authorized lab"]
    ST.s_sleep(ctx, {"seconds": 0})
    kinds = [e.step for e in ctx.events]
    assert "note" in kinds and "sleep" in kinds


def test_scan_step_dry_run_records_without_scanning():
    ctx = ScenarioContext(dry_run=True)
    ST.s_scan(ctx, {"target": "10.0.0.0/30", "ports": "22"})
    assert ctx.scans == {}                            # nothing actually scanned
    assert any(e.step == "scan" and "dry-run" in e.detail for e in ctx.events)


def test_detect_covert_flags_suspicious_dns(tmp_path):
    # a long, high-entropy DNS label looks like tunneling / exfil
    label = "z7x2q9w4k1m8b3n6v5c0a7s2d9f4g1h8"
    pkt = (Ether() / IP(src="10.0.0.50", dst="10.0.0.1")
           / UDP(sport=5555, dport=53)
           / DNS(rd=1, qd=DNSQR(qname=f"{label}.exfil.example")))
    pcap = tmp_path / "covert.pcap"
    wrpcap(str(pcap), [pkt])

    ctx = ScenarioContext()
    ST.s_detect_covert(ctx, {"file": str(pcap)})
    assert any(e.step == "detect_covert" for e in ctx.events)
    assert any("covert" in n for n in ctx.notes)      # the DNS channel was flagged
