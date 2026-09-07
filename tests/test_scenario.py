"""Scenario runner + report."""

from __future__ import annotations

import base64
import json

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from reforge.scenario.report import build_report
from reforge.scenario.runner import ScenarioRunner, load_scenario


def _creds_pcap(path):
    tok = base64.b64encode(b"admin:hunter2").decode()
    req = f"GET /a HTTP/1.1\r\nHost: t\r\nAuthorization: Basic {tok}\r\n\r\n".encode()
    pkts = [
        Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=5000, dport=80, seq=1, flags="PA") / req,
        Ether() / IP(src="10.0.0.9", dst="10.0.0.5") / TCP(sport=22, seq=1, flags="PA") / b"SSH-2.0-OpenSSH_9\r\n",
    ]
    wrpcap(str(path), pkts)


def test_scenario_analyze_and_report(tmp_path):
    pcap = tmp_path / "cap.pcap"
    _creds_pcap(pcap)
    spec = {
        "name": "loot-a-pcap",
        "steps": [
            {"type": "note", "params": {"text": "engagement start"}},
            {"type": "analyze_pcap", "params": {"file": str(pcap)}},
            {"type": "scan", "params": {"target": "10.0.0.9", "ports": "22"}},  # dry-run skips
        ],
    }
    report = ScenarioRunner(dry_run=True).run(spec)

    assert report.name == "loot-a-pcap"
    assert any(c["kind"] == "http-basic" and c["username"] == "admin"
               for c in report.credentials)
    assert any(h["ip"] == "10.0.0.9" for h in report.hosts)
    assert "T1040" in report.techniques and "T1046" in report.techniques
    # timeline recorded the steps
    steps = [e["step"] for e in report.events]
    assert "analyze_pcap" in steps and "note" in steps


def test_report_markdown_and_json(tmp_path):
    pcap = tmp_path / "c.pcap"
    _creds_pcap(pcap)
    spec = {"name": "r", "steps": [{"type": "analyze_pcap", "params": {"file": str(pcap)}}]}
    report = ScenarioRunner(dry_run=True).run(spec)

    md = report.to_markdown()
    assert "# Engagement report" in md and "admin" in md and "## Credentials" in md
    parsed = json.loads(report.to_json())
    assert parsed["summary"]["credentials"] >= 1


def test_dry_run_skips_root_steps():
    spec = {"name": "s", "steps": [
        {"type": "arp_spoof", "params": {"iface": "eth0", "victim": "10.0.0.5",
                                         "gateway": "10.0.0.1"}},
    ]}
    report = ScenarioRunner(dry_run=True).run(spec)
    # attack recorded as a technique + a dry-run skip event, but nothing started
    assert "T1557.002" in report.techniques
    assert any("dry-run" in e["detail"] for e in report.events)


def test_load_scenario_json(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"name": "x", "steps": [{"type": "note", "params": {"text": "hi"}}]}))
    spec = load_scenario(f)
    assert spec["name"] == "x"


def test_unknown_step_is_skipped():
    report = ScenarioRunner(dry_run=True).run({"name": "s", "steps": [{"type": "nope"}]})
    assert any("unknown step" in e["detail"] for e in report.events)
