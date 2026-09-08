"""Engagement record — timeline, snapshot, report render, persistence."""

from __future__ import annotations

from reforge.engage import Engagement


def _sample():
    e = Engagement("op-test")
    e.log("capture", "live on lab0")
    e.log("mitm", "ARP: 10.0.0.50 <-> 10.0.0.1")
    e.snapshot(
        hosts=[{"ip": "10.0.0.10", "mac": "aa:bb", "os_family": "Linux",
                "services": {80: "http", 443: "tls"}}],
        creds=[{"kind": "http-basic", "proto": "HTTP", "src": "10.0.0.50",
                "dst": "10.0.0.10", "username": "admin", "secret": "s3cr3t"}])
    return e


def test_render_markdown_and_html():
    e = _sample()
    md = e.render_markdown()
    assert "admin" in md and "Timeline" in md and "10.0.0.10" in md
    html = e.render_html({"packets": 1284, "flows": 5, "modified": 3})
    assert "admin" in html and "op-test" in html and "1284" in html
    assert html.lstrip().startswith("<!doctype html>")


def test_report_json_shape():
    d = _sample().to_report().to_dict()
    assert d["summary"]["hosts"] == 1 and d["summary"]["credentials"] == 1
    assert d["credentials"][0]["username"] == "admin"


def test_persistence_roundtrip(tmp_path):
    e = _sample()
    p = tmp_path / "engagement.json"
    e.save(p)
    back = Engagement.load(p)
    assert back.name == "op-test"
    assert len(back.events) == 2 and back.events[0].kind == "capture"
    assert back.hosts[0]["ip"] == "10.0.0.10"
    assert back.creds[0]["username"] == "admin"


def test_load_missing_and_reset(tmp_path):
    assert Engagement.load(tmp_path / "none.json").name == "engagement"   # fresh
    e = _sample()
    e.reset()
    assert e.events == [] and e.hosts == [] and e.creds == []
