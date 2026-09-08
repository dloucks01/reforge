"""Doctor checks + health snapshot / rate metering."""

from __future__ import annotations

from reforge.diagnostics import doctor
from reforge.diagnostics.health import RateMeter, snapshot, system_stats


def test_run_checks_returns_named_checks():
    checks = doctor.run_checks()
    names = {c.name for c in checks}
    assert {"python", "scapy", "pyside6"} <= names
    for c in checks:
        assert c.name and isinstance(c.ok, bool) and isinstance(c.detail, str)


def test_run_doctor_text_and_json(capsys):
    rc = doctor.run_doctor(as_json=False)
    text = capsys.readouterr().out
    assert rc in (0, 1)
    assert "[PASS]" in text or "[FAIL]" in text          # human format printed


def test_rate_meter_computes_per_second():
    m = RateMeter()
    assert m.update({"captured": 0}, now=0.0) == {}      # first snapshot: no rate
    rates = m.update({"captured": 100}, now=1.0)
    assert rates["captured_per_s"] == 100.0


def test_snapshot_from_capture_service_like():
    class Svc:
        running = True
        captured = 42
        dropped = 3
    snap = snapshot(Svc())
    assert snap["running"] is True
    assert snap["counters"] == {"captured": 42, "dropped": 3}
    assert "cpu_count" in snap["system"]


def test_snapshot_from_bridge_like_with_meter():
    class Counters:
        def as_dict(self):
            return {"forwarded": 10, "dropped": 1}

    class Bridge:
        running = True
        counters = Counters()
    m = RateMeter()
    snapshot(Bridge(), m)                                # prime
    snap = snapshot(Bridge(), m)
    assert snap["counters"]["forwarded"] == 10 and "rates" in snap


def test_system_stats():
    s = system_stats()
    assert "cpu_count" in s and "loadavg" in s
