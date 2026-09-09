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


# ---- inline preflight -----------------------------------------------------
def test_parse_forward_policy():
    assert doctor.parse_forward_policy("Chain FORWARD (policy DROP)\n...") == "DROP"
    assert doctor.parse_forward_policy("Chain FORWARD (policy ACCEPT)\n") == "ACCEPT"
    assert doctor.parse_forward_policy("no forward chain here") is None


def test_interpret_rp_filter():
    ok, note = doctor.interpret_rp_filter("1", "0")
    assert ok is False and "strict" in note                 # any strict -> not ok
    assert doctor.interpret_rp_filter("0", "0")[0] is True
    assert doctor.interpret_rp_filter("2", "2")[0] is True   # loose is fine


def test_parse_offloads_on():
    out = ("tx-checksumming: on\nrx-checksumming: off\n"
           "generic-segmentation-offload: on\ntcp-segmentation-offload: off\n")
    on = doctor.parse_offloads_on(out)
    assert "tx-checksumming" in on and "generic-segmentation-offload" in on
    assert "rx-checksumming" not in on
    assert doctor.parse_offloads_on("tx-checksumming: off\n") == []


def test_run_inline_preflight_returns_named_checks():
    names = {c.name for c in doctor.run_inline_preflight()}
    assert {"nfqueue-ready", "forward-policy", "rp-filter", "ip-forward"} <= names
    # with an interface, an offloads check is added
    names2 = {c.name for c in doctor.run_inline_preflight(["lo"])}
    assert any(n.startswith("offloads/") for n in names2)


def test_inline_blockers_is_subset_of_failures():
    blockers = doctor.inline_blockers()
    assert all(b.ok is False for b in blockers)
    assert all(hasattr(b, "fix") for b in blockers)


def test_inline_checks_included_in_full_doctor():
    names = {c.name for c in doctor.run_checks()}
    assert {"forward-policy", "rp-filter", "nfqueue-ready"} <= names


# ---- inline engine recommendation -----------------------------------------
def test_recommend_inline_engine_matrix():
    from reforge.diagnostics.doctor import recommend_inline_engine as rec
    # a live MITM + nfqueue -> relay through NFQUEUE
    a = rec(iface_count=1, nfqueue_ok=True, mitm_active=True)
    assert a.engine == "nfqueue" and "MITM" in a.reason and a.alternative
    # two NICs, no MITM -> a transparent bridge is the clean choice
    a = rec(iface_count=2, nfqueue_ok=True, mitm_active=False)
    assert a.engine == "bridge" and "two interfaces" in a.reason
    # two NICs but nfqueue stack absent -> still bridge
    assert rec(iface_count=2, nfqueue_ok=False).engine == "bridge"
    # one NIC, no MITM yet, nfqueue ready -> NFQUEUE (pair with a MITM)
    a = rec(iface_count=1, nfqueue_ok=True, mitm_active=False)
    assert a.engine == "nfqueue" and "single interface" in a.reason
    # one NIC and no nfqueue stack -> neither engine is ready
    a = rec(iface_count=1, nfqueue_ok=False)
    assert a.engine is None and "second interface" in a.tradeoff
