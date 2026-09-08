"""ScenarioContext bookkeeping + ScenarioRunner unknown-step/error/yaml paths."""

from __future__ import annotations

import pytest

from reforge.scenario.context import ScenarioContext
from reforge.scenario.runner import ScenarioRunner, load_scenario


def test_context_creds_background_and_teardown():
    ctx = ScenarioContext()
    ctx.add_creds([{"u": 1}, {"u": 2}])
    assert len(ctx.creds) == 2

    stopped = []

    class BG:
        def stop(self):
            stopped.append(1)

    class BadBG:
        def stop(self):
            raise RuntimeError("won't stop")

    ctx.add_background(BG())
    ctx.add_background(BadBG())          # teardown must swallow its error
    ctx.teardown()
    assert stopped == [1] and ctx.background == []


def test_runner_reports_unknown_step():
    rep = ScenarioRunner(dry_run=True).run({"name": "x", "steps": [{"type": "bogus"}]})
    assert any("unknown step" in e["detail"] for e in rep.events)


def test_runner_records_step_error():
    # analyze_pcap on a missing file raises inside the step -> recorded, not fatal
    rep = ScenarioRunner(dry_run=True).run(
        {"name": "x", "steps": [{"type": "analyze_pcap", "params": {"file": "/no/such.pcap"}}]})
    assert any(e["step"] == "analyze_pcap" and "error" in e["detail"] for e in rep.events)


def test_load_scenario_json(tmp_path):
    import json
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"name": "n", "steps": []}))
    assert load_scenario(p)["name"] == "n"


def test_load_scenario_yaml_or_clear_error(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("name: y\nsteps: []\n")
    try:
        import yaml  # noqa: F401
    except ImportError:
        with pytest.raises(RuntimeError, match="PyYAML"):
            load_scenario(p)
    else:
        assert load_scenario(p)["name"] == "y"
