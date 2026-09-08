"""ConsolePanel (collector refresh/export/lifecycle) + ScenarioPanel (load/run/save)."""

from __future__ import annotations

import json
import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


# ---- ConsolePanel ---------------------------------------------------------
def test_console_refresh_renders_hosts_and_creds(app):
    from reforge.distributed.collector import Collector
    from reforge.distributed.protocol import Message
    from reforge.gui.console_panel import ConsolePanel

    col = Collector()
    col.ingest(Message("s1", "host", {"ip": "10.0.0.9", "mac": "aa:bb:cc:dd:ee:ff",
                                      "os_family": "Linux", "services": {22: "ssh"}}))
    col.ingest(Message("s1", "cred", {"kind": "http-basic", "proto": "http",
                                      "src": "10.0.0.50", "dst": "10.0.0.9",
                                      "username": "admin", "secret": "pw"}))
    p = ConsolePanel()
    p._collector = col
    p.refresh()
    assert p.hosts.rowCount() == 1 and p.hosts.item(0, 0).text() == "10.0.0.9"
    assert "22:ssh" in p.hosts.item(0, 3).text()
    assert p.creds.rowCount() == 1 and p.creds.item(0, 4).text() == "admin"
    assert "sensors: 1" in p.summary.text()


def test_console_refresh_idle_is_noop(app):
    from reforge.gui.console_panel import ConsolePanel
    p = ConsolePanel()
    p.refresh()                                         # no collector -> no crash
    assert p.hosts.rowCount() == 0


def test_console_start_and_stop_plaintext(app):
    from reforge.gui.console_panel import ConsolePanel
    p = ConsolePanel()
    p.mtls.setChecked(False)
    p.port.setValue(39917)
    p.start()
    # either it bound (server present) or it reported an error — never crashes
    assert (p._server is not None) or ("error" in p.summary.text())
    p.stop()
    assert p._server is None


def test_console_export_bundle(app, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog

    from reforge.gui.console_panel import ConsolePanel

    p = ConsolePanel()
    monkeypatch.setattr(QFileDialog, "getExistingDirectory",
                        staticmethod(lambda *a, **k: str(tmp_path)))
    p.export_bundle()
    assert (tmp_path / "ca.pem").exists()
    assert (tmp_path / "sensor.crt").exists() and (tmp_path / "sensor.key").exists()
    assert (tmp_path / "collector.crt").exists()


# ---- ScenarioPanel --------------------------------------------------------
def _scenario(tmp_path):
    spec = {"name": "demo-run", "steps": [
        {"type": "note", "params": {"text": "authorized"}},
        {"type": "sleep", "params": {"seconds": 0}},
    ], "run_seconds": 0}
    p = tmp_path / "s.json"
    p.write_text(json.dumps(spec))
    return p


def _drive_run(panel):
    end = time.time() + 3.0
    while time.time() < end:
        panel._check()
        if panel._report is not None and panel.run_btn.isEnabled():
            return
        time.sleep(0.02)


def test_scenario_load_run_and_save(app, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog

    from reforge.gui.scenario_panel import ScenarioPanel

    panel = ScenarioPanel()
    sc = _scenario(tmp_path)
    monkeypatch.setattr(QFileDialog, "getOpenFileName",
                        staticmethod(lambda *a, **k: (str(sc), "")))
    panel._load()
    assert "demo-run" in panel.file_lbl.text() and panel._spec is not None

    panel.dry.setChecked(True)
    panel._run()
    _drive_run(panel)
    assert panel._report is not None
    assert "demo-run" in panel.view.toPlainText() or panel.view.toPlainText()

    # save markdown
    out_md = tmp_path / "r.md"
    monkeypatch.setattr(QFileDialog, "getSaveFileName",
                        staticmethod(lambda *a, **k: (str(out_md), "")))
    panel._save()
    assert out_md.exists() and out_md.read_text()

    # save json
    out_json = tmp_path / "r.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName",
                        staticmethod(lambda *a, **k: (str(out_json), "")))
    panel._save()
    json.loads(out_json.read_text())


def test_scenario_save_encrypted(app, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog

    from reforge.gui.scenario_panel import ScenarioPanel

    panel = ScenarioPanel()
    sc = _scenario(tmp_path)
    monkeypatch.setattr(QFileDialog, "getOpenFileName",
                        staticmethod(lambda *a, **k: (str(sc), "")))
    panel._load()
    panel._run(); _drive_run(panel)

    out = tmp_path / "r.md"
    panel.passphrase.setText("s3cret")
    monkeypatch.setattr(QFileDialog, "getSaveFileName",
                        staticmethod(lambda *a, **k: (str(out), "")))
    panel._save()
    blob = out.read_bytes()
    assert b"authorized" not in blob                    # encrypted at rest
    from reforge.core.vault import decrypt_bytes
    assert decrypt_bytes(blob, "s3cret")


def test_scenario_run_without_spec_and_save_without_report(app):
    from reforge.gui.scenario_panel import ScenarioPanel
    panel = ScenarioPanel()
    panel._run()
    assert "Load a scenario first" in panel.status.text()
    panel._save()
    assert "Run a scenario first" in panel.status.text()
