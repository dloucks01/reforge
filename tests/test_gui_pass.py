"""GUI pass: inline start/stop routes through the privileged helper when present,
and the drain timer throttles heavy refreshes (2026-09 review §3.8, §3.12)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


def _win(app):
    from reforge.gui.main_window import MainWindow
    return MainWindow()


class _FakeHelper:
    def __init__(self):
        self.calls = []

    def queue_install(self, q, victims=None, apply=True):
        self.calls.append(("install", q, victims))

    def queue_remove(self, apply=True):
        self.calls.append(("remove",))


class _FakeRunner:
    def __init__(self, *a, **k):
        pass

    def run(self):
        pass

    def stop(self):
        pass


# ---- §3.8 / item-1 wiring: privileged nft config via the helper ------------
def test_start_inline_uses_helper_when_available(app, monkeypatch):
    win = _win(app)
    fake = _FakeHelper()
    monkeypatch.setattr(win, "_helper", lambda: fake)
    monkeypatch.setattr("reforge.capture.nfqueue.NfqueueRunner", _FakeRunner)

    status = win._start_inline("eth0", ["10.0.0.5"])
    assert "inline via NFQUEUE" in status
    assert ("install", 1, ["10.0.0.5"]) in fake.calls   # one IPC batch, no subprocess
    assert win._nfq_via_helper is True

    win._stop_inline()
    assert ("remove",) in fake.calls                    # torn down via the helper too
    assert win._nfq_via_helper is False


def test_start_inline_falls_back_to_subprocess_without_helper(app, monkeypatch):
    win = _win(app)
    monkeypatch.setattr(win, "_helper", lambda: None)
    monkeypatch.setattr("reforge.capture.nfqueue.NfqueueRunner", _FakeRunner)
    ran = []
    monkeypatch.setattr("subprocess.run",
                        lambda cmd, **k: ran.append(cmd) or None)

    win._start_inline("eth0", ["10.0.0.5"])
    assert win._nfq_via_helper is False
    # applied the nft diversion rules directly (preflight iptables call aside)
    assert any(c[:5] == ["nft", "add", "table", "inet", "reforge_q"] for c in ran)
    win._stop_inline()                                  # removes via subprocess, no error


# ---- §3.12: drain throttles the heavy per-tick refreshes -------------------
class _IdleService:
    running = True

    def drain(self):
        return []


def test_drain_throttles_heavy_refreshes(app, monkeypatch):
    win = _win(app)
    win.service = _IdleService()

    health = {"n": 0}
    recon = {"n": 0}
    monkeypatch.setattr(win.diag_panel, "refresh_health", lambda: health.__setitem__("n", health["n"] + 1))
    monkeypatch.setattr(win.recon_panel, "refresh", lambda: recon.__setitem__("n", recon["n"] + 1))

    for _ in range(10):
        win._drain()

    # 10 ticks at 1/5 cadence -> the heavy refreshes ran exactly twice (ticks 5, 10)
    assert health["n"] == 2
    assert recon["n"] == 2
    assert win._SLOW_TICK_EVERY == 5
