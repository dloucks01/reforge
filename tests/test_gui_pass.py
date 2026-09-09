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
    win._inline_flush()                                 # privileged work runs off-thread
    assert "inline via NFQUEUE" in status
    assert ("install", 1, ["10.0.0.5"]) in fake.calls   # one IPC batch, no subprocess
    assert win._nfq_via_helper is True

    win._stop_inline()
    win._inline_flush()
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
    win._inline_flush()
    assert win._nfq_via_helper is False
    # applied the nft diversion rules directly (preflight iptables call aside)
    assert any(c[:5] == ["nft", "add", "table", "inet", "reforge_q"] for c in ran)
    win._stop_inline()                                  # removes via subprocess, no error
    win._inline_flush()


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


# ---- layout pass: attack scroll, intercept collapse, live split, status -----
def test_attacks_panel_sections_in_scrollarea(app):
    from PySide6.QtWidgets import QScrollArea
    from reforge.gui.attacks_panel import AttacksPanel
    p = AttacksPanel()
    # the seven sections live inside a resizable scroll area (no more clipping)
    scrolls = p.findChildren(QScrollArea)
    assert scrolls and scrolls[0].widgetResizable()
    # the scroll content hosts the seven group boxes
    from PySide6.QtWidgets import QGroupBox
    assert len(scrolls[0].widget().findChildren(QGroupBox)) == 7


def test_intercept_apparatus_collapses_when_off(app):
    from reforge.gui.intercept_panel import InterceptPanel
    p = InterceptPanel()
    # off + nothing held -> apparatus hidden, hint shown
    assert p._body_split.isHidden() and not p._collapsed_hint.isHidden()

    # enabling intercept expands it
    p.enable_check.setChecked(True)          # toggled -> _apply_filter -> _sync_body
    assert not p._body_split.isHidden() and p._collapsed_hint.isHidden()

    # disabling collapses again
    p.enable_check.setChecked(False)
    assert p._body_split.isHidden()


def test_intercept_expands_on_held_rows_even_when_off(app):
    from reforge.gui.intercept_panel import InterceptPanel
    p = InterceptPanel()
    assert p._body_split.isHidden()
    p.table.insertRow(0)                     # a rule-fed HOLD populated the queue
    p._sync_body()
    assert not p._body_split.isHidden()      # visible despite the checkbox being off


def test_live_split_follows_intercept_arm(app, monkeypatch):
    win = _win(app)
    calls = []
    monkeypatch.setattr(win, "_set_live_split", lambda armed: calls.append(armed))
    from reforge.rules.matchers import AllMatch
    win.engine = win.rules_panel.build_engine(dry_run=False)
    win._on_intercept_filter(AllMatch(), "all")
    win._on_intercept_filter(None, "")
    assert calls == [True, False]            # armed -> editor room, off -> stream room
    assert win._LIVE_SPLIT_IDLE[0] > win._LIVE_SPLIT_IDLE[1]   # idle favors the stream


def test_status_pill_omits_packet_count(app):
    win = _win(app)

    class _PassiveService:
        running = True

        def drain(self):
            return []

    win.service = _PassiveService()
    win.packets.extend([(0.0, None)] * 5)
    win._refresh_status_pill()
    text = win.status_pill.text()
    assert "read-only" in text and "pkts" not in text and "5" not in text


# ---- follow-up 1: inline privileged work runs off-thread, in order ----------
def test_inline_executor_runs_ops_in_submission_order(app):
    win = _win(app)
    order = []
    win._inline_submit(lambda: order.append("a"))
    win._inline_submit(lambda: order.append("b"))
    win._inline_submit(lambda: order.append("c"))
    win._inline_flush()
    assert order == ["a", "b", "c"]          # FIFO: teardown before a following start


def test_start_inline_returns_before_privileged_work_runs(app, monkeypatch):
    import threading
    win = _win(app)
    gate = threading.Event()
    fake = _FakeHelper()
    orig = fake.queue_install
    fake.queue_install = lambda *a, **k: (gate.wait(2.0), orig(*a, **k))
    monkeypatch.setattr(win, "_helper", lambda: fake)
    monkeypatch.setattr("reforge.capture.nfqueue.NfqueueRunner", _FakeRunner)

    win._start_inline("eth0", ["10.0.0.5"])  # must not block on the gated install
    assert fake.calls == []                  # privileged work still pending on the worker
    gate.set()
    win._inline_flush()
    assert ("install", 1, ["10.0.0.5"]) in fake.calls


# ---- follow-up 2: dry-run is chunked, doesn't block on a big capture --------
def test_dry_run_chunks_and_completes(app, monkeypatch):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from reforge.capture.base import Frame
    from reforge.rules.actions import SetField
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine
    from reforge.rules.filter import parse_filter

    win = _win(app)
    win._DRY_RUN_CHUNK = 3                   # force multiple slices over 10 packets
    for i in range(10):
        dport = 80 if i % 2 == 0 else 22
        win.packets.append((float(i), Frame(data=bytes(Ether() / IP() / TCP(dport=dport)))))

    engine = RuleEngine([Rule("r", parse_filter("TCP.dport == 80"), [SetField("IP", "ttl", 5)])])
    monkeypatch.setattr(win.rules_panel, "specs", ["r"], raising=False)
    monkeypatch.setattr(win.rules_panel, "build_engine", lambda dry_run=True: engine)
    monkeypatch.setattr(win.rules_panel, "refresh", lambda hits: None)

    # drive the chunk function directly (no QTimer / event loop), so the test
    # leaves no pending timers pinning the window
    win._dry_run = {"i": 0, "matched": [], "packets": list(win.packets), "engine": engine}
    steps = 0
    while not win._dry_run_chunk_once():
        steps += 1
    win._dry_run_finish()
    assert steps >= 3                        # 10 packets / chunk 3 -> multiple slices
    assert win._dry_run is None
    assert "5 of 10 packets matched" in win.statusBar().currentMessage()
