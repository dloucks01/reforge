"""Smart fuzzing tab.

Pick a seed (the current Builder packet, a selected capture, or a pcap), choose
strategies, preview generated variants offline, or run a live campaign that
sends each variant, classifies the target's response, and lists findings.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from PySide6.QtCore import QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from reforge.capture.registry import list_interfaces
from reforge.fuzzing import monitor as mon
from reforge.fuzzing import strategies as St
from reforge.fuzzing.campaign import FuzzCampaign
from reforge.fuzzing.corpus import seeds_from_pcap


class FuzzingPanel(QWidget):
    def __init__(self, *, get_builder_bytes: Callable[[], bytes | None],
                 get_selected_packet: Callable[[], bytes | None], parent=None):
        super().__init__(parent)
        self._get_builder = get_builder_bytes
        self._get_selected = get_selected_packet
        self._seed: bytes | None = None
        self._extra_seeds: list[bytes] = []
        self._worker: threading.Thread | None = None
        self._report = None

        root = QVBoxLayout(self)

        # seed row
        srow = QHBoxLayout()
        b1 = QPushButton("Seed from builder"); b1.clicked.connect(self._seed_builder)
        b2 = QPushButton("Seed from selected capture"); b2.clicked.connect(self._seed_capture)
        b3 = QPushButton("Seeds from pcap"); b3.clicked.connect(self._seed_pcap)
        srow.addWidget(QLabel("Seed:")); srow.addWidget(b1); srow.addWidget(b2); srow.addWidget(b3)
        srow.addStretch(1)
        root.addLayout(srow)

        # strategy row
        strow = QHBoxLayout()
        strow.addWidget(QLabel("Strategies:"))
        self.strat_boxes = {}
        for s in St.DEFAULT_STRATEGIES:
            cb = QCheckBox(s.name); cb.setChecked(True)
            self.strat_boxes[s.name] = (cb, s)
            strow.addWidget(cb)
        strow.addStretch(1)
        root.addLayout(strow)

        # run config row
        crow = QHBoxLayout()
        self.iters = QSpinBox(); self.iters.setRange(1, 1000000); self.iters.setValue(200)
        self.iface = QComboBox(); self.iface.addItems(list_interfaces() or ["<none>"])
        self.timeout = QSpinBox(); self.timeout.setRange(1, 30); self.timeout.setValue(2)
        self.rate = QSpinBox(); self.rate.setRange(0, 100000); self.rate.setValue(0)
        self.rate.setToolTip("Cases per second (0 = unlimited)")
        self.preview_btn = QPushButton("Preview variants"); self.preview_btn.clicked.connect(self.preview)
        self.run_btn = QPushButton("Run live campaign"); self.run_btn.clicked.connect(self.run_campaign)
        self.save_btn = QPushButton("Save results"); self.save_btn.clicked.connect(self.save_results)
        self.save_btn.setEnabled(False)
        for w in (QLabel("Iterations:"), self.iters, QLabel("Iface:"), self.iface,
                  QLabel("Timeout(s):"), self.timeout, QLabel("Rate/s:"), self.rate,
                  self.preview_btn, self.run_btn, self.save_btn):
            crow.addWidget(w)
        crow.addStretch(1)
        root.addLayout(crow)

        mono = QFont("JetBrains Mono"); mono.setStyleHint(QFont.Monospace)
        self.view = QPlainTextEdit(); self.view.setReadOnly(True); self.view.setFont(mono)
        root.addWidget(self.view)

        self.status = QLabel("Pick a seed to begin.")
        root.addWidget(self.status)

        self._poll = QTimer(self); self._poll.setInterval(250)
        self._poll.timeout.connect(self._check_worker)

    # ---- seeds --------------------------------------------------------------
    def _seed_builder(self) -> None:
        data = self._get_builder()
        self._set_seed(data, "builder packet")

    def _seed_capture(self) -> None:
        data = self._get_selected()
        self._set_seed(data, "selected capture packet")

    def _seed_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Seeds from pcap", "",
                                              "Capture files (*.pcap *.pcapng)")
        if not path:
            return
        seeds = seeds_from_pcap(path)
        if not seeds:
            self.status.setText("No packets in pcap.")
            return
        self._seed = seeds[0]
        self._extra_seeds = seeds[1:200]
        self.status.setText(f"Loaded {len(seeds)} seed(s) from pcap.")

    def _set_seed(self, data: bytes | None, label: str) -> None:
        if not data:
            self.status.setText("No seed available — build or select a packet first.")
            return
        self._seed = data
        self._extra_seeds = []
        self.status.setText(f"Seed set from {label} ({len(data)} bytes).")

    def _strategies(self):
        return [s for name, (cb, s) in self.strat_boxes.items() if cb.isChecked()]

    # ---- preview (offline) --------------------------------------------------
    def preview(self) -> None:
        if not self._seed:
            self.status.setText("Pick a seed first.")
            return
        import random

        from scapy.layers.l2 import Ether

        strategies = self._strategies() or St.DEFAULT_STRATEGIES
        rng = random.Random(0)
        lines = ["Preview of generated variants (not sent):\n"]
        for _ in range(8):
            s = rng.choice(strategies)
            data = s.mutate(self._seed, random.Random(rng.randrange(9999)))
            try:
                summ = Ether(data).summary()
            except Exception:
                summ = "(unparseable)"
            lines.append(f"[{s.name:6s}] {len(data):4d}B  {summ[:80]}")
        self.view.setPlainText("\n".join(lines))
        self.status.setText("Previewed 8 variants.")

    # ---- live campaign ------------------------------------------------------
    def run_campaign(self) -> None:
        if not self._seed:
            self.status.setText("Pick a seed first.")
            return
        if self._worker and self._worker.is_alive():
            return
        iface = self.iface.currentText()
        timeout = float(self.timeout.value())
        iters = self.iters.value()
        strategies = self._strategies() or St.DEFAULT_STRATEGIES

        from reforge.craft import sender

        def send_receive(data: bytes) -> mon.Response:
            t = time.monotonic()
            try:
                reply = sender.send_receive(iface, data, timeout=timeout, l2=True)
            except Exception as exc:
                return mon.Response(reply=None, error=str(exc))
            return mon.Response(reply=reply, latency=time.monotonic() - t)

        camp = FuzzCampaign(self._seed, send_receive, strategies=strategies,
                            iterations=iters, extra_seeds=self._extra_seeds,
                            rate=float(self.rate.value()))
        self._report = None
        self._campaign = camp

        def work():
            self._report = camp.run()

        self._worker = threading.Thread(target=work, daemon=True)
        self._worker.start()
        self._poll.start()
        self.run_btn.setEnabled(False)
        self.status.setText(f"Campaign running on {iface} ({iters} iterations)…")

    def _check_worker(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._poll.stop()
        self.run_btn.setEnabled(True)
        if self._report is not None:
            self.view.setPlainText(self._report.summary())
            self.save_btn.setEnabled(True)
            self.status.setText(f"Campaign done — {len(self._report.findings)} finding(s).")

    # ---- persistence --------------------------------------------------------
    def save_results(self) -> None:
        """Save the current campaign's corpus + findings for replay/triage."""
        if not getattr(self, "_campaign", None) or self._report is None:
            self.status.setText("Run a campaign first.")
            return
        directory = QFileDialog.getExistingDirectory(self, "Save fuzzing results")
        if not directory:
            return
        self._campaign.save(directory)
        self.status.setText(f"Saved corpus + {len(self._report.findings)} finding(s) to {directory}.")
