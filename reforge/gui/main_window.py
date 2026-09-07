"""Main window (Phase 1): live capture list + protocol tree + hex view.

Capture runs on a background thread (CaptureService); the UI drains its queue on
a timer, so the packet list stays responsive and Qt is only touched on the UI
thread. Live capture (AF_PACKET) needs root/CAP_NET_RAW; opening a pcap works
unprivileged.
"""

from __future__ import annotations

import datetime as _dt
import logging

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDockWidget,
    QFileDialog,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from reforge.core.intercept import InterceptQueue
from reforge.core.packet import Packet
from reforge.gui import theme
from reforge.gui.attacks_panel import AttacksPanel
from reforge.gui.builder_panel import BuilderPanel
from reforge.gui.creds_panel import CredsPanel
from reforge.gui.diagnostics_panel import DiagnosticsPanel
from reforge.gui.fuzzing_panel import FuzzingPanel
from reforge.gui.intercept_panel import InterceptPanel
from reforge.gui.rules_panel import RulesPanel

from reforge.capture.afpacket import AfPacketBackend
from reforge.capture.base import Frame
from reforge.capture.pcap import PcapFileBackend, export_pcap
from reforge.capture.registry import list_interfaces
from reforge.constants import APP_NAME, TAGLINE, VERSION
from reforge.core.capture_service import CaptureService
from reforge.dissect import scapy_tree

log = logging.getLogger("reforge.gui")

COLUMNS = ["No.", "Time", "Source", "Destination", "Proto", "Length", "Info"]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {VERSION} — {TAGLINE}")
        self.resize(1300, 850)

        self.service: CaptureService | None = None
        self.intercept: InterceptQueue | None = None
        self.packets: list[tuple[float, Frame]] = []  # captured (ts, frame)
        self._t0: float | None = None

        self._mono_small = QFont("JetBrains Mono", 11)
        self._mono_small.setStyleHint(QFont.Monospace)

        self._build_toolbar()
        self._build_center()
        self._build_docks()

        self.timer = QTimer(self)
        self.timer.setInterval(100)
        self.timer.timeout.connect(self._drain)

        self.statusBar().showMessage("Idle — open a pcap or start a live capture")

    # ---- layout -------------------------------------------------------------
    def _build_toolbar(self) -> None:
        tb = QToolBar("main")
        tb.setMovable(False)
        self.addToolBar(tb)

        self.brand = QLabel(f"  {APP_NAME}  ")
        tb.addWidget(self.brand)
        self.sep = QLabel("│")
        tb.addWidget(self.sep)
        self._restyle_brand()

        tb.addWidget(QLabel(" Mode: "))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Passive", "Bridge"])
        self.mode_combo.currentTextChanged.connect(self._on_mode_changed)
        tb.addWidget(self.mode_combo)

        tb.addWidget(QLabel("  Interface: "))
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(list_interfaces() or ["<none>"])
        tb.addWidget(self.iface_combo)

        self.peer_label = QLabel("  Peer: ")
        tb.addWidget(self.peer_label)
        self.peer_combo = QComboBox()
        self.peer_combo.addItems(list_interfaces() or ["<none>"])
        tb.addWidget(self.peer_combo)
        self.peer_label.setVisible(False)
        self.peer_combo.setVisible(False)

        tb.addWidget(QLabel("  BPF: "))
        self.bpf_edit = QLineEdit()
        self.bpf_edit.setPlaceholderText("e.g. tcp port 80 (optional)")
        self.bpf_edit.setMaximumWidth(240)
        tb.addWidget(self.bpf_edit)

        self.act_start = QAction("Start", self)
        self.act_start.triggered.connect(self.on_start)
        tb.addAction(self.act_start)

        self.act_stop = QAction("Stop", self)
        self.act_stop.triggered.connect(self.stop_capture)
        self.act_stop.setEnabled(False)
        tb.addAction(self.act_stop)

        tb.addSeparator()
        self.act_arm = QAction("Arm", self)
        self.act_arm.setCheckable(True)
        self.act_arm.toggled.connect(self._on_arm_toggled)
        tb.addAction(self.act_arm)

        self.act_kill = QAction("Kill-switch", self)
        self.act_kill.triggered.connect(self.kill_switch)
        tb.addAction(self.act_kill)

        self.act_seqfix = QAction("TCP seq-fix", self)
        self.act_seqfix.setCheckable(True)
        self.act_seqfix.setToolTip("Keep TCP flows in sync after length-changing edits")
        self.act_seqfix.toggled.connect(self._on_seqfix_toggled)
        tb.addAction(self.act_seqfix)

        self.act_csum = QAction("Fix cksums", self)
        self.act_csum.setCheckable(True)
        self.act_csum.setToolTip("Recompute IP/TCP/UDP checksums on every forwarded packet")
        self.act_csum.toggled.connect(self._on_csum_toggled)
        tb.addAction(self.act_csum)

        tb.addSeparator()
        act_open = QAction("Open pcap", self)
        act_open.triggered.connect(self.open_pcap)
        tb.addAction(act_open)

        act_export = QAction("Export pcap", self)
        act_export.triggered.connect(self.export_pcap)
        tb.addAction(act_export)

        act_clear = QAction("Clear", self)
        act_clear.triggered.connect(self.clear)
        tb.addAction(act_clear)

        tb.addSeparator()
        act_doctor = QAction("Doctor", self)
        act_doctor.triggered.connect(self.show_doctor)
        tb.addAction(act_doctor)

        act_plugins = QAction("Plugins", self)
        act_plugins.triggered.connect(self.load_plugins)
        tb.addAction(act_plugins)

        # push the theme toggle to the far right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb.addWidget(spacer)
        self.act_theme = QAction("", self)
        self.act_theme.triggered.connect(self.toggle_theme)
        tb.addAction(self.act_theme)
        self._update_theme_action()

    def _build_center(self) -> None:
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(24)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(True)   # Info column stretches
        # Column widths: No | Time | Source | Destination | Proto | Length | Info
        for col, width in ((0, 64), (1, 110), (2, 160), (3, 160), (4, 90), (5, 78)):
            self.table.setColumnWidth(col, width)
        hdr.setSectionResizeMode(0, QHeaderView.Fixed)
        hdr.setSectionResizeMode(5, QHeaderView.Fixed)
        self.table.itemSelectionChanged.connect(self._on_select)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setColumnWidth(0, 230)

        mono = QFont("monospace")
        mono.setStyleHint(QFont.Monospace)
        self.hex = QPlainTextEdit()
        self.hex.setReadOnly(True)
        self.hex.setFont(mono)

        detail = QSplitter(Qt.Horizontal)
        detail.addWidget(self.tree)
        detail.addWidget(self.hex)
        detail.setSizes([650, 650])

        center = QSplitter(Qt.Vertical)
        center.addWidget(self.table)
        center.addWidget(detail)
        center.setSizes([500, 350])

        self.tabs = QTabWidget()
        self.tabs.addTab(center, "Capture")
        self.builder_panel = BuilderPanel(get_selected_packet=self._selected_packet_bytes)
        self.tabs.addTab(self.builder_panel, "Builder")
        self.diag_panel = DiagnosticsPanel(
            get_selected_packet=self._selected_packet_bytes,
            build_engine=lambda: self.rules_panel.build_engine(dry_run=False),
            get_service=lambda: self.service,
            get_bridge_ifaces=self._bridge_ifaces,
            get_rule_specs=lambda: self.rules_panel.specs,
        )
        self.tabs.addTab(self.diag_panel, "Diagnostics")
        self.fuzz_panel = FuzzingPanel(
            get_builder_bytes=lambda: self.builder_panel._current_bytes(),
            get_selected_packet=self._selected_packet_bytes,
        )
        self.tabs.addTab(self.fuzz_panel, "Fuzzing")
        self.attacks_panel = AttacksPanel()
        self.tabs.addTab(self.attacks_panel, "Attacks")
        self.setCentralWidget(self.tabs)

    def _bridge_ifaces(self) -> list[str]:
        if self.mode_combo.currentText() != "Bridge":
            return []
        return [i for i in (self.iface_combo.currentText(), self.peer_combo.currentText())
                if i and i != "<none>"]

    def _selected_packet_bytes(self) -> bytes | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        i = rows[0].row()
        return self.packets[i][1].data if i < len(self.packets) else None

    def _build_docks(self) -> None:
        left = QDockWidget("Session", self)
        session_tree = QTreeWidget()
        session_tree.setHeaderLabels(["Session"])
        left.setWidget(session_tree)
        self.addDockWidget(Qt.LeftDockWidgetArea, left)

        rules_dock = QDockWidget("Rules", self)
        self.rules_panel = RulesPanel(on_dry_run=self._dry_run_over_capture)
        rules_dock.setWidget(self.rules_panel)
        self.addDockWidget(Qt.RightDockWidgetArea, rules_dock)

        intercept_dock = QDockWidget("Intercept", self)
        self.intercept_panel = InterceptPanel()
        intercept_dock.setWidget(self.intercept_panel)
        self.addDockWidget(Qt.RightDockWidgetArea, intercept_dock)
        self.tabifyDockWidget(rules_dock, intercept_dock)

        creds_dock = QDockWidget("Creds", self)
        self.creds_panel = CredsPanel()
        creds_dock.setWidget(self.creds_panel)
        self.addDockWidget(Qt.RightDockWidgetArea, creds_dock)
        self.tabifyDockWidget(intercept_dock, creds_dock)
        rules_dock.raise_()

    # ---- capture control ----------------------------------------------------
    def _on_mode_changed(self, mode: str) -> None:
        bridge = mode == "Bridge"
        self.peer_label.setVisible(bridge)
        self.peer_combo.setVisible(bridge)

    def on_start(self) -> None:
        if self.mode_combo.currentText() == "Bridge":
            self.start_bridge()
        else:
            self.start_live()

    def start_live(self) -> None:
        iface = self.iface_combo.currentText()
        if iface in ("", "<none>"):
            self.statusBar().showMessage("No interface selected")
            return
        bpf = self.bpf_edit.text().strip() or None
        try:
            backend = AfPacketBackend([iface], bpf=bpf)
        except Exception as exc:
            QMessageBox.critical(self, "Capture error", str(exc))
            return
        self._start_service(CaptureService(backend), f"live on {iface}")

    def start_bridge(self) -> None:
        a, b = self.iface_combo.currentText(), self.peer_combo.currentText()
        if a in ("", "<none>") or b in ("", "<none>") or a == b:
            self.statusBar().showMessage("Bridge needs two different interfaces")
            return
        from reforge.core.bridge import UserspaceBridge

        engine = self.rules_panel.build_engine(dry_run=False)
        self.intercept = InterceptQueue()
        self.intercept_panel.set_queue(self.intercept)
        armed = self.act_arm.isChecked()
        bridge = UserspaceBridge(a, b, engine, intercept=self.intercept, armed=armed,
                                 seq_fixup=self.act_seqfix.isChecked(),
                                 checksum_fixup=self.act_csum.isChecked())
        state = "ARMED" if armed else "pass-through (safe)"
        self._start_service(bridge, f"bridge {a} <-> {b}  [{state}]")

    def open_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open pcap", "", "Capture files (*.pcap *.pcapng *.cap);;All files (*)"
        )
        if not path:
            return
        self._start_service(CaptureService(PcapFileBackend(path)), f"pcap {path}")

    def _start_service(self, service, label: str) -> None:
        """Start any capture-like service (CaptureService or UserspaceBridge)."""
        self.stop_capture()
        self.clear()
        self.service = service
        try:
            self.service.start()
        except Exception as exc:
            QMessageBox.critical(self, "Start error", str(exc))
            self.service = None
            return
        self.timer.start()
        self.act_start.setEnabled(False)
        self.act_stop.setEnabled(True)
        self.statusBar().showMessage(f"Running — {label}")

    def stop_capture(self) -> None:
        self.timer.stop()
        if self.intercept is not None:
            self.intercept.release_all("forward")  # never strand held packets
            self.intercept_panel.set_queue(None)
            self.intercept = None
        if self.service:
            self._flush_rows()  # flush remaining (no auto-stop re-entry)
            self.service.stop()
            self.service = None
        self.act_start.setEnabled(True)
        self.act_stop.setEnabled(False)
        self.statusBar().showMessage(f"Stopped — {len(self.packets)} packets")

    def clear(self) -> None:
        self.table.setRowCount(0)
        self.tree.clear()
        self.hex.clear()
        self.packets.clear()
        self._t0 = None

    # ---- data flow ----------------------------------------------------------
    def _flush_rows(self) -> int:
        """Drain queued frames into the table. Returns how many were appended."""
        if not self.service:
            return 0
        batch = self.service.drain()
        if not batch:
            return 0
        self.table.setUpdatesEnabled(False)
        for ts, frame in batch:
            self._append_row(ts, frame)
        self.table.setUpdatesEnabled(True)
        return len(batch)

    def _drain(self) -> None:
        """Timer handler: flush rows, refresh held packets, auto-stop when done."""
        if not self.service:
            return
        if self.intercept is not None:
            self.intercept_panel.refresh_pending()
        self.diag_panel.refresh_health()
        n = self._flush_rows()
        if n == 0 and not self.service.running:
            self.stop_capture()
        elif n:
            self.statusBar().showMessage(f"Capturing — {len(self.packets)} packets")

    # ---- arm / kill-switch --------------------------------------------------
    def _on_arm_toggled(self, armed: bool) -> None:
        self.act_arm.setText("ARMED" if armed else "Arm")
        if self.service is not None and hasattr(self.service, "armed"):
            self.service.armed = armed
            self.statusBar().showMessage("ARMED — rules active" if armed
                                         else "Safe — pass-through")

    def _on_seqfix_toggled(self, on: bool) -> None:
        if self.service is not None and hasattr(self.service, "set_seq_fixup"):
            self.service.set_seq_fixup(on)
        self.statusBar().showMessage("TCP seq-fix " + ("ON" if on else "off"))

    def _on_csum_toggled(self, on: bool) -> None:
        if self.service is not None and hasattr(self.service, "checksum_fixup"):
            self.service.checksum_fixup = on
        self.statusBar().showMessage("Checksum fix-up " + ("ON" if on else "off"))

    def kill_switch(self) -> None:
        """Instantly revert to pass-through and release all held packets."""
        if self.service is not None and hasattr(self.service, "armed"):
            self.service.armed = False
        if self.act_arm.isChecked():
            self.act_arm.setChecked(False)  # triggers _on_arm_toggled
        released = 0
        if self.intercept is not None:
            released = self.intercept.release_all("forward")
            self.intercept_panel.refresh_pending()
        self.statusBar().showMessage(
            f"KILL-SWITCH — pass-through; released {released} held packet(s)")

    def _append_row(self, ts: float, frame: Frame) -> None:
        from scapy.layers.l2 import Ether

        idx = len(self.packets)
        self.packets.append((ts, frame))
        if self._t0 is None:
            self._t0 = ts
        try:
            pkt = Ether(frame.data)
            row = scapy_tree.summarize(pkt, index=idx, ts=ts)
            rel = ts - self._t0
            values = [str(idx), f"{rel:.6f}", row.src, row.dst, row.proto,
                      str(row.length), row.info]
            color = QColor(theme.proto_color(row.proto))
        except Exception as exc:
            values = [str(idx), f"{ts:.6f}", "", "", "malformed", str(len(frame.data)), str(exc)]
            color = QColor(theme.PROTO_MALFORMED)

        brush = QBrush(color)
        right = {0, 1, 5}  # numeric columns right-aligned
        r = self.table.rowCount()
        self.table.insertRow(r)
        for c, v in enumerate(values):
            item = QTableWidgetItem(v)
            item.setForeground(brush)
            if c in right:
                item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            if c in (0, 1, 5):
                item.setFont(self._mono_small)
            self.table.setItem(r, c, item)

        # passively harvest credentials from every captured frame
        self.creds_panel.add_from_frame(frame.data)

    def _on_select(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if idx >= len(self.packets):
            return
        _ts, frame = self.packets[idx]
        self._show_detail(frame)

    def _show_detail(self, frame: Frame) -> None:
        from scapy.layers.l2 import Ether

        self.tree.clear()
        bold = QFont()
        bold.setBold(True)
        try:
            pkt = Ether(frame.data)
            for layer in scapy_tree.to_tree(pkt):
                parent = QTreeWidgetItem([layer.name, ""])
                parent.setFont(0, bold)
                parent.setForeground(0, QBrush(QColor(theme.proto_color(layer.name))))
                for f in layer.fields:
                    child = QTreeWidgetItem([f.name, f.human])
                    child.setForeground(0, QBrush(QColor(theme.TEXT_MUTED)))
                    parent.addChild(child)
                self.tree.addTopLevelItem(parent)
                parent.setExpanded(True)
        except Exception as exc:
            self.tree.addTopLevelItem(QTreeWidgetItem(["error", str(exc)]))

        self.hex.setPlainText("\n".join(scapy_tree.hexdump_lines(frame.data)))

    # ---- misc ---------------------------------------------------------------
    def export_pcap(self) -> None:
        if not self.packets:
            self.statusBar().showMessage("Nothing to export")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export pcap", "capture.pcap",
                                              "pcap (*.pcap)")
        if not path:
            return
        n = export_pcap(path, [f for _ts, f in self.packets])
        self.statusBar().showMessage(f"Exported {n} packets -> {path}")

    # ---- rules / dry-run ----------------------------------------------------
    def _dry_run_over_capture(self) -> None:
        if not self.packets:
            self.statusBar().showMessage("No packets — capture or open a pcap first")
            return
        if not self.rules_panel.specs:
            self.statusBar().showMessage("No rules defined — add a rule first")
            return
        engine = self.rules_panel.build_engine(dry_run=True)
        matched: list[int] = []
        for idx, (_ts, frame) in enumerate(self.packets):
            try:
                verdict = engine.evaluate(Packet.from_bytes(frame.data, link="ether"))
            except Exception:
                continue
            if verdict.matched_rule:
                matched.append(idx)
        hits = {r.name: r.hits for r in engine.rules}
        self.rules_panel.refresh(hits)
        self._mark_rows(set(matched))
        active = sum(1 for v in hits.values() if v)
        self.statusBar().showMessage(
            f"Dry-run (shadow): {len(matched)} of {len(self.packets)} packets matched "
            f"by {active} rule(s) — no traffic altered"
        )

    def _mark_rows(self, matched: set[int]) -> None:
        matched_brush = QBrush(QColor(theme.ACCENT_DIM))
        clear = QBrush()
        for r in range(self.table.rowCount()):
            bg = matched_brush if r in matched else clear
            for c in range(self.table.columnCount()):
                item = self.table.item(r, c)
                if item is not None:
                    item.setBackground(bg)

    def load_plugins(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Select plugins directory")
        if not directory:
            return
        from reforge.plugins import PluginManager

        if not hasattr(self, "plugin_mgr"):
            self.plugin_mgr = PluginManager()
        n = self.plugin_mgr.load_dir(directory)
        # custom protocols registered by plugins appear in the builder palette
        self.builder_panel.layer_combo.clear()
        from reforge.craft import builder as _b
        self.builder_panel.layer_combo.addItems(_b.available_layers())
        self.statusBar().showMessage(f"Loaded {n} plugin(s) from {directory}")

    def show_doctor(self) -> None:
        from reforge.diagnostics.doctor import run_checks

        lines = [f"[{'PASS' if c.ok else 'FAIL'}] {c.name}: {c.detail}"
                 + (f"\n    fix: {c.fix}" if (not c.ok and c.fix) else "")
                 for c in run_checks()]
        QMessageBox.information(self, "Doctor", "\n".join(lines))

    # ---- theme --------------------------------------------------------------
    def _restyle_brand(self) -> None:
        self.brand.setStyleSheet(
            f"color: {theme.ACCENT}; font-size: 16px; font-weight: 800;"
            " letter-spacing: 0.5px;"
        )
        self.sep.setStyleSheet(f"color: {theme.BORDER_LIGHT}; padding: 0 6px;")

    def _update_theme_action(self) -> None:
        # Show what a click will switch TO.
        if theme.current_mode() == "dark":
            self.act_theme.setText("☀  Light")
        else:
            self.act_theme.setText("☾  Dark")

    def toggle_theme(self) -> None:
        mode = theme.toggle_mode()
        theme.apply_theme(QApplication.instance(), mode)
        theme.save_mode(mode)
        self._restyle_brand()
        self._update_theme_action()
        self._recolor_rows()
        self._on_select()  # refresh tree colors for the selected packet

    def _recolor_rows(self) -> None:
        """Re-apply per-protocol foreground colors after a theme change."""
        for r in range(self.table.rowCount()):
            proto_item = self.table.item(r, 4)
            if proto_item is None:
                continue
            proto = proto_item.text()
            color = QColor(theme.PROTO_MALFORMED if proto == "malformed"
                           else theme.proto_color(proto))
            brush = QBrush(color)
            for c in range(self.table.columnCount()):
                item = self.table.item(r, c)
                if item is not None:
                    item.setForeground(brush)

    def closeEvent(self, event) -> None:  # noqa: N802 (Qt signature)
        self.stop_capture()
        try:
            self.attacks_panel.stop_all()
        except Exception:
            pass
        super().closeEvent(event)


_ = _dt  # reserved for absolute-time column formatting
