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

from reforge.capture.afpacket import AfPacketBackend
from reforge.capture.base import Frame
from reforge.capture.pcap import PcapFileBackend, export_pcap
from reforge.capture.registry import list_interfaces
from reforge.constants import APP_NAME, TAGLINE, VERSION
from reforge.core.capture_service import CaptureService
from reforge.core.intercept import InterceptQueue
from reforge.core.packet import Packet
from reforge.dissect import scapy_tree
from reforge.gui import theme
from reforge.gui.attacks_panel import AttacksPanel
from reforge.gui.builder_panel import BuilderPanel
from reforge.gui.console_panel import ConsolePanel
from reforge.gui.creds_panel import CredsPanel
from reforge.gui.diagnostics_panel import DiagnosticsPanel
from reforge.gui.fuzzing_panel import FuzzingPanel
from reforge.gui.guidance import wrap_with_intro
from reforge.gui.guide_panel import GuidePanel
from reforge.gui.intercept_panel import InterceptPanel
from reforge.gui.recon_panel import ReconPanel
from reforge.gui.rules_panel import RulesPanel
from reforge.gui.scan_panel import ScanPanel
from reforge.gui.scenario_panel import ScenarioPanel

log = logging.getLogger("reforge.gui")

COLUMNS = ["No.", "Time", "Source", "Destination", "Proto", "Length", "Info"]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {VERSION} — {TAGLINE}")
        self.resize(1300, 850)

        self.service: CaptureService | None = None
        self.intercept: InterceptQueue | None = None
        self.engine = None                 # live engine while a bridge runs
        self._intercept_filter: tuple | None = None  # (match, text) to hold
        self._transforms: list = []                   # persistent promoted rewrite rules
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

        self._load_settings()                 # restore last-used inputs
        self.statusBar().showMessage("Idle — open a pcap or start a live capture")

    # ---- remembered settings ------------------------------------------------
    def _state_widgets(self) -> dict:
        """Inputs whose last-used value is remembered between runs (never secrets)."""
        a, sc, ic, bd = (self.attacks_panel, self.scan_panel,
                         self.intercept_panel, self.builder_panel)
        return {
            "toolbar/iface": self.iface_combo, "toolbar/peer": self.peer_combo,
            "toolbar/mode": self.mode_combo, "toolbar/bpf": self.bpf_edit,
            "scan/target": sc.target, "scan/ports": sc.ports, "scan/mode": sc.mode,
            "scan/banners": sc.banners,
            "intercept/limit": ic.limit_spin, "intercept/autorel": ic.autorel_spin,
            "intercept/overflow": ic.overflow_combo, "intercept/filter": ic.filter_edit,
            "attacks/tp_port": a.tp_port, "attacks/tp_target": a.tp_target,
            "attacks/tp_sslstrip": a.tp_sslstrip, "attacks/tp_stripenc": a.tp_stripenc,
            "attacks/tp_cookie": a.tp_cookie, "attacks/tp_inject": a.tp_inject,
            "attacks/tp_int_keyword": a.tp_int_keyword, "attacks/tp_int_dir": a.tp_int_dir,
            "builder/iface": bd.iface, "builder/count": bd.count,
            "builder/interval": bd.interval, "builder/l2": bd.l2,
        }

    def _load_settings(self) -> None:
        from reforge.gui.settings import load_all

        try:
            load_all(self._state_widgets())
        except Exception:
            log.debug("settings load failed", exc_info=True)

    def _save_settings(self) -> None:
        from reforge.gui.settings import save_all

        try:
            save_all(self._state_widgets())
        except Exception:
            log.debug("settings save failed", exc_info=True)

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
        from reforge.gui.guidance import bpf_help_tooltip
        self.bpf_edit.setToolTip(bpf_help_tooltip())
        tb.addWidget(self.bpf_edit)

        self.act_start = QAction("Start", self)
        self.act_start.setShortcut("F5")
        self.act_start.setToolTip("Start capture or bridge (F5)")
        self.act_start.triggered.connect(self.on_start)
        tb.addAction(self.act_start)

        self.act_stop = QAction("Stop", self)
        self.act_stop.setShortcut("Shift+F5")
        self.act_stop.setToolTip("Stop the running service (Shift+F5)")
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
        act_guide = QAction("Guide", self)
        act_guide.setShortcut("F1")
        act_guide.setToolTip("What each section does and how to start (F1)")
        act_guide.triggered.connect(lambda: self._open_guide(""))
        tb.addAction(act_guide)

        act_doctor = QAction("Doctor", self)
        act_doctor.triggered.connect(self.show_doctor)
        tb.addAction(act_doctor)

        act_plugins = QAction("Plugins", self)
        act_plugins.triggered.connect(self.load_plugins)
        tb.addAction(act_plugins)

        act_vault = QAction("Vault", self)
        act_vault.setToolTip("Encrypt/decrypt an engagement artifact at rest")
        act_vault.triggered.connect(self.vault_tool)
        tb.addAction(act_vault)

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
        g = self._open_guide
        self.tabs.addTab(wrap_with_intro(center, "capture", g), "Capture")
        self.builder_panel = BuilderPanel(get_selected_packet=self._selected_packet_bytes)
        self.tabs.addTab(wrap_with_intro(self.builder_panel, "builder", g), "Builder")
        self.diag_panel = DiagnosticsPanel(
            get_selected_packet=self._selected_packet_bytes,
            build_engine=lambda: self.rules_panel.build_engine(dry_run=False),
            get_service=lambda: self.service,
            get_bridge_ifaces=self._bridge_ifaces,
            get_rule_specs=lambda: self.rules_panel.specs,
        )
        self.tabs.addTab(wrap_with_intro(self.diag_panel, "diagnostics", g), "Diagnostics")
        self.fuzz_panel = FuzzingPanel(
            get_builder_bytes=lambda: self.builder_panel._current_bytes(),
            get_selected_packet=self._selected_packet_bytes,
        )
        self.tabs.addTab(wrap_with_intro(self.fuzz_panel, "fuzzing", g), "Fuzzing")
        self.attacks_panel = AttacksPanel()
        self.attacks_panel.get_intercept_queue = self._shared_intercept_queue
        self.tabs.addTab(wrap_with_intro(self.attacks_panel, "attacks", g), "Attacks")
        self.scan_panel = ScanPanel(get_inventory=lambda: self.recon_panel.inv)
        self.tabs.addTab(wrap_with_intro(self.scan_panel, "scan", g), "Scan")
        self.scenario_panel = ScenarioPanel()
        self.tabs.addTab(wrap_with_intro(self.scenario_panel, "scenario", g), "Scenario")
        self.console_panel = ConsolePanel()
        self.tabs.addTab(wrap_with_intro(self.console_panel, "console", g), "Console")
        self.guide_panel = GuidePanel()
        self.tabs.addTab(self.guide_panel, "Guide")
        self.setCentralWidget(self.tabs)

    def _open_guide(self, section_key: str = "") -> None:
        """Switch to the Guide tab and scroll to a section (used by intro links)."""
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == "Guide":
                self.tabs.setCurrentIndex(i)
                break
        if section_key:
            self.guide_panel.scroll_to(section_key)

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

        g = self._open_guide
        rules_dock = QDockWidget("Rules", self)
        self.rules_panel = RulesPanel(on_dry_run=self._dry_run_over_capture)
        rules_dock.setWidget(wrap_with_intro(self.rules_panel, "rules", g))
        self.addDockWidget(Qt.RightDockWidgetArea, rules_dock)

        intercept_dock = QDockWidget("Intercept", self)
        self.intercept_panel = InterceptPanel()
        self.intercept_panel.on_filter = self._on_intercept_filter
        self.intercept_panel.on_promote = self._on_intercept_promote
        self.intercept_panel.on_queue_config = self._on_queue_config
        self.intercept_panel.on_help = lambda: self._open_guide("_filter")
        self.intercept_panel.on_clear_transforms = self._clear_transforms
        intercept_dock.setWidget(wrap_with_intro(self.intercept_panel, "intercept", g))
        self.addDockWidget(Qt.RightDockWidgetArea, intercept_dock)
        self.tabifyDockWidget(rules_dock, intercept_dock)

        creds_dock = QDockWidget("Creds", self)
        self.creds_panel = CredsPanel()
        creds_dock.setWidget(wrap_with_intro(self.creds_panel, "creds", g))
        self.addDockWidget(Qt.RightDockWidgetArea, creds_dock)
        self.tabifyDockWidget(intercept_dock, creds_dock)

        recon_dock = QDockWidget("Recon", self)
        self.recon_panel = ReconPanel()
        recon_dock.setWidget(wrap_with_intro(self.recon_panel, "recon", g))
        self.addDockWidget(Qt.RightDockWidgetArea, recon_dock)
        self.tabifyDockWidget(creds_dock, recon_dock)
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

        # Tear down any prior service FIRST, then build new engine/intercept state
        # so _start_service (reset=False) does not wipe what we just created.
        self.stop_capture()
        self.clear()
        engine = self.rules_panel.build_engine(dry_run=False)
        self.engine = engine
        self._install_intercept_filter(engine)
        max_held, auto_rel, overflow = self.intercept_panel.queue_config()
        self.intercept = InterceptQueue(max_held=max_held, auto_release_s=auto_rel,
                                        overflow=overflow)
        self.intercept_panel.set_queue(self.intercept)
        self.intercept_panel.set_transform_count(len(self._transforms))
        armed = self.act_arm.isChecked()
        bridge = UserspaceBridge(a, b, engine, intercept=self.intercept, armed=armed,
                                 flow_rewrite=self.act_seqfix.isChecked(),
                                 checksum_fixup=self.act_csum.isChecked())
        state = "ARMED" if armed else "pass-through (safe)"
        self._start_service(bridge, f"bridge {a} <-> {b}  [{state}]", reset=False)

    def open_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open pcap", "", "Capture files (*.pcap *.pcapng *.cap);;All files (*)"
        )
        if not path:
            return
        self._start_service(CaptureService(PcapFileBackend(path)), f"pcap {path}")

    def _start_service(self, service, label: str, reset: bool = True) -> None:
        """Start any capture-like service (CaptureService or UserspaceBridge).

        reset=False when the caller has already torn down the prior service and
        set up new engine/intercept state that must survive (see start_bridge)."""
        if reset:
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

    # ---- interactive intercept filter --------------------------------------
    _INTERCEPT_RULE = "__intercept_filter__"

    def _on_intercept_filter(self, match, text: str) -> None:
        """Called by the Intercept panel: install/clear a HOLD rule from a filter."""
        if match is None:
            self._intercept_filter = None
        else:
            self._intercept_filter = (match, text)
        if self.engine is not None:
            self._install_intercept_filter(self.engine)
            n = self.intercept.count() if self.intercept else 0
            state = f"intercept: {text or 'all packets'}" if match is not None else "intercept off"
            self.statusBar().showMessage(f"{state} (held: {n})")
        elif match is not None:
            self.statusBar().showMessage("Intercept filter armed — starts with the bridge")

    _TRANSFORM_PREFIX = "__xform__"

    def _install_intercept_filter(self, engine) -> None:
        """Rebuild the engine rule list: promoted transforms, then the HOLD rule.

        A new list is assigned atomically, so the bridge worker thread iterating
        the old list is never disturbed mid-evaluation. Transforms run as normal
        FORWARD rewrites; the HOLD rule sits in front so interactive catching (if
        still enabled) takes precedence over the auto-transforms."""
        from reforge.rules.actions import Hold
        from reforge.rules.base import Rule

        base = [r for r in engine.rules
                if r.name != self._INTERCEPT_RULE
                and not r.name.startswith(self._TRANSFORM_PREFIX)]
        rules = list(self._transforms) + base
        if self._intercept_filter is not None:
            match, _text = self._intercept_filter
            rules.insert(0, Rule(self._INTERCEPT_RULE, match, [Hold()]))
        engine.rules = rules

    def _on_intercept_promote(self, original: bytes, edited: bytes) -> str:
        """Turn one interactive edit into a persistent transform on all matches."""
        from reforge.rules.base import Rule
        from reforge.rules.derive import derive_actions, describe_actions
        from reforge.rules.matchers import AllMatch

        actions = derive_actions(original, edited, link="ether")
        if not actions:
            return "No change to promote — edit the packet first."
        # scope the transform to the current catch filter, else to any packet
        # (a payload find/replace self-scopes to packets containing the pattern).
        match = self._intercept_filter[0] if self._intercept_filter is not None else AllMatch()
        name = f"{self._TRANSFORM_PREFIX}{len(self._transforms) + 1}"
        self._transforms.append(Rule(name, match, actions))
        if self.engine is not None:
            self._install_intercept_filter(self.engine)
        self.intercept_panel.set_transform_count(len(self._transforms))
        desc = describe_actions(actions)
        return f"Transform added ({desc}) — applies to all matching traffic and resends."

    def _clear_transforms(self) -> None:
        """Remove every promoted 'apply to all' transform from the live engine."""
        self._transforms = []
        if self.engine is not None:
            self._install_intercept_filter(self.engine)
        self.intercept_panel.set_transform_count(0)
        self.statusBar().showMessage("Cleared all interactive transforms.")

    def _shared_intercept_queue(self):
        """Return the intercept queue (creating one if no bridge is running).

        Lets the HTTP/TLS proxy hold whole messages in the same Intercept tab
        even when the inline bridge is not the active service."""
        if self.intercept is None:
            max_held, auto_rel, overflow = self.intercept_panel.queue_config()
            self.intercept = InterceptQueue(max_held=max_held, auto_release_s=auto_rel,
                                            overflow=overflow)
            self.intercept_panel.set_queue(self.intercept)
        return self.intercept

    def _on_queue_config(self, max_held: int, auto_release_s: float, overflow: str) -> None:
        """Live-update the running queue's volume safeguards."""
        if self.intercept is not None:
            self.intercept.max_held = max_held
            self.intercept.auto_release_s = auto_release_s
            self.intercept.overflow = overflow if overflow in ("forward", "drop") else "forward"

    def stop_capture(self) -> None:
        self.timer.stop()
        if self.intercept is not None:
            self.intercept.release_all("forward")  # never strand held packets
            self.intercept_panel.set_queue(None)
            self.intercept = None
        self.engine = None
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
            self.intercept.reap()               # auto-release timed-out holds
            self.intercept_panel.refresh_pending()
        self.diag_panel.refresh_health()
        self.recon_panel.refresh()
        n = self._flush_rows()
        if n == 0 and not self.service.running:
            err = getattr(self.service, "error", None)
            self.stop_capture()
            if err:                             # stopped on an error (e.g. iface lost)
                self.statusBar().showMessage(f"Capture stopped: {err}")
                QMessageBox.warning(self, "Capture stopped", f"The capture stopped:\n\n{err}")
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
            self.service.set_seq_fixup(on, position_aware=True)
        self.statusBar().showMessage("TCP seq-fix " + ("ON (position-aware)" if on else "off"))

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

        # passively harvest credentials + build the asset inventory
        self.creds_panel.add_from_frame(frame.data)
        self.recon_panel.add_from_frame(frame.data)

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

    def vault_tool(self) -> None:
        from PySide6.QtWidgets import QInputDialog, QLineEdit

        mode, ok = QInputDialog.getItem(self, "Vault", "Operation:",
                                        ["encrypt", "decrypt"], 0, False)
        if not ok:
            return
        src, _ = QFileDialog.getOpenFileName(self, f"{mode}: source file")
        if not src:
            return
        dst, _ = QFileDialog.getSaveFileName(self, f"{mode}: output file")
        if not dst:
            return
        pw, ok = QInputDialog.getText(self, "Vault", "Passphrase:", QLineEdit.Password)
        if not ok or not pw:
            return
        from reforge.core.vault import decrypt_file, encrypt_file

        try:
            fn = encrypt_file if mode == "encrypt" else decrypt_file
            fn(src, dst, pw)
            self.statusBar().showMessage(f"{mode}ed {src} -> {dst}")
        except Exception as exc:
            QMessageBox.critical(self, "Vault error", str(exc))

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

    def closeEvent(self, event) -> None:
        self._save_settings()                 # remember last-used inputs
        self.stop_capture()
        for cleanup in (self.attacks_panel.stop_all, self.console_panel.stop):
            try:
                cleanup()
            except Exception:
                pass
        super().closeEvent(event)


_ = _dt  # reserved for absolute-time column formatting
