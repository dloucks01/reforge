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
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from reforge.capture.afpacket import AfPacketBackend
from reforge.capture.base import Frame
from reforge.capture.pcap import PcapFileBackend, export_pcap
from reforge.capture.registry import list_interfaces
from reforge.constants import APP_NAME, CONFIG_DIR, TAGLINE, VERSION, ensure_dirs
from reforge.core.capture_service import CaptureService
from reforge.core.flows import FlowTracker
from reforge.core.intercept import InterceptQueue
from reforge.core.packet import Packet
from reforge.dissect import scapy_tree
from reforge.engage import Engagement
from reforge.gui import theme
from reforge.gui.attacks_panel import AttacksPanel
from reforge.gui.builder_panel import BuilderPanel
from reforge.gui.console_panel import ConsolePanel
from reforge.gui.creds_panel import CredsPanel
from reforge.gui.diagnostics_panel import DiagnosticsPanel
from reforge.gui.errors import explain
from reforge.gui.fuzzing_panel import FuzzingPanel
from reforge.gui.guide_panel import GuidePanel
from reforge.gui.intercept_panel import InterceptPanel
from reforge.gui.navrail import NavRail
from reforge.gui.recon_panel import ReconPanel
from reforge.gui.rules_panel import RulesPanel
from reforge.gui.scan_panel import ScanPanel
from reforge.gui.scenario_panel import ScenarioPanel

log = logging.getLogger("reforge.gui")

COLUMNS = ["No.", "Time", "Source", "Destination", "Proto", "Length", "Info"]
FLOW_COLS = ["Proto", "Conversation", "Pkts", "Bytes", "State", "Duration"]


_WS_BLURB = {
    "live": "Capture the stream, catch matching packets, and edit them before they forward.",
    "recon": "Discover hosts and harvest credentials from what crosses the wire.",
    "craft": "Build any packet field-by-field, then send, receive, or fuzz it.",
    "attack": "Position on-path and manipulate application traffic.",
    "automate": "Script repeatable runs and merge many sensors into one view.",
    "system": "Health checks, the artifact vault, and the built-in guide.",
}


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
        self.flows = FlowTracker()
        ensure_dirs()
        self._engagement_path = CONFIG_DIR / "engagement.json"
        self.engagement = Engagement.load(self._engagement_path)
        self._t0: float | None = None

        self._mono_small = QFont("JetBrains Mono", 11)
        self._mono_small.setStyleHint(QFont.Monospace)

        self._build_actions()
        self._build_panels()
        self._build_shell()

        self.timer = QTimer(self)
        self.timer.setInterval(100)
        self.timer.timeout.connect(self._drain)

        self._load_settings()                 # restore last-used inputs
        self._restore_layout()                # restore the pane split + workspaces
        try:
            self.recon_panel.load_hosts(self.engagement.hosts)
            self.creds_panel.load_creds(self.engagement.creds)
            self.recon_panel.refresh()
        except Exception:
            log.debug("engagement restore failed", exc_info=True)
        self.statusBar().showMessage("Idle — open a pcap or start a live capture")

    def _save_layout(self) -> None:
        from reforge.gui.settings import settings

        try:
            s = settings()
            s.setValue("shell/panes", ",".join(self.pane_area.layout_keys()))
            s.sync()
        except Exception:
            log.debug("layout save failed", exc_info=True)

    def _restore_layout(self) -> None:
        from reforge.gui.settings import settings

        try:
            saved = str(settings().value("shell/panes", "") or "")
            keys = [k for k in saved.split(",") if k]
            if keys:
                self.pane_area.restore_layout(keys)
        except Exception:
            log.debug("layout restore failed", exc_info=True)

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
    def _build_actions(self) -> None:
        from reforge.gui.guidance import bpf_help_tooltip

        # session-control widgets (kept as attributes for handlers/settings/tests)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Passive", "Bridge"])
        self.mode_combo.currentTextChanged.connect(self._on_mode_changed)
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(list_interfaces() or ["<none>"])
        self.peer_label = QLabel("Peer")
        self.peer_combo = QComboBox()
        self.peer_combo.addItems(list_interfaces() or ["<none>"])
        self.peer_label.setVisible(False)
        self.peer_combo.setVisible(False)
        self.bpf_edit = QLineEdit()
        self.bpf_edit.setPlaceholderText("tcp port 80 (optional)")
        self.bpf_edit.setMaximumWidth(220)
        self.bpf_edit.setToolTip(bpf_help_tooltip())

        # brand + theme label used by _restyle_brand / _update_theme_action
        self.brand = QLabel(APP_NAME)
        self.sep = QLabel("")
        self._restyle_brand()

        def act(text, handler, *, shortcut=None, checkable=False, tip=None):
            a = QAction(text, self)
            if shortcut:
                a.setShortcut(shortcut)
            if tip:
                a.setToolTip(tip)
            if checkable:
                a.setCheckable(True)
                a.toggled.connect(handler)
            else:
                a.triggered.connect(handler)
            return a

        self.act_start = act("Start", self.on_start, shortcut="F5",
                             tip="Start capture or bridge (F5)")
        self.act_stop = act("Stop", self.stop_capture, shortcut="Shift+F5",
                            tip="Stop the running service (Shift+F5)")
        self.act_stop.setEnabled(False)
        self.act_arm = act("Arm", self._on_arm_toggled, checkable=True)
        self.act_kill = act("Kill", self.kill_switch,
                            tip="Revert to pass-through and release held packets")
        self.act_seqfix = act("Seq-fix", self._on_seqfix_toggled, checkable=True,
                              tip="Keep TCP flows in sync after length-changing edits")
        self.act_csum = act("Cksum", self._on_csum_toggled, checkable=True,
                            tip="Recompute checksums on every forwarded packet")
        self.act_open = act("Open pcap\u2026", self.open_pcap)
        self.act_demo = act("Demo traffic", self.start_demo,
                            tip="Replay synthetic traffic \u2014 no NIC or root needed")
        self.act_export = act("Export pcap\u2026", self.export_pcap)
        self.act_clear = act("Clear", self.clear)
        self.act_guide = act("Guide", lambda: self._open_guide(""), shortcut="F1",
                             tip="What each section does and how to start (F1)")
        self.act_doctor = act("Doctor", self.show_doctor)
        self.act_plugins = act("Plugins\u2026", self.load_plugins)
        self.act_vault = act("Vault\u2026", self.vault_tool,
                             tip="Encrypt/decrypt an engagement artifact at rest")
        self.act_report = act("Export report\u2026", self._export_report,
                              tip="Save an HTML engagement report (hosts, creds, timeline)")
        self.act_new_engagement = act("New engagement", self._new_engagement,
                                      tip="Clear the current hosts, creds, and timeline")
        self.act_theme = act("", self.toggle_theme)
        self._update_theme_action()
        for a in (self.act_start, self.act_stop, self.act_guide):
            self.addAction(a)  # window-level shortcuts
    def _build_panels(self) -> None:
        # capture inspection widgets (the packet stream + detail/hex view)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(True)
        for col, width in ((0, 56), (1, 96), (2, 150), (3, 150), (4, 80), (5, 66)):
            self.table.setColumnWidth(col, width)
        hdr.setSectionResizeMode(0, QHeaderView.Fixed)
        hdr.setSectionResizeMode(5, QHeaderView.Fixed)
        self.table.itemSelectionChanged.connect(self._on_select)

        # capability panels (single-instance; composed into workspaces)
        self.builder_panel = BuilderPanel(get_selected_packet=self._selected_packet_bytes)
        self.diag_panel = DiagnosticsPanel(
            get_selected_packet=self._selected_packet_bytes,
            build_engine=lambda: self.rules_panel.build_engine(dry_run=False),
            get_service=lambda: self.service,
            get_bridge_ifaces=self._bridge_ifaces,
            get_rule_specs=lambda: self.rules_panel.specs,
        )
        self.fuzz_panel = FuzzingPanel(
            get_builder_bytes=lambda: self.builder_panel._current_bytes(),
            get_selected_packet=self._selected_packet_bytes,
        )
        self.attacks_panel = AttacksPanel()
        self.attacks_panel.get_intercept_queue = self._shared_intercept_queue
        self.attacks_panel.on_start_inline = self._start_inline
        self.attacks_panel.on_stop_inline = self._stop_inline
        self.attacks_panel.on_event = self.engagement.log
        self.recon_panel = ReconPanel()
        self.scan_panel = ScanPanel(get_inventory=lambda: self.recon_panel.inv)
        self.scan_panel.on_scan_done = lambda d: self.engagement.log("scan", d)
        self.scenario_panel = ScenarioPanel()
        self.console_panel = ConsolePanel()
        self.guide_panel = GuidePanel()
        self.creds_panel = CredsPanel()
        self.rules_panel = RulesPanel(on_dry_run=self._dry_run_over_capture)
        self.intercept_panel = InterceptPanel()
        self.intercept_panel.on_filter = self._on_intercept_filter
        self.intercept_panel.on_promote = self._on_intercept_promote
        self.intercept_panel.on_queue_config = self._on_queue_config
        self.intercept_panel.on_help = lambda: self._open_guide("_filter")
        self.intercept_panel.on_clear_transforms = self._clear_transforms
        self.intercept_panel.on_send_to_builder = self._send_to_builder
        self.intercept_panel.on_length_change = self._on_intercept_length_change


    def _build_shell(self) -> None:
        self._workspaces = {
            "live": self._ws_live(),
            "recon": self._ws("recon", self._ws_recon()),
            "craft": self._ws("craft", self._ws_craft()),
            "attack": self._ws("attack", self.attacks_panel),
            "automate": self._ws("automate", self._ws_automate()),
            "system": self._ws("system", self._ws_system()),
        }
        from reforge.gui.navrail import SECTIONS as _RAIL
        from reforge.gui.panes import PaneArea

        titles = dict(_RAIL)
        self.pane_area = PaneArea(self._workspaces, titles)
        self.pane_area.active_changed.connect(self.nav_reflect)

        self.nav = NavRail()
        self.nav.switched.connect(self._go_workspace)

        body = QWidget()
        bl = QHBoxLayout(body)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setSpacing(0)
        bl.addWidget(self.nav)
        bl.addWidget(self.pane_area, 1)

        central = QWidget()
        cl = QVBoxLayout(central)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        cl.addWidget(self._build_session_bar())
        cl.addWidget(body, 1)
        self.setCentralWidget(central)
        self._go_workspace("live")

    def _build_session_bar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("sessionBar")
        row = QHBoxLayout(bar)
        row.setContentsMargins(10, 6, 10, 6)
        row.setSpacing(8)

        def tbtn(action, obj=None):
            b = QToolButton()
            b.setDefaultAction(action)
            b.setToolButtonStyle(Qt.ToolButtonTextOnly)
            if obj:
                b.setObjectName(obj)
            return b

        row.addWidget(self.brand)
        row.addWidget(self._vsep())
        for w in (QLabel("Mode"), self.mode_combo, QLabel("If"), self.iface_combo,
                  self.peer_label, self.peer_combo, QLabel("BPF"), self.bpf_edit):
            row.addWidget(w)
        row.addWidget(tbtn(self.act_start, "goBtn"))
        row.addWidget(tbtn(self.act_stop))
        row.addWidget(self._vsep())
        for a in (self.act_arm, self.act_kill, self.act_seqfix, self.act_csum):
            row.addWidget(tbtn(a))
        row.addStretch(1)

        overflow = QToolButton()
        overflow.setText("\u22ef")
        overflow.setPopupMode(QToolButton.InstantPopup)
        menu = QMenu(overflow)
        for a in (self.act_open, self.act_demo, self.act_export, self.act_clear):
            menu.addAction(a)
        menu.addSeparator()
        for a in (self.act_doctor, self.act_plugins, self.act_vault):
            menu.addAction(a)
        menu.addSeparator()
        for a in (self.act_report, self.act_new_engagement):
            menu.addAction(a)
        overflow.setMenu(menu)
        row.addWidget(overflow)
        row.addWidget(tbtn(self.act_guide))
        row.addWidget(tbtn(self.act_theme))
        return bar

    def _vsep(self) -> QLabel:
        s = QLabel("\u2502")
        s.setStyleSheet(f"color:{theme.BORDER_LIGHT};")
        return s

    def _ws(self, key, inner) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        v.addWidget(self._ws_header(key))
        v.addWidget(inner, 1)
        return w

    def _ws_header(self, key) -> QWidget:
        h = QFrame()
        h.setObjectName("wsHeader")
        row = QHBoxLayout(h)
        row.setContentsMargins(12, 5, 12, 5)
        row.setSpacing(8)
        lbl = QLabel(_WS_BLURB.get(key, ""))
        lbl.setObjectName("wsBlurb")
        row.addWidget(lbl)
        row.addStretch(1)
        q = QToolButton()
        q.setText("?")
        q.setObjectName("wsHelp")
        q.setToolTip("Open the Guide")
        q.clicked.connect(lambda: self._open_guide(""))
        row.addWidget(q)
        return h

    def _region_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("regionLabel")
        return lbl

    def _ws_live(self) -> QWidget:
        # top: Stream (raw packets) | Flows (conversations)
        self._live_top = QTabWidget()
        stream = QWidget()
        sv = QVBoxLayout(stream); sv.setContentsMargins(0, 0, 0, 0); sv.setSpacing(0)
        sv.addWidget(self.table)
        self._live_top.addTab(stream, "Stream")

        self.flows_table = QTableWidget(0, len(FLOW_COLS))
        self.flows_table.setHorizontalHeaderLabels(FLOW_COLS)
        self.flows_table.verticalHeader().setVisible(False)
        self.flows_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.flows_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.flows_table.setSelectionMode(QTableWidget.SingleSelection)
        self.flows_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.flows_table.itemDoubleClicked.connect(self._on_flow_activated)
        self._live_top.addTab(self.flows_table, "Flows")

        lower = QTabWidget()
        lower.addTab(self.intercept_panel, "Intercept")
        lower.addTab(self.rules_panel, "Rules")
        outer = QSplitter(Qt.Vertical)
        outer.addWidget(self._live_top)
        outer.addWidget(lower)
        outer.setSizes([260, 560])
        return self._ws("live", outer)

    def _refresh_flows(self) -> None:
        if not hasattr(self, "flows_table"):
            return
        self._live_top.setTabText(1, f"Flows ({self.flows.count()})")
        if self._live_top.currentIndex() != 1:
            return                                    # only repaint when the Flows tab is visible
        flows = self.flows.flows()
        self.flows_table.setRowCount(0)
        for f in flows:
            r = self.flows_table.rowCount(); self.flows_table.insertRow(r)
            vals = [f.proto, f.endpoints, str(f.packets), str(f.bytes),
                    f.state, f"{f.duration:.2f}s"]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setToolTip(v)
                if c == 0:
                    item.setForeground(QBrush(QColor(theme.proto_color(f.proto))))
                    item.setData(Qt.UserRole, (f.a_ip, f.a_port, f.b_ip, f.b_port))
                self.flows_table.setItem(r, c, item)

    def _on_flow_activated(self, item) -> None:
        """Double-click a flow -> jump to the Stream tab and select its first packet."""
        from reforge.core.flows import _dissect

        key = self.flows_table.item(item.row(), 0).data(Qt.UserRole)
        if not key:
            return
        aip, ap, bip, bp = key
        ends = {(aip, ap), (bip, bp)}
        for i, (_ts, frame) in enumerate(self.packets):
            try:
                info = _dissect(frame.data)
            except Exception:
                info = None
            if info and {(info[1], info[2]), (info[3], info[4])} == ends:
                self._live_top.setCurrentIndex(0)     # Stream tab
                self.table.selectRow(i)
                self.table.scrollToItem(self.table.item(i, 0))
                break

    def _ws_recon(self) -> QWidget:
        bottom = QSplitter(Qt.Horizontal)
        bottom.addWidget(self.recon_panel)
        bottom.addWidget(self.creds_panel)
        sp = QSplitter(Qt.Vertical)
        sp.addWidget(self.scan_panel)
        sp.addWidget(bottom)
        sp.setSizes([300, 360])
        return sp

    def _ws_craft(self) -> QWidget:
        t = QTabWidget()
        t.addTab(self.builder_panel, "Builder")
        t.addTab(self.fuzz_panel, "Fuzzing")
        return t

    def _ws_automate(self) -> QWidget:
        sp = QSplitter(Qt.Horizontal)
        sp.addWidget(self.scenario_panel)
        sp.addWidget(self.console_panel)
        return sp

    def _ws_system(self) -> QWidget:
        t = QTabWidget()
        t.addTab(self.diag_panel, "Diagnostics")
        t.addTab(self.guide_panel, "Guide")
        return t

    def _go_workspace(self, key) -> None:
        self.pane_area.set_active_workspace(key)

    def nav_reflect(self, key) -> None:
        self.nav.set_active(key)
    def _open_guide(self, section_key: str = "") -> None:
        """Switch to the System workspace, its Guide tab, and scroll to a section."""
        self._go_workspace("system")
        sysw = self._workspaces.get("system")
        if sysw is not None:
            tabs = sysw.findChild(QTabWidget)
            if tabs is not None:
                for i in range(tabs.count()):
                    if tabs.tabText(i) == "Guide":
                        tabs.setCurrentIndex(i)
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

    def _usable_iface_count(self) -> int:
        return len([i for i in list_interfaces()
                    if i not in ("lo", "<none>", "af_packet")])

    def _engine_advice(self, mitm_active: bool = False):
        """Recommend an inline engine (bridge vs NFQUEUE) for the detected host."""
        from reforge.diagnostics.doctor import (
            check_nfqueue_ready,
            recommend_inline_engine,
        )
        return recommend_inline_engine(self._usable_iface_count(),
                                       check_nfqueue_ready().ok, mitm_active)

    def _on_mode_changed(self, mode: str) -> None:
        bridge = mode == "Bridge"
        self.peer_label.setVisible(bridge)
        self.peer_combo.setVisible(bridge)
        if not bridge:
            return
        adv = self._engine_advice()
        if adv.engine == "bridge":
            self.statusBar().showMessage("Bridge engine: " + adv.reason + ". " + adv.alternative)
        elif adv.engine == "nfqueue":       # recommender steered away — usually <2 NICs
            self.statusBar().showMessage(
                "⚠ Bridge needs two interfaces — " + adv.reason +
                " (Attacks → MITM + “Intercept & rewrite”).")
        else:
            self.statusBar().showMessage("⚠ " + adv.reason + " — " + adv.alternative)

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
            QMessageBox.critical(self, "Capture error", explain(exc))
            return
        self.engagement.log("capture", "live on " + iface)
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
                                 flow_rewrite=self._auto_arm_seqfix(),
                                 checksum_fixup=self.act_csum.isChecked())
        state = "ARMED" if armed else "pass-through (safe)"
        warn = self._inline_preflight_warning([a, b])   # includes NIC offloads on a/b
        self.engagement.log("bridge", a + " <-> " + b + " [" + state + "]")
        label = f"bridge {a} <-> {b}  [{state}]"
        self._start_service(bridge, f"{warn}   {label}" if warn else label, reset=False)

    def open_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open pcap", "", "Capture files (*.pcap *.pcapng *.cap);;All files (*)"
        )
        if not path:
            return
        self.engagement.log("pcap", str(path))
        self._start_service(CaptureService(PcapFileBackend(path)), f"pcap {path}")

    def start_demo(self) -> None:
        """Replay synthetic lab traffic as a live capture (offline test env)."""
        from reforge.testlab.synthetic import SyntheticBackend

        self.engagement.log("demo", "synthetic lab traffic")
        self._start_service(CaptureService(SyntheticBackend(loop=True)),
                            "demo — synthetic lab traffic (looping)")

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
            QMessageBox.critical(self, "Start error", explain(exc))
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
        self.engagement.log("transform", desc)
        return f"Transform added ({desc}) — applies to all matching traffic and resends."

    def _send_to_builder(self, data: bytes) -> None:
        """Load a held/sent packet into the Builder (Craft) for replay/resend."""
        self.builder_panel.load_bytes(data)
        self._go_workspace("craft")
        craft = self._workspaces.get("craft")
        tabs = craft.findChild(QTabWidget) if craft is not None else None
        if tabs is not None:
            for i in range(tabs.count()):
                if tabs.tabText(i) == "Builder":
                    tabs.setCurrentIndex(i)
                    break
        self.statusBar().showMessage("Loaded packet into Builder — edit and send.")

    def _clear_transforms(self) -> None:
        """Remove every promoted 'apply to all' transform from the live engine."""
        self._transforms = []
        if self.engine is not None:
            self._install_intercept_filter(self.engine)
        self.intercept_panel.set_transform_count(0)
        self.statusBar().showMessage("Cleared all interactive transforms.")

    def _on_intercept_length_change(self, delta: int) -> None:
        """An interactive edit resized the packet. The intercept release path
        bypasses the seq-fixer, so this one edit can't be kept in sync — warn
        rather than pretend a toggle would help (use a rule for auto seq-fix)."""
        sign = f"+{delta}" if delta > 0 else str(delta)
        self.engagement.log("seqfix", f"length-changing interactive edit ({sign} bytes)")
        self.statusBar().showMessage(
            f"⚠ edit changed length by {sign} bytes — an interactive length change "
            "isn't seq-fixed and may desync this flow. Prefer a same-length edit, or a "
            "rule (rules are auto seq-fixed).")

    def _auto_arm_seqfix(self) -> bool:
        """Turn on TCP seq/ack fix-up when the rule set has a length-changing
        action — a grow/shrink edit desyncs the flow otherwise. Returns whether
        fix-up is on (respecting an operator who already enabled it)."""
        from reforge.rules.spec import rules_change_length
        if not self.act_seqfix.isChecked() and rules_change_length(self.rules_panel.specs):
            self.act_seqfix.setChecked(True)
            self.engagement.log("seqfix", "auto-armed (a rule changes payload length)")
            self.statusBar().showMessage(
                "Auto-enabled TCP seq-fix — a rule changes payload length, so the flow "
                "is kept in sync.")
        return self.act_seqfix.isChecked()

    def _inline_preflight_warning(self, ifaces: list | None = None) -> str:
        """Run the inline preflight; return a one-line warning naming any host-level
        blocker (FORWARD DROP, strict rp_filter, missing NFQUEUE, NIC offloads) that
        would silently swallow relayed traffic, or '' when clear."""
        try:
            from reforge.diagnostics.doctor import inline_blockers
            blockers = inline_blockers(ifaces)
        except Exception:
            return ""
        if not blockers:
            return ""
        parts = "; ".join(f"{b.name} — {b.fix}" for b in blockers)
        self.engagement.log("preflight", "inline blockers: " + parts)
        return "⚠ inline preflight: " + parts

    def _start_inline(self, iface: str, victims: list) -> str:
        """Divert a MITM'd victim's forwarded traffic into the rule engine +
        interactive intercept via NFQUEUE. Returns a status string."""
        import subprocess
        import threading

        from reforge.capture.nfqueue import NfqueueRunner, nft_forward_queue_rules

        warn = self._inline_preflight_warning()      # NFQUEUE relays via the kernel
        self._stop_inline()
        engine = self.rules_panel.build_engine(dry_run=False)
        self.engine = engine
        self._install_intercept_filter(engine)      # the Intercept-tab filter applies here too
        queue = self._shared_intercept_queue()
        self.intercept_panel.set_transform_count(len(self._transforms))

        install, self._nfq_remove = nft_forward_queue_rules(1, victims or None)
        for cmd in install:
            subprocess.run(cmd, capture_output=True, check=False)
        seq_fixer = None
        if self._auto_arm_seqfix():          # keep flows in sync on length-changing edits
            from reforge.core.flowrewrite import FlowRewriter
            seq_fixer = FlowRewriter()
        self._nfq_runner = NfqueueRunner(engine, queue_num=1, intercept=queue,
                                         seq_fixer=seq_fixer)
        self._nfq_thread = threading.Thread(target=self._nfq_runner.run, daemon=True)
        self._nfq_thread.start()
        self.engagement.log("mitm-inline", "NFQUEUE victims: " + ", ".join(victims or []))
        base = ("Inline manipulation ON — victim traffic flows through the Intercept tab. "
                "Set a filter to hold, or add rules.")
        self.statusBar().showMessage(f"{warn}   {base}" if warn else base)
        return "inline via NFQUEUE" + (f"  [{warn}]" if warn else "")

    def _stop_inline(self) -> None:
        import subprocess

        runner = getattr(self, "_nfq_runner", None)
        if runner is not None:
            try:
                runner.stop()
            except Exception:
                pass
            self._nfq_runner = None
        # wait for the runner loop to unbind the kernel queue before returning,
        # so a quick restart (_start_inline calls _stop_inline first) can rebind
        # the same queue number instead of failing with "Failed to create queue".
        thread = getattr(self, "_nfq_thread", None)
        if thread is not None:
            thread.join(timeout=3.0)
            self._nfq_thread = None
        for cmd in getattr(self, "_nfq_remove", []):
            subprocess.run(cmd, capture_output=True, check=False)
        self._nfq_remove = []

    def _snapshot_engagement(self) -> None:
        try:
            self.engagement.snapshot(hosts=self.recon_panel.host_dicts(),
                                     creds=self.creds_panel.harvested_creds())
        except Exception:
            log.debug("engagement snapshot failed", exc_info=True)

    def _report_stats(self) -> dict:
        st = {"packets": len(self.packets), "flows": self.flows.count()}
        if self.intercept is not None:
            s = self.intercept.stats
            st["forwarded"] = s.get("forwarded", 0) + s.get("modified", 0)
            st["modified"] = s.get("modified", 0)
            st["dropped"] = s.get("dropped", 0)
        return st

    def _export_report(self) -> None:
        self._snapshot_engagement()
        path, _ = QFileDialog.getSaveFileName(self, "Export engagement report",
                                              "reforge-report.html",
                                              "HTML (*.html);;Markdown (*.md);;JSON (*.json)")
        if not path:
            return
        try:
            if path.endswith(".md"):
                data = self.engagement.render_markdown()
            elif path.endswith(".json"):
                data = self.engagement.to_report().to_json()
            else:
                data = self.engagement.render_html(self._report_stats())
            with open(path, "w") as fh:
                fh.write(data)
            self.statusBar().showMessage(f"Report written to {path}")
        except Exception as exc:
            QMessageBox.critical(self, "Report error", explain(exc))

    def _new_engagement(self) -> None:
        if QMessageBox.question(self, "New engagement",
                                "Clear the current hosts, credentials, and timeline?") \
                != QMessageBox.Yes:
            return
        self.engagement.reset()
        self.recon_panel.clear()
        self.creds_panel.table.setRowCount(0)
        self.creds_panel._seen.clear()
        self.creds_panel.harvested.clear()
        self.creds_panel.count.setText("Credentials harvested: 0")
        self.engagement.save(self._engagement_path)
        self.statusBar().showMessage("New engagement — cleared.")

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
        self.flows.clear()
        if hasattr(self, "flows_table"):
            self.flows_table.setRowCount(0)
        self.intercept_panel.set_original(b"")
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
        self._refresh_flows()
        n = self._flush_rows()
        if n == 0 and not self.service.running:
            err = getattr(self.service, "error", None)
            err = explain(err) if err else err
            self.stop_capture()
            if err:                             # stopped on an error (e.g. iface lost)
                self.statusBar().showMessage(f"Capture stopped: {err}")
                QMessageBox.warning(self, "Capture stopped", f"The capture stopped:\n\n{err}")
        elif n:
            self.statusBar().showMessage(
                f"Capturing — {len(self.packets)} packets{self._loss_suffix()}")

    def _loss_suffix(self) -> str:
        """A visible ' · dropped N (X%)' tail when capture is losing frames."""
        fn = getattr(self.service, "stats", None)
        if fn is None:
            return ""
        try:
            st = fn()
        except Exception:
            return ""
        if st.get("total_dropped", 0) <= 0:
            return ""
        kern = st.get("kernel_dropped", 0)
        where = " (kernel — raise buffer / faster backend)" if kern else " (UI backpressure)"
        return f"   ⚠ dropped {st['total_dropped']} ({st['loss_pct']}%){where}"

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
        self.flows.observe(ts, frame.data)
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
            item.setToolTip(v)   # never hide: hover reveals the full cell
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
        self.intercept_panel.set_original(frame.data)

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
            QMessageBox.critical(self, "Vault error", explain(exc))

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
        self._save_layout()                   # remember the pane split + workspaces
        self._stop_inline()
        self.stop_capture()
        self._snapshot_engagement()
        try:
            self.engagement.save(self._engagement_path)
        except Exception:
            log.debug("engagement save failed", exc_info=True)
        for cleanup in (self.attacks_panel.stop_all, self.console_panel.stop):
            try:
                cleanup()
            except Exception:
                pass
        super().closeEvent(event)


_ = _dt  # reserved for absolute-time column formatting
