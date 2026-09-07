"""Interactive intercept & edit panel.

Lists packets the engine HELD, lets the operator edit fields (editable tree) or
raw bytes (hex box), then Forward / Forward-modified / Drop. Resolving calls back
into the InterceptQueue, which releases the packet on the correct egress.
"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from reforge.core.packet import Packet
from reforge.dissect import scapy_tree
from reforge.rules.filter import FilterError, parse_filter

HELD_COLUMNS = ["ID", "Ingress", "Proto", "Info", "Age"]
_LAYER_FIELD = Qt.UserRole + 1


class InterceptPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.queue = None
        self._current_id: int | None = None
        self._work: bytes = b""
        self._current_kind = "packet"
        self._applying = False
        # Set by the main window: on_filter(match_or_None, text) installs/clears a
        # HOLD rule; on_promote(original, edited) turns an edit into a persistent
        # transform applied to all matching traffic (and resends).
        self.on_filter = None
        self.on_promote = None
        self.on_queue_config = None    # called with (max_held, auto_release_s, overflow)

        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)

        # --- intercept filter bar: which packets to catch -------------------
        fbar = QHBoxLayout()
        self.enable_check = QCheckBox("Intercept")
        self.enable_check.setToolTip("Hold matching packets for edit; others pass through")
        self.enable_check.toggled.connect(self._apply_filter)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(
            'catch filter, e.g.  TCP.dport == 80 and Raw.load contains "login"')
        self.filter_edit.returnPressed.connect(self._apply_filter)
        btn_apply = QPushButton("Apply"); btn_apply.clicked.connect(self._apply_filter)
        fbar.addWidget(self.enable_check)
        fbar.addWidget(self.filter_edit, 1)
        fbar.addWidget(btn_apply)
        root.addLayout(fbar)

        # --- volume safeguards: never drown the queue or stall the wire -----
        vbar = QHBoxLayout()
        vbar.addWidget(QLabel("Hold at most:"))
        self.limit_spin = QSpinBox(); self.limit_spin.setRange(0, 100000)
        self.limit_spin.setValue(20); self.limit_spin.setSpecialValueText("∞")
        self.limit_spin.setToolTip("Max packets held at once (0 = unlimited). "
                                   "Extra matches auto-resolve instead of piling up.")
        self.limit_spin.valueChanged.connect(self._push_queue_config)
        vbar.addWidget(self.limit_spin)
        vbar.addWidget(QLabel("  Auto-release after:"))
        self.autorel_spin = QSpinBox(); self.autorel_spin.setRange(0, 3600)
        self.autorel_spin.setSuffix(" s"); self.autorel_spin.setValue(0)
        self.autorel_spin.setSpecialValueText("off")
        self.autorel_spin.setToolTip("A held packet not acted on in this many seconds "
                                     "auto-resolves, so the wire never stalls (0 = off).")
        self.autorel_spin.valueChanged.connect(self._push_queue_config)
        vbar.addWidget(self.autorel_spin)
        vbar.addWidget(QLabel("  On overflow:"))
        self.overflow_combo = QComboBox(); self.overflow_combo.addItems(["forward", "drop"])
        self.overflow_combo.currentTextChanged.connect(self._push_queue_config)
        vbar.addWidget(self.overflow_combo)
        vbar.addStretch(1)
        root.addLayout(vbar)

        self.filter_status = QLabel("Intercept off — all traffic passes through.")
        self.filter_status.setStyleSheet("color: palette(mid);")
        root.addWidget(self.filter_status)

        self.header = QLabel("Interception queue — held: 0")
        self.header.setStyleSheet("font-weight: 700;")
        root.addWidget(self.header)

        # --- search box over the held queue ---------------------------------
        sbar = QHBoxLayout()
        sbar.addWidget(QLabel("Search:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("filter the held list (id / iface / proto / info)")
        self.search_edit.textChanged.connect(self._apply_search)
        sbar.addWidget(self.search_edit, 1)
        root.addLayout(sbar)

        split = QSplitter(Qt.Vertical)

        self.table = QTableWidget(0, len(HELD_COLUMNS))
        self.table.setHorizontalHeaderLabels(HELD_COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._on_select)
        split.addWidget(self.table)

        editor = QWidget()
        elayout = QVBoxLayout(editor)
        elayout.setContentsMargins(0, 0, 0, 0)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value (double-click to edit)"])
        self.tree.setColumnWidth(0, 220)
        self.tree.itemChanged.connect(self._on_field_edited)
        elayout.addWidget(self.tree)

        mono = QFont("JetBrains Mono"); mono.setStyleHint(QFont.Monospace)
        self.hex_edit = QPlainTextEdit()
        self.hex_edit.setFont(mono)
        self.hex_edit.setPlaceholderText("raw bytes as hex (editable) — then Apply hex")
        elayout.addWidget(self.hex_edit)

        buttons = QHBoxLayout()
        self.btn_apply_hex = QPushButton("Apply hex")
        self.btn_all = QPushButton("Apply to all")
        self.btn_all.setToolTip("Turn this edit into a persistent transform applied to "
                                "every matching packet, including resends")
        self.btn_fwd = QPushButton("Forward")
        self.btn_mod = QPushButton("Forward modified")
        self.btn_drop = QPushButton("Drop")
        self.btn_apply_hex.clicked.connect(self._apply_hex)
        self.btn_all.clicked.connect(self._apply_to_all)
        self.btn_fwd.clicked.connect(lambda: self._resolve("forward"))
        self.btn_mod.clicked.connect(lambda: self._resolve("modify"))
        self.btn_drop.clicked.connect(lambda: self._resolve("drop"))
        buttons.addWidget(self.btn_apply_hex)
        buttons.addStretch(1)
        buttons.addWidget(self.btn_all)
        buttons.addWidget(self.btn_fwd)
        buttons.addWidget(self.btn_mod)
        buttons.addWidget(self.btn_drop)
        elayout.addLayout(buttons)

        split.addWidget(editor)
        split.setSizes([180, 360])
        root.addWidget(split)
        self._set_buttons_enabled(False)

    # ---- intercept filter / search -----------------------------------------
    def _apply_filter(self) -> None:
        """Compile the filter box and (via on_filter) install/clear a HOLD rule."""
        enabled = self.enable_check.isChecked()
        text = self.filter_edit.text().strip()
        if not enabled:
            if self.on_filter is not None:
                self.on_filter(None, "")
            self.filter_status.setText("Intercept off — all traffic passes through.")
            self.filter_status.setStyleSheet("color: palette(mid);")
            return
        if not text:
            match = None                       # empty + enabled = hold everything
        else:
            try:
                match = parse_filter(text)
            except FilterError as exc:
                self.filter_status.setText(f"Filter error: {exc}")
                self.filter_status.setStyleSheet("color: #c0392b; font-weight: 600;")
                return
        if self.on_filter is not None:
            self.on_filter(match, text)
        shown = text or "all packets"
        self.filter_status.setText(f"Holding: {shown}")
        self.filter_status.setStyleSheet("color: #27ae60; font-weight: 600;")

    def _apply_search(self) -> None:
        needle = self.search_edit.text().strip().lower()
        for r in range(self.table.rowCount()):
            if not needle:
                self.table.setRowHidden(r, False)
                continue
            hay = " ".join(
                (self.table.item(r, c).text() if self.table.item(r, c) else "")
                for c in range(self.table.columnCount())
            ).lower()
            self.table.setRowHidden(r, needle not in hay)

    # ---- queue binding ------------------------------------------------------
    def set_queue(self, queue) -> None:
        self.queue = queue
        self._current_id = None
        if not hasattr(self, "_timer"):
            self._timer = QTimer(self)
            self._timer.setInterval(200)
            self._timer.timeout.connect(self._tick)
        if queue is None:
            self._timer.stop()
            self.table.setRowCount(0)
            self.tree.clear()
            self.hex_edit.clear()
            self.header.setText("Interception queue — held: 0")
            self._set_buttons_enabled(False)
            return
        self.refresh_pending()
        self._timer.start()          # self-refresh (works with bridge or proxy)

    def _tick(self) -> None:
        if self.queue is None:
            return
        self.queue.reap()            # auto-release timed-out holds
        self.refresh_pending()

    def refresh_pending(self) -> None:
        if self.queue is None:
            return
        pending = self.queue.pending()
        self.header.setText(f"Interception queue — held: {len(pending)}")
        selected = self._current_id
        self.table.setRowCount(0)
        now = time.time()
        for hp in pending:
            r = self.table.rowCount()
            self.table.insertRow(r)
            if hp.kind == "message":
                proto = "HTTP"
                info = (hp.meta or {}).get("summary", "")
            else:
                try:
                    pkt = __import__("scapy.layers.l2", fromlist=["Ether"]).Ether(hp.data)
                    row = scapy_tree.summarize(pkt)
                    proto, info = row.proto, row.info
                except Exception:
                    proto, info = "?", ""
            vals = [str(hp.id), hp.ingress, proto, info, f"{now - hp.ts:.1f}s"]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setData(Qt.UserRole, hp.id)
                self.table.setItem(r, c, item)
        # keep the previously selected row if still present
        if selected is not None:
            for r in range(self.table.rowCount()):
                if self.table.item(r, 0).data(Qt.UserRole) == selected:
                    self.table.selectRow(r)
                    break
        self._apply_search()                    # keep the active search applied

    # ---- detail / editing ---------------------------------------------------
    def _on_select(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows or self.queue is None:
            return
        pid = self.table.item(rows[0].row(), 0).data(Qt.UserRole)
        hp = self.queue.get(pid)
        if hp is None:
            return
        self._current_id = pid
        self._current_kind = hp.kind
        # message items edit as text (HTTP), packets keep the tree + hex view
        self.btn_apply_hex.setText("Apply text" if hp.kind == "message" else "Apply hex")
        self.tree.setVisible(hp.kind != "message")
        self._set_work_bytes(hp.data)
        self._set_buttons_enabled(True)

    def _set_work_bytes(self, data: bytes) -> None:
        self._work = bytes(data)
        self._applying = True
        if self._current_kind == "message":
            self.tree.clear()
            self.hex_edit.setPlainText(self._work.decode("latin-1"))  # editable HTTP text
        else:
            self._rebuild_tree()
            self.hex_edit.setPlainText(" ".join(f"{b:02x}" for b in self._work))
        self._applying = False

    def _rebuild_tree(self) -> None:
        self._applying = True
        self.tree.clear()
        try:
            from scapy.layers.l2 import Ether

            for layer in scapy_tree.to_tree(Ether(self._work)):
                parent = QTreeWidgetItem([layer.name, ""])
                parent.setFlags(parent.flags() & ~Qt.ItemIsEditable)
                for f in layer.fields:
                    child = QTreeWidgetItem([f.name, f.human])
                    child.setFlags(child.flags() | Qt.ItemIsEditable)
                    child.setData(0, _LAYER_FIELD, (layer.name, f.name))
                    parent.addChild(child)
                self.tree.addTopLevelItem(parent)
                parent.setExpanded(True)
        except Exception:
            pass
        self._applying = False

    def _on_field_edited(self, item: QTreeWidgetItem, column: int) -> None:
        if self._applying or column != 1:
            return
        meta = item.data(0, _LAYER_FIELD)
        if not meta:
            return
        layer, field = meta
        text = item.text(1)
        try:
            pkt = Packet.from_bytes(self._work, link="ether")
            pkt.set_field(layer, field, text)
            self._set_work_bytes(pkt.rebuild())
        except Exception:
            self._rebuild_tree()  # revert display on bad input

    def _message_bytes(self) -> bytes:
        """Encode the edited message text, restoring CRLF line endings.

        Qt's plain-text widget collapses CRLF to LF; HTTP framing needs CRLF, so
        canonicalize any mix back to CRLF before the bytes go on the wire."""
        text = self.hex_edit.toPlainText().replace("\r\n", "\n").replace("\r", "\n")
        return text.replace("\n", "\r\n").encode("latin-1", "ignore")

    def _apply_hex(self) -> None:
        if self._current_kind == "message":
            self._work = self._message_bytes()
            return
        raw = self.hex_edit.toPlainText().replace(":", " ").split()
        try:
            data = bytes(int(b, 16) for b in raw)
            self._set_work_bytes(data)
        except Exception:
            pass

    def _resolve(self, action: str) -> None:
        if self.queue is None or self._current_id is None:
            return
        if action == "modify" and self._current_kind == "message":
            self._work = self._message_bytes()
        self.queue.resolve(self._current_id, action, self._work if action == "modify" else None)
        self._current_id = None
        self.tree.setVisible(True)
        self.tree.clear()
        self.hex_edit.clear()
        self._set_buttons_enabled(False)
        self.refresh_pending()

    def _set_buttons_enabled(self, on: bool) -> None:
        for b in (self.btn_apply_hex, self.btn_all, self.btn_fwd, self.btn_mod, self.btn_drop):
            b.setEnabled(on)

    # ---- volume safeguards / promote ---------------------------------------
    def queue_config(self) -> tuple[int, float, str]:
        """(max_held, auto_release_s, overflow) for creating/updating the queue."""
        return (self.limit_spin.value(), float(self.autorel_spin.value()),
                self.overflow_combo.currentText())

    def _push_queue_config(self) -> None:
        if self.on_queue_config is not None:
            self.on_queue_config(*self.queue_config())

    def _apply_to_all(self) -> None:
        """Promote the current edit to a persistent transform, then forward it."""
        if self.queue is None or self._current_id is None or self.on_promote is None:
            return
        hp = self.queue.get(self._current_id)
        if hp is None:
            return
        msg = self.on_promote(hp.data, self._work)      # derive + install transform
        # forwarding the current edited packet is also part of "apply to all"
        self._resolve("modify")
        self.filter_status.setText(msg)
        self.filter_status.setStyleSheet("color: #27ae60; font-weight: 600;")
        # promoting turns off interactive holding for this filter; the transform
        # now handles the rest of the stream automatically.
        self.enable_check.setChecked(False)
