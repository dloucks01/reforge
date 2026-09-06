"""Theming for Reforge — dark + light palettes, QSS, protocol colors.

One place owns the look. Two palettes (dark/light) share the same keys; the
active one is copied into module globals (ACCENT, BORDER, TEXT, ...) so callers
can read ``theme.ACCENT`` and always get the current theme. The choice persists
to the config dir.
"""

from __future__ import annotations

import json
import logging

from reforge.constants import CONFIG_DIR, ensure_dirs

log = logging.getLogger("reforge.theme")

DARK = {
    "BG": "#0f1117",
    "BG_PANEL": "#161923",
    "BG_ELEV": "#1d212e",
    "BG_ELEV2": "#232838",
    "BORDER": "#2b3040",
    "BORDER_LIGHT": "#363c50",
    "TEXT": "#e7ebf3",
    "TEXT_MUTED": "#8b93a7",
    "TEXT_DIM": "#5c6478",
    "ACCENT": "#5b8cff",
    "ACCENT_HOVER": "#7aa2ff",
    "ACCENT_DIM": "#2a3552",
    "HL_TEXT": "#0b0d12",
    "DANGER": "#ff5c6c",
    "OK": "#3ddc97",
    "PROTO": {
        "TCP": "#6ea8fe", "UDP": "#63e6be", "ICMP": "#ffd43b", "ICMPv6": "#ffd43b",
        "ARP": "#ffa94d", "DNS": "#b197fc", "DHCP": "#b197fc", "TLS": "#74c0fc",
        "HTTP": "#74c0fc", "Ethernet": "#8b93a7", "IP": "#9aa4bd", "IPv6": "#9aa4bd",
    },
}

LIGHT = {
    "BG": "#eef1f7",
    "BG_PANEL": "#ffffff",
    "BG_ELEV": "#f2f5fa",
    "BG_ELEV2": "#e5eaf3",
    "BORDER": "#d4dae6",
    "BORDER_LIGHT": "#c2cad9",
    "TEXT": "#1b2130",
    "TEXT_MUTED": "#5a6478",
    "TEXT_DIM": "#9aa2b4",
    "ACCENT": "#2f6bff",
    "ACCENT_HOVER": "#1b57f0",
    "ACCENT_DIM": "#d7e2ff",
    "HL_TEXT": "#ffffff",
    "DANGER": "#d23c4b",
    "OK": "#12925f",
    "PROTO": {
        "TCP": "#1f6feb", "UDP": "#0c8a6a", "ICMP": "#b7791f", "ICMPv6": "#b7791f",
        "ARP": "#c1590a", "DNS": "#7048e8", "DHCP": "#7048e8", "TLS": "#1f6feb",
        "HTTP": "#1f6feb", "Ethernet": "#5a6478", "IP": "#6b7488", "IPv6": "#6b7488",
    },
}

PALETTES = {"dark": DARK, "light": LIGHT}
_SETTINGS = CONFIG_DIR / "ui.json"

# --- active palette, mirrored into module globals ---------------------------
_active_name = "dark"
_active = DARK

# module-level color names (updated by _sync); declared here for callers/linters
BG = BG_PANEL = BG_ELEV = BG_ELEV2 = BORDER = BORDER_LIGHT = ""
TEXT = TEXT_MUTED = TEXT_DIM = ACCENT = ACCENT_HOVER = ACCENT_DIM = ""
HL_TEXT = DANGER = OK = ""
PROTO_COLORS: dict[str, str] = {}
PROTO_DEFAULT = ""
PROTO_MALFORMED = ""


def _sync() -> None:
    g = globals()
    for key in ("BG", "BG_PANEL", "BG_ELEV", "BG_ELEV2", "BORDER", "BORDER_LIGHT",
                "TEXT", "TEXT_MUTED", "TEXT_DIM", "ACCENT", "ACCENT_HOVER",
                "ACCENT_DIM", "HL_TEXT", "DANGER", "OK"):
        g[key] = _active[key]
    g["PROTO_COLORS"] = _active["PROTO"]
    g["PROTO_DEFAULT"] = _active["TEXT"]
    g["PROTO_MALFORMED"] = _active["DANGER"]


_sync()


def current_mode() -> str:
    return _active_name


def proto_color(proto: str) -> str:
    return _active["PROTO"].get(proto, _active["TEXT"])


def load_mode(default: str = "dark") -> str:
    try:
        return json.loads(_SETTINGS.read_text()).get("theme", default)
    except Exception:
        return default


def save_mode(mode: str) -> None:
    try:
        ensure_dirs()
        _SETTINGS.write_text(json.dumps({"theme": mode}))
    except Exception:
        log.debug("could not persist theme choice", exc_info=True)


def qss(pal: dict | None = None) -> str:
    p = pal or _active
    return f"""
* {{
    font-family: "Inter", "Segoe UI", "Noto Sans", sans-serif;
    font-size: 13px;
    color: {p['TEXT']};
}}
QMainWindow, QWidget {{ background: {p['BG']}; }}

QToolBar {{
    background: {p['BG_PANEL']};
    border: none;
    border-bottom: 1px solid {p['BORDER']};
    padding: 6px 8px;
    spacing: 6px;
}}
QToolBar QLabel {{ color: {p['TEXT_MUTED']}; padding: 0 2px; }}
QToolButton {{
    background: {p['BG_ELEV']};
    border: 1px solid {p['BORDER']};
    border-radius: 6px;
    padding: 6px 14px;
    color: {p['TEXT']};
    font-weight: 600;
}}
QToolButton:hover {{ background: {p['BG_ELEV2']}; border-color: {p['BORDER_LIGHT']}; }}
QToolButton:pressed {{ background: {p['ACCENT_DIM']}; }}
QToolButton:disabled {{ color: {p['TEXT_DIM']}; background: {p['BG_PANEL']}; border-color: {p['BORDER']}; }}

QLineEdit, QComboBox {{
    background: {p['BG_ELEV']};
    border: 1px solid {p['BORDER']};
    border-radius: 6px;
    padding: 5px 9px;
    selection-background-color: {p['ACCENT']};
    selection-color: {p['HL_TEXT']};
}}
QLineEdit:focus, QComboBox:focus {{ border-color: {p['ACCENT']}; }}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background: {p['BG_ELEV']};
    border: 1px solid {p['BORDER_LIGHT']};
    selection-background-color: {p['ACCENT_DIM']};
    outline: none;
}}

QTableWidget, QTreeWidget, QPlainTextEdit {{
    background: {p['BG_PANEL']};
    alternate-background-color: {p['BG_ELEV']};
    border: 1px solid {p['BORDER']};
    border-radius: 8px;
    gridline-color: {p['BORDER']};
    outline: none;
}}
QTableWidget::item, QTreeWidget::item {{ padding: 4px 6px; border: none; }}
QTableWidget::item:selected, QTreeWidget::item:selected {{
    background: {p['ACCENT_DIM']};
    color: {p['TEXT']};
}}
QHeaderView::section {{
    background: {p['BG_ELEV']};
    color: {p['TEXT_MUTED']};
    border: none;
    border-right: 1px solid {p['BORDER']};
    border-bottom: 1px solid {p['BORDER']};
    padding: 7px 8px;
    font-weight: 600;
}}
QTableCornerButton::section {{ background: {p['BG_ELEV']}; border: none; }}
QTreeWidget {{ show-decoration-selected: 1; }}

QPlainTextEdit {{
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    font-size: 12px;
    selection-background-color: {p['ACCENT']};
    selection-color: {p['HL_TEXT']};
    padding: 6px;
}}

QDockWidget::title {{
    background: {p['BG_ELEV']};
    padding: 7px 10px;
    border-bottom: 1px solid {p['BORDER']};
    color: {p['TEXT_MUTED']};
    font-weight: 600;
}}

QSplitter::handle {{ background: {p['BORDER']}; }}
QSplitter::handle:horizontal {{ width: 3px; }}
QSplitter::handle:vertical {{ height: 3px; }}
QSplitter::handle:hover {{ background: {p['ACCENT']}; }}

QStatusBar {{
    background: {p['BG_PANEL']};
    border-top: 1px solid {p['BORDER']};
    color: {p['TEXT_MUTED']};
}}
QStatusBar::item {{ border: none; }}

QScrollBar:vertical {{ background: {p['BG']}; width: 12px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {p['BORDER_LIGHT']}; border-radius: 6px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {p['ACCENT']}; }}
QScrollBar:horizontal {{ background: {p['BG']}; height: 12px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {p['BORDER_LIGHT']}; border-radius: 6px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background: {p['ACCENT']}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}

QMenu {{ background: {p['BG_ELEV']}; border: 1px solid {p['BORDER_LIGHT']}; padding: 4px; }}
QMenu::item {{ padding: 6px 22px; border-radius: 4px; }}
QMenu::item:selected {{ background: {p['ACCENT_DIM']}; }}
QMessageBox {{ background: {p['BG_PANEL']}; }}
QToolTip {{
    background: {p['BG_ELEV2']}; color: {p['TEXT']};
    border: 1px solid {p['BORDER_LIGHT']}; padding: 5px 8px; border-radius: 4px;
}}
"""


def apply_theme(app, mode: str | None = None) -> str:
    """Apply Fusion base + palette + QSS for `mode` (dark/light). Returns mode."""
    global _active_name, _active
    from PySide6.QtGui import QColor, QPalette

    mode = mode or _active_name
    _active = PALETTES.get(mode, DARK)
    _active_name = "light" if _active is LIGHT else "dark"
    _sync()

    app.setStyle("Fusion")
    p = _active
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(p["BG"]))
    pal.setColor(QPalette.Base, QColor(p["BG_PANEL"]))
    pal.setColor(QPalette.AlternateBase, QColor(p["BG_ELEV"]))
    pal.setColor(QPalette.Text, QColor(p["TEXT"]))
    pal.setColor(QPalette.WindowText, QColor(p["TEXT"]))
    pal.setColor(QPalette.Button, QColor(p["BG_ELEV"]))
    pal.setColor(QPalette.ButtonText, QColor(p["TEXT"]))
    pal.setColor(QPalette.Highlight, QColor(p["ACCENT"]))
    pal.setColor(QPalette.HighlightedText, QColor(p["HL_TEXT"]))
    pal.setColor(QPalette.ToolTipBase, QColor(p["BG_ELEV2"]))
    pal.setColor(QPalette.ToolTipText, QColor(p["TEXT"]))
    pal.setColor(QPalette.PlaceholderText, QColor(p["TEXT_DIM"]))
    app.setPalette(pal)
    app.setStyleSheet(qss())
    return _active_name


def toggle_mode() -> str:
    return "light" if _active_name == "dark" else "dark"
