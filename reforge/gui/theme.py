"""Dark theme for Reforge — palette, Qt stylesheet, and protocol colors.

One place owns the look: colors here, QSS built from them, and a protocol→color
map for the packet list. Applied via apply_theme() in gui/app.py.
"""

from __future__ import annotations

# --- palette ----------------------------------------------------------------
BG = "#0f1117"          # window ground (deep charcoal)
BG_PANEL = "#161923"    # docks / panels
BG_ELEV = "#1d212e"     # inputs / headers
BG_ELEV2 = "#232838"    # hover / alt rows
BORDER = "#2b3040"
BORDER_LIGHT = "#363c50"
TEXT = "#e7ebf3"
TEXT_MUTED = "#8b93a7"
TEXT_DIM = "#5c6478"
ACCENT = "#5b8cff"      # primary accent (indigo-blue)
ACCENT_HOVER = "#7aa2ff"
ACCENT_DIM = "#2a3552"
DANGER = "#ff5c6c"
OK = "#3ddc97"

# --- protocol colors (foreground in the packet list) ------------------------
PROTO_COLORS: dict[str, str] = {
    "TCP": "#6ea8fe",
    "UDP": "#63e6be",
    "ICMP": "#ffd43b",
    "ICMPv6": "#ffd43b",
    "ARP": "#ffa94d",
    "DNS": "#b197fc",
    "DHCP": "#b197fc",
    "TLS": "#74c0fc",
    "HTTP": "#74c0fc",
    "Ethernet": "#8b93a7",
    "IP": "#9aa4bd",
    "IPv6": "#9aa4bd",
}
PROTO_DEFAULT = TEXT
PROTO_MALFORMED = DANGER


def proto_color(proto: str) -> str:
    return PROTO_COLORS.get(proto, PROTO_DEFAULT)


def qss() -> str:
    return f"""
* {{
    font-family: "Inter", "Segoe UI", "Noto Sans", sans-serif;
    font-size: 13px;
    color: {TEXT};
}}
QMainWindow, QWidget {{ background: {BG}; }}

/* Toolbar */
QToolBar {{
    background: {BG_PANEL};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 6px 8px;
    spacing: 6px;
}}
QToolBar QLabel {{ color: {TEXT_MUTED}; padding: 0 2px; }}
QToolButton {{
    background: {BG_ELEV};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 14px;
    color: {TEXT};
    font-weight: 600;
}}
QToolButton:hover {{ background: {BG_ELEV2}; border-color: {BORDER_LIGHT}; }}
QToolButton:pressed {{ background: {ACCENT_DIM}; }}
QToolButton:disabled {{ color: {TEXT_DIM}; background: {BG_PANEL}; border-color: {BORDER}; }}

/* Inputs */
QLineEdit, QComboBox {{
    background: {BG_ELEV};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 5px 9px;
    selection-background-color: {ACCENT};
    selection-color: #0b0d12;
}}
QLineEdit:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background: {BG_ELEV};
    border: 1px solid {BORDER_LIGHT};
    selection-background-color: {ACCENT_DIM};
    outline: none;
}}

/* Packet table */
QTableWidget, QTreeWidget, QPlainTextEdit {{
    background: {BG_PANEL};
    alternate-background-color: {BG_ELEV};
    border: 1px solid {BORDER};
    border-radius: 8px;
    gridline-color: {BORDER};
    outline: none;
}}
QTableWidget::item, QTreeWidget::item {{ padding: 4px 6px; border: none; }}
QTableWidget::item:selected, QTreeWidget::item:selected {{
    background: {ACCENT_DIM};
    color: {TEXT};
}}
QHeaderView::section {{
    background: {BG_ELEV};
    color: {TEXT_MUTED};
    border: none;
    border-right: 1px solid {BORDER};
    border-bottom: 1px solid {BORDER};
    padding: 7px 8px;
    font-weight: 600;
}}
QTableCornerButton::section {{ background: {BG_ELEV}; border: none; }}

/* Tree */
QTreeWidget {{ show-decoration-selected: 1; }}
QTreeWidget::branch {{ background: {BG_PANEL}; }}

/* Hex view */
QPlainTextEdit {{
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    font-size: 12px;
    color: #c8d0e0;
    selection-background-color: {ACCENT};
    selection-color: #0b0d12;
    padding: 6px;
}}

/* Docks */
QDockWidget {{ titlebar-close-icon: none; }}
QDockWidget::title {{
    background: {BG_ELEV};
    padding: 7px 10px;
    border-bottom: 1px solid {BORDER};
    color: {TEXT_MUTED};
    font-weight: 600;
}}

/* Splitter */
QSplitter::handle {{ background: {BORDER}; }}
QSplitter::handle:horizontal {{ width: 3px; }}
QSplitter::handle:vertical {{ height: 3px; }}
QSplitter::handle:hover {{ background: {ACCENT}; }}

/* Status bar */
QStatusBar {{
    background: {BG_PANEL};
    border-top: 1px solid {BORDER};
    color: {TEXT_MUTED};
}}
QStatusBar::item {{ border: none; }}

/* Scrollbars */
QScrollBar:vertical {{ background: {BG}; width: 12px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {BORDER_LIGHT}; border-radius: 6px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
QScrollBar:horizontal {{ background: {BG}; height: 12px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {BORDER_LIGHT}; border-radius: 6px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background: {ACCENT}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}

/* Menus / dialogs */
QMenu {{ background: {BG_ELEV}; border: 1px solid {BORDER_LIGHT}; padding: 4px; }}
QMenu::item {{ padding: 6px 22px; border-radius: 4px; }}
QMenu::item:selected {{ background: {ACCENT_DIM}; }}
QMessageBox {{ background: {BG_PANEL}; }}
QToolTip {{
    background: {BG_ELEV2}; color: {TEXT};
    border: 1px solid {BORDER_LIGHT}; padding: 5px 8px; border-radius: 4px;
}}
"""


def apply_theme(app) -> None:
    """Apply the Fusion base + dark palette + Reforge QSS to a QApplication."""
    from PySide6.QtGui import QColor, QPalette

    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(BG))
    pal.setColor(QPalette.Base, QColor(BG_PANEL))
    pal.setColor(QPalette.AlternateBase, QColor(BG_ELEV))
    pal.setColor(QPalette.Text, QColor(TEXT))
    pal.setColor(QPalette.WindowText, QColor(TEXT))
    pal.setColor(QPalette.Button, QColor(BG_ELEV))
    pal.setColor(QPalette.ButtonText, QColor(TEXT))
    pal.setColor(QPalette.Highlight, QColor(ACCENT))
    pal.setColor(QPalette.HighlightedText, QColor("#0b0d12"))
    pal.setColor(QPalette.ToolTipBase, QColor(BG_ELEV2))
    pal.setColor(QPalette.ToolTipText, QColor(TEXT))
    pal.setColor(QPalette.PlaceholderText, QColor(TEXT_DIM))
    app.setPalette(pal)
    app.setStyleSheet(qss())
