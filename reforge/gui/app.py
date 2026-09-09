"""GUI application entry point."""

from __future__ import annotations

import logging
import sys

log = logging.getLogger("reforge.gui")


def run_gui() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except Exception as exc:  # pragma: no cover
        log.error("PySide6 not available: %s", exc)
        print("PySide6 is required for the GUI. Try: reforge doctor", file=sys.stderr)
        return 2

    from reforge.gui.main_window import MainWindow
    from reforge.gui.theme import apply_theme, load_mode

    app = QApplication(sys.argv)
    app.setApplicationName("Reforge")
    apply_theme(app, load_mode())
    window = MainWindow()
    window.show()
    return app.exec()
