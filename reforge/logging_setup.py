"""Structured logging setup.

Logs go to the local state dir and to stderr. No network handlers, ever
(airgapped). The same log stream feeds the in-GUI log viewer and the
diagnostic-bundle export.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from reforge.constants import LOG_DIR, ensure_dirs

_CONFIGURED = False


def setup_logging(level: int = logging.INFO, logfile: Path | None = None) -> logging.Logger:
    """Configure root logging once and return the Reforge logger."""
    global _CONFIGURED
    logger = logging.getLogger("reforge")
    if _CONFIGURED:
        return logger

    ensure_dirs()
    logfile = logfile or (LOG_DIR / "reforge.log")

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream = logging.StreamHandler()
    stream.setFormatter(fmt)

    rotating = logging.handlers.RotatingFileHandler(
        logfile, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    rotating.setFormatter(fmt)

    logger.setLevel(level)
    logger.handlers.clear()
    logger.addHandler(stream)
    logger.addHandler(rotating)
    logger.propagate = False

    _CONFIGURED = True
    logger.debug("logging initialized -> %s", logfile)
    return logger
