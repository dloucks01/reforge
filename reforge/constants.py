"""Central identity and constants for Reforge.

Renaming the project means changing APP_NAME / APP_SLUG here and the package
directory name; nothing else hard-codes the name.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "Reforge"
APP_SLUG = "reforge"
VERSION = "0.0.1"
TAGLINE = "Inline packet interception & manipulation suite"

# XDG-style local paths (airgapped: everything stays on-host, no network).
_XDG_CONFIG = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
_XDG_DATA = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
_XDG_STATE = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))

CONFIG_DIR = _XDG_CONFIG / APP_SLUG
DATA_DIR = _XDG_DATA / APP_SLUG
STATE_DIR = _XDG_STATE / APP_SLUG
LOG_DIR = STATE_DIR / "logs"
SESSION_DIR = DATA_DIR / "sessions"

# Local IPC socket between the unprivileged GUI and the privileged helper.
HELPER_SOCKET = STATE_DIR / "privhelper.sock"


def ensure_dirs() -> None:
    """Create the local directories Reforge writes to."""
    for d in (CONFIG_DIR, DATA_DIR, STATE_DIR, LOG_DIR, SESSION_DIR):
        d.mkdir(parents=True, exist_ok=True)
