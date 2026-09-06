"""Frozen-bundle entry point (PyInstaller).

Runs the Reforge CLI (default subcommand launches the GUI).
"""

import sys

from reforge.cli import main

if __name__ == "__main__":
    sys.exit(main())
