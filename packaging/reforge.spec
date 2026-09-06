# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — self-contained, no-install Reforge bundle (onedir).

Bundles the Python runtime, Scapy, PySide6/Qt, and the reforge package into a
directory that is tarred up. Copy the tarball to the airgapped host, extract,
and run ./reforge — nothing to pip/apt install.
"""

import os
import sys

from PyInstaller.utils.hooks import collect_all, collect_submodules

# The spec runs from packaging/; the reforge package lives one level up. Put the
# repo root on sys.path so collect_submodules("reforge") and Analysis can find it.
_ROOT = os.path.abspath(os.path.join(os.getcwd(), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

datas, binaries, hiddenimports = [], [], []

# Scapy loads layers/contrib dynamically — pull it all in.
_d, _b, _h = collect_all("scapy")
datas += _d; binaries += _b; hiddenimports += _h

# reforge's own modules are largely lazy-imported; include them explicitly.
hiddenimports += collect_submodules("reforge")

# Qt bindings the GUI needs (the PySide6 hook bundles the Qt libs + plugins).
hiddenimports += ["PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets"]

a = Analysis(
    ["launch.py"],
    pathex=[_ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib", "PySide6.QtQml", "PySide6.QtQuick",
              "PySide6.Qt3DCore", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
              "PySide6.QtMultimedia", "PySide6.QtCharts", "PySide6.QtDataVisualization"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="reforge",
    console=True,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="reforge")
