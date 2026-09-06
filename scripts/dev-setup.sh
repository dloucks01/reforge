#!/usr/bin/env bash
# Developer setup for Kali/Debian. Installs system deps and dev tooling.
# Reforge itself runs against system scapy/PySide6; this just fills gaps.
set -euo pipefail

echo "[*] Installing system dependencies (needs sudo)..."
sudo apt-get update
sudo apt-get install -y \
  python3 python3-dev build-essential \
  python3-scapy python3-pyside6.qtwidgets python3-netfilterqueue \
  libnetfilter-queue-dev libpcap-dev \
  ethtool iproute2 nftables tcpreplay

echo "[*] Installing dev tools (pytest, ruff)..."
pip install --user pytest ruff 2>/dev/null || \
  sudo apt-get install -y python3-pytest ruff || true

echo "[*] Running doctor..."
python3 -m reforge doctor || true
echo "[*] Done."
