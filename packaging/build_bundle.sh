#!/usr/bin/env bash
# Build the self-contained, copy-and-run Reforge tarball (no installation).
#
# Produces reforge-<version>-linux-<arch>.tar.gz containing a `reforge/`
# directory with the bundled Python runtime, Scapy, PySide6/Qt, and Reforge.
# On the target: extract, then run ./reforge (no pip/apt).
#
# Usage: packaging/build_bundle.sh
set -euo pipefail
cd "$(dirname "$0")/.."          # repo root

VER=$(python3 -c "from reforge.constants import VERSION; print(VERSION)")
ARCH=$(uname -m)
NAME="reforge-${VER}-linux-${ARCH}"

echo "[*] Building bundle $NAME ..."
rm -rf build dist "$NAME.tar.gz" "$NAME.tar.gz.sha256"

# Spec references launch.py by relative path; run from packaging/ dir.
( cd packaging && pyinstaller --clean --noconfirm reforge.spec --distpath ../dist --workpath ../build )

# Ship a plain-text how-to next to the binary.
cat > dist/reforge/RUN.txt <<EOF
Reforge ${VER} — copy-and-run bundle (no installation required).

Extract this archive anywhere on the target and run the binary in this folder:

  ./reforge doctor        # environment self-check
  ./reforge backends      # list usable capture backends
  sudo ./reforge gui      # GUI (live capture / bridge need root)
  sudo ./reforge bridge --a eth0 --b eth1

System tools ip/ethtool/nft/tcpdump are expected to be present on the target OS
(standard on Kali/Debian). Nothing here needs pip or apt.
EOF

OUT="${NAME}.tar.gz"
tar -C dist -czf "$OUT" reforge
sha256sum "$OUT" > "$OUT.sha256"
SIZE=$(du -h "$OUT" | cut -f1)
echo "[*] Built $OUT ($SIZE)"
echo "[*] SHA256: $(cat "$OUT.sha256")"
echo "[*] Transfer $OUT to the target, 'tar xzf $OUT', then run reforge/reforge"
