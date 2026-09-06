#!/usr/bin/env bash
# Replay a pcap into the lab for capture/manipulation testing.
# Usage: sudo ./replay.sh <pcap> [iface]
set -euo pipefail
PCAP="${1:?usage: replay.sh <pcap> [iface]}"
IFACE="${2:-vA_m}"

if command -v tcpreplay >/dev/null 2>&1; then
  exec tcpreplay --intf1="$IFACE" "$PCAP"
else
  echo "tcpreplay not found; falling back to scapy sendp" >&2
  exec python3 - "$PCAP" "$IFACE" <<'PY'
import sys
from scapy.all import rdpcap, sendp
pkts = rdpcap(sys.argv[1])
sendp(pkts, iface=sys.argv[2], verbose=True)
PY
fi
