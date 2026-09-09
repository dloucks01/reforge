#!/usr/bin/env bash
# Reforge inline demo lab (authorized testing only).
#
# Brings up a namespaced client/server wired through two veths that Reforge's
# userspace bridge sits between, and serves a small HTTP page:
#
#     client (rf-bfc, 10.8.8.1)  <->  [ bf-c-br | bf-s-br ]  <->  server (rf-bfs, 10.8.8.2:8000)
#                                            ^ run Reforge Inline here
#
# Run it, then drive Reforge from other terminals (see the printed steps).
# Ctrl-C here tears the whole lab down.
set -euo pipefail
cd "$(dirname "$0")/.."

[ "$(id -u)" -eq 0 ] || { echo "run with sudo: sudo scripts/demo-lab.sh"; exit 1; }

DOCROOT="$(mktemp -d)"
echo "TOKEN-ORIGINAL-PAGE" > "$DOCROOT/page.html"   # rewrite ORIGINAL->INJECTED to see a rule work

echo "[*] bringing up the bridge-flow lab (rf-bfc / rf-bfs, bf-c-br / bf-s-br)..."
PYTHONPATH=. python3 -c "from reforge.testlab.netlab import up_bridge_flow_lab; up_bridge_flow_lab()"

echo "[*] starting HTTP server in rf-bfs on 10.8.8.2:8000..."
ip netns exec rf-bfs python3 -m http.server 8000 --bind 10.8.8.2 --directory "$DOCROOT" \
    >/dev/null 2>&1 &
SRV=$!

cleanup() {
    echo; echo "[*] tearing down..."
    kill "$SRV" 2>/dev/null || true
    PYTHONPATH=. python3 -c "from reforge.testlab.netlab import down_bridge_flow_lab; down_bridge_flow_lab()" || true
    rm -rf "$DOCROOT"
    echo "[*] lab down."
}
trap cleanup EXIT INT TERM

cat <<'EOF'

  ┌─ Lab is up ─────────────────────────────────────────────────────────────┐
  │ In a SECOND terminal, launch the GUI (as root, keep your display):       │
  │     sudo -E python3 -m reforge gui                                        │
  │                                                                          │
  │ In the GUI session bar:                                                   │
  │     Mode: Inline    If: bf-c-br    Peer: bf-s-br                          │
  │     (optional) Intercept ✓  filter:  Raw.load contains "GET"              │
  │     Start,  then click the toggle to  ● Modifying the wire                │
  │                                                                          │
  │ In a THIRD terminal, generate real traffic through the bridge:           │
  │     sudo ip netns exec rf-bfc curl -s http://10.8.8.2:8000/page.html      │
  │                                                                          │
  │ Held requests show in the Intercept panel — edit then Forward, or Drop.  │
  │ Ctrl-C HERE tears the lab down.                                          │
  └──────────────────────────────────────────────────────────────────────────┘

EOF
sleep infinity
