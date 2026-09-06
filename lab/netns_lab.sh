#!/usr/bin/env bash
# Isolated test lab: two namespaces (host-a, host-b) wired through a middle
# namespace (mid) that will run Reforge inline. Lets us test capture and
# manipulation on real traffic without touching any external network.
#
#   host-a  <-->  mid (inline)  <-->  host-b
#
# Usage: sudo ./netns_lab.sh up    | down | status
set -euo pipefail

A=rf-a; B=rf-b; MID=rf-mid

up() {
  ip netns add $A;   ip netns add $B;   ip netns add $MID

  # host-a <-> mid
  ip link add vA type veth peer name vA_m
  ip link set vA netns $A;      ip link set vA_m netns $MID
  # mid <-> host-b
  ip link add vB_m type veth peer name vB
  ip link set vB_m netns $MID;  ip link set vB netns $B

  ip -n $A  addr add 10.10.0.1/24 dev vA; ip -n $A  link set vA up; ip -n $A link set lo up
  ip -n $B  addr add 10.10.0.2/24 dev vB; ip -n $B  link set vB up; ip -n $B link set lo up
  # mid interfaces stay L3-invisible (no IP) — Reforge bridges vA_m <-> vB_m
  ip -n $MID link set vA_m up; ip -n $MID link set vB_m up; ip -n $MID link set lo up

  echo "lab up. inline interfaces in netns '$MID': vA_m, vB_m"
  echo "test:  sudo ip netns exec $A ping -c1 10.10.0.2   (needs the bridge running in $MID)"
}

down() {
  for ns in $A $B $MID; do ip netns del $ns 2>/dev/null || true; done
  echo "lab down."
}

status() { ip netns list; }

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 {up|down|status}" >&2; exit 1 ;;
esac
