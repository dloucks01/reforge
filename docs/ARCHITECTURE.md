# Reforge architecture

```
                         ┌─────────────────────────────────────────┐
                         │              GUI (PySide6)               │
                         │  live capture · intercept queue · builder │
                         │  rule editor · diagnostics · dashboards   │
                         └───────────────┬───────────────────────────┘
                                         │ local Unix-socket IPC (JSON)
                                         │  (GUI = unprivileged)
                         ┌───────────────▼───────────────┐
                         │      Privileged helper         │  CAP_NET_RAW /
                         │  netconfig (idempotent+revert) │  CAP_NET_ADMIN
                         │  pipeline start/stop/teardown  │
                         └───────────────┬───────────────┘
                                         │
   ┌───────────────┐   recv_burst   ┌────▼─────────┐   send_burst   ┌───────────────┐
   │ CaptureBackend │ ─────────────▶ │   Pipeline    │ ─────────────▶ │ CaptureBackend │
   │  (ingress IF)  │                │  capture ▶    │                │  (egress IF)   │
   └───────────────┘                │  rules ▶      │                └───────────────┘
                                     │  forward      │
                                     └────┬─────────┘
                                          │
                       ┌──────────────────▼───────────────────┐
                       │            RuleEngine                 │
                       │  ordered  Match → [Action...]  → Verdict│
                       │  dry-run / hit counters / drop-safe    │
                       └──────────────────┬───────────────────┘
                                          │ uses
                              ┌───────────▼───────────┐
                              │   Packet (Scapy)      │
                              │  field get/set · rebuild│
                              │  auto checksum/length   │
                              └───────────────────────┘
```

## Design commitments

- **One narrow backend interface** (`recv_burst` / `send_burst`) so AF_PACKET can be
  swapped for AF_XDP / PF_RING / DPDK without touching rules, dissection, or GUI.
- **Never break the wire.** Match/action errors are caught and logged; the packet still
  forwards. Bridge mode adds a watchdog + fail-open policy (Phase 3).
- **Privilege separation.** The GUI never runs as root; the helper holds capabilities and
  is the only component that changes host network state.
- **Idempotent, self-reverting host changes.** Every ethtool/ip/nft change records its
  undo; teardown and crash-recovery restore the host exactly.
- **Diagnostics are first-class.** The same counters and checks feed the health dashboard,
  the CLI `doctor`, and the exported diagnostic bundle.

## Data flow for one packet

1. Backend captures a `Frame` on the ingress interface.
2. Pipeline wraps it in a `Packet` (lazy Scapy dissection).
3. `RuleEngine` evaluates ordered rules → `Verdict` (forward / drop / hold, plus delay,
   injected packets, notes).
4. On forward, `Packet.rebuild()` reserializes, recomputing lengths/checksums unless a
   field is pinned.
5. Backend transmits on the egress interface. Counters update for the dashboard.

## Interception modes (selected per session)

`userspace_bridge` (primary, full L2–L7) · `nfqueue` (gateway) · `bridged_nfqueue`
(transparent, kernel quirks) · `arp` (on-path) · `passive` (read-only). See PLAN.md §2.
