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

## GUI shell

The interface (`reforge/gui/`) is a re-usable set of self-contained panel widgets hung on
one shell:

- **Session bar** (`main_window._build_session_bar`) — the session controls: **Mode**
  (`Capture` = observe only / `Inline` = transparent bridge in the path), interface(s),
  BPF, **Start/Stop**, one **self-labeling arm toggle** (`Pass-through ↔ ● Modifying the
  wire`, driven by `act_arm`), and an always-visible **status pill**
  (`_refresh_status_pill`) that states in plain words what the session is doing. Rarely
  touched controls (Revert, seq-fix/checksum — both automatic now, Doctor, Vault, report)
  live in the overflow menu.
- **Nav rail** (`navrail.py`) — six workspaces: Live, Recon, Craft, Attack, Automate,
  System. Panes can split side-by-side and detach into their own window (`panes.py`).
- **Live workspace** — the capture→hold→modify→send loop: the packet stream / flows over
  the **Intercept** editor (Original read-only beside an editable Modified copy; one
  **Forward** and **Drop**) with **Rules** alongside (the automated sibling of the manual
  edit). Advanced hold knobs are disclosed on demand.

The core loop's correctness aids — inline preflight, auto-armed seq/ack fix-up, live
confirmation counters, engine-choice guidance, message-relay routing — are described in
[`CAPABILITY-AUDIT.md`](CAPABILITY-AUDIT.md).
