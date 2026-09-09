# Reforge

[![CI](https://github.com/dloucks01/reforge/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dloucks01/reforge/actions/workflows/ci.yml)

**Inline packet interception & manipulation suite.** Sit in the path of live traffic,
**catch** the packets you care about, **edit** any header field or payload byte, and
**forward** the modified packet in place of the original — or drop it. Also: craft
packets from scratch, and automate the whole thing with a match→action rule engine.

> ⚠️ **For authorized security testing and research only.** Reforge actively alters
> traffic on the wire. Use it only on networks and systems you are explicitly authorized
> to test. It is built to run fully offline on an airgapped Linux host (Kali / Debian).

See [`PLAN.md`](PLAN.md) for the full design, [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for how the pieces fit, and [`docs/CAPABILITY-AUDIT.md`](docs/CAPABILITY-AUDIT.md) for a
walk of every capability with its rough edges and the improvements shipped against them.

---

## The core workflow: capture → hold → modify → send

This is the heart of the tool, and the GUI's **Live** workspace is built around it.

1. **Pick how you sit on the wire** — the **Mode** control in the session bar:
   - **Capture** — observe only (read-only). Good for finding what you want to catch.
   - **Inline** — sit *in the path* as a transparent bridge, so held packets can be
     edited and forwarded. (Two NICs; the tool tells you if you're missing one and
     points you at the alternative.)
2. **Start.** The status pill on the session bar always states, in plain words, exactly
   what's happening: `○ Stopped` · `● Capturing · N pkts · read-only` ·
   `● Inline · forwarding, not modifying` · `● Inline · forwarding + modifying · N held`.
3. **Catch what matters.** In the **Intercept** panel, turn on **Intercept** and set a
   catch filter — type one (`TCP.dport == 80 and Raw.load contains "login"`) or pick a
   **preset** (HTTP logins, DNS queries, a subnet, …). Matching packets are held; the
   rest pass straight through.
4. **Edit.** Select a held packet. Its **Original** is shown read-only beside an editable
   **Modified** copy — edit raw bytes (Hex/ASCII) or individual fields. Checksums and
   lengths are recomputed for you.
5. **Send it.** One **Forward** button sends what's in the Modified pane (your edits if
   you made any, otherwise unchanged); **Drop** discards it. That's the loop.

Two safety details worth knowing:

- **Inline mode starts in pass-through** — traffic flows untouched until you deliberately
  flip the self-labeling toggle to **● Modifying the wire** (shown hot/red while live).
  **Revert to pass-through** (overflow menu) instantly stops modifying and releases every
  held packet.
- **Length-changing edits** keep the TCP flow in sync automatically (seq/ack fix-up
  auto-arms); when an edit genuinely can't be done per-segment (a whole-HTTP-message
  rewrite that spans segments), the tool says so and points you at the message relay.

Advanced hold controls (limit, auto-release timeout, overflow policy, held-list search)
are tucked behind **Advanced ▾** — sensible defaults hold otherwise.

---

## Quick start (dev)

```bash
./scripts/dev-setup.sh              # one-time system deps (Kali/Debian)
python3 -m reforge doctor           # check the environment
python3 -m reforge backends         # list usable capture backends
python3 -m reforge gui              # launch the GUI
pytest -q                           # run the test suite
```

Run the bridge headless (everything the GUI does is reachable from the CLI):

```bash
sudo python3 -m reforge bridge --a eth0 --b eth1                       # pass-through (safe)
sudo python3 -m reforge bridge --a eth0 --b eth1 --session engagement.reforge.json
```

`reforge doctor` includes an **inline preflight**: before you arm, it checks the FORWARD
policy, `rp_filter`, IP-forwarding, NIC offloads and queue readiness, and names the
one-line fix for anything that would silently swallow relayed traffic.

## Privileged helper

The GUI runs unprivileged; a small helper holds the network capabilities.

```bash
sudo python3 -m reforge.privhelper.helper
```

## Test lab (no external network)

A namespaced range lets you exercise (and verify) the full loop on a real kernel with no
external network:

```bash
sudo lab/netns_lab.sh up            # host-a <-> mid (inline) <-> host-b
sudo lab/replay.sh some.pcap vA_m
sudo lab/netns_lab.sh down

# opt-in live end-to-end tests (root):
sudo REFORGE_LIVE=1 python3 -m pytest tests/test_live_e2e.py -q
```

## Status

All roadmap phases (0–8) are complete: the capture ladder (AF_PACKET → AF_XDP → PF_RING →
DPDK behind one interface, with host-capability detection and tuning), the userspace
bridge and NFQUEUE inline engines, the interactive intercept editor, the match→action rule
engine, crafting, fuzzing, the active-MITM / credential / HTTP-attack modules, diagnostics,
and a self-contained no-install tarball (`packaging/build_bundle.sh`, deploy per
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)).

The five prioritized improvements from the capability audit are shipped and verified —
inline preflight, auto-armed seq/ack fix-up, live confirmation counters, engine-choice
guidance, and message-relay routing for multi-segment intent
(see [`docs/CAPABILITY-AUDIT.md`](docs/CAPABILITY-AUDIT.md)).

> The high-rate data planes (AF_XDP/PF_RING/DPDK) need a compiled fast-path component per
> deployment; without it Reforge runs on AF_PACKET and reports what's missing.

## Layout

| Path | Purpose |
|---|---|
| `reforge/capture/` | Pluggable capture/forward backends (AF_PACKET → AF_XDP → PF_RING → DPDK) + NFQUEUE |
| `reforge/core/` | Packet model, pipeline, sessions, userspace bridge, intercept queue, flow/seq fix-up |
| `reforge/rules/` | Match→action rule engine (with dry-run) |
| `reforge/attacks/` | Active MITM (ARP/NDP/DNS/LLMNR/NBNS/DHCP), HTTP toolkit, TCP/TLS message proxy |
| `reforge/dissect/` | Custom/proprietary protocol dissectors |
| `reforge/fuzzing/` | Structure/field/dictionary/byte fuzzing + response monitor + campaigns |
| `reforge/privhelper/` | Privileged helper, local IPC, idempotent netconfig + revert |
| `reforge/diagnostics/` | Doctor self-tests / health checks / inline preflight |
| `reforge/gui/` | PySide6 interface — sidebar workspaces, session bar, the Live core loop |
| `reforge/testlab/` | Namespaced veth/segment labs used by the live tests |
| `lab/` | netns + tcpreplay test harness |
| `packaging/` | Self-contained no-install tarball bundle |
