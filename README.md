# Reforge

**Inline packet interception & manipulation suite** — capture traffic in line, edit any
header field or payload byte, and forward the modified packet in place of the original;
craft packets from scratch; automate it all with a match→action rule engine.

For **authorized security testing and research only.** Built to run fully offline on an
airgapped Linux host (Kali / Debian).

See [`PLAN.md`](PLAN.md) for the full design and roadmap, and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit.

## Status

**Phase 3 — userspace transparent bridge.** On top of Phases 0-2 (foundations, live/
offline capture with a stylized dark/light GUI, and the match→action rule engine with
NFQUEUE), the tool now has a real dual-NIC userspace bridge: it forwards traffic inline
between two interfaces, manipulates it at L2-L7 through the rule engine, and is protected
by a watchdog with a fail-open (kernel-bridge fallback) or fail-closed policy. Interface
prep (offload disable, promiscuous/allmulti, host-stack suppression) and teardown are
idempotent and self-reverting. Verified end-to-end in the netns lab: pass-through
forwarding (including ARP/broadcast) and an inline ICMP-drop rule. Next: the interactive
intercept & edit queue (Phase 4).

Run the bridge headless:

```bash
sudo python3 -m reforge bridge --a eth0 --b eth1            # fail-open (default)
sudo python3 -m reforge bridge --a eth0 --b eth1 --session engagement.reforge.json
```

## Quick start (dev)

```bash
# one-time system deps (Kali/Debian)
./scripts/dev-setup.sh

# check the environment
python3 -m reforge doctor

# list capture backends
python3 -m reforge backends

# launch the GUI shell
python3 -m reforge gui

# run tests
pytest -q
```

## Privileged helper

The GUI runs unprivileged; a small helper holds the network capabilities.

```bash
sudo python3 -m reforge.privhelper.helper
```

## Test lab (no external network)

```bash
sudo lab/netns_lab.sh up        # host-a <-> mid (inline) <-> host-b
sudo lab/replay.sh some.pcap vA_m
sudo lab/netns_lab.sh down
```

## Layout

| Path | Purpose |
|---|---|
| `reforge/capture/` | Pluggable capture/forward backends (AF_PACKET → AF_XDP → PF_RING → DPDK) |
| `reforge/rules/` | Match→action rule engine (with dry-run) |
| `reforge/dissect/` | Custom/proprietary protocol dissectors |
| `reforge/core/` | Packet model, pipeline, sessions |
| `reforge/privhelper/` | Privileged helper, local IPC, idempotent netconfig + revert |
| `reforge/diagnostics/` | Doctor self-tests / health checks |
| `reforge/gui/` | PySide6 interface |
| `lab/` | netns + tcpreplay test harness |
| `packaging/` | AppImage + .deb skeletons |
