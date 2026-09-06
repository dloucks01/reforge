# Reforge

**Inline packet interception & manipulation suite** — capture traffic in line, edit any
header field or payload byte, and forward the modified packet in place of the original;
craft packets from scratch; automate it all with a match→action rule engine.

For **authorized security testing and research only.** Built to run fully offline on an
airgapped Linux host (Kali / Debian).

See [`PLAN.md`](PLAN.md) for the full design and roadmap, and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit.

## Status

**Phase 4 — interactive intercept & edit.** On top of Phases 0-3 (foundations, live/
offline capture with a stylized dark/light GUI, the match→action rule engine with NFQUEUE,
and the userspace transparent bridge), the tool now has an interactive interception queue:
a rule can HOLD a matched packet, which parks in the queue (non-blocking, so the wire never
stalls) for the operator to inspect, edit field-by-field or as raw hex, then Forward /
Forward-modified / Drop. An Arm/pass-through state machine gates manipulation, and a
kill-switch instantly reverts to pass-through and releases all held packets. Verified
end-to-end in the netns lab: held ICMP forwarded (ping passes) vs dropped (ping fails).
Next: packet crafting & transmission (Phase 5).

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
