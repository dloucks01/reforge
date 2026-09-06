# Reforge

**Inline packet interception & manipulation suite** — capture traffic in line, edit any
header field or payload byte, and forward the modified packet in place of the original;
craft packets from scratch; automate it all with a match→action rule engine.

For **authorized security testing and research only.** Built to run fully offline on an
airgapped Linux host (Kali / Debian).

See [`PLAN.md`](PLAN.md) for the full design and roadmap, and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit.

## Status

**Phase 2 — rule engine + NFQUEUE inline path.** On top of Phase 0 foundations and
Phase 1 live/offline capture with a stylized dark/light GUI, the tool now has a
match→action rule engine (field rewrite, payload replace, drop, delay, duplicate) with
automatic checksum/length recompute, a dry-run/shadow mode you can run over a capture
from the GUI Rules panel, and an NFQUEUE runner for real inline enforcement. Next:
the userspace transparent bridge (Phase 3).

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
