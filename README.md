# Reforge

**Inline packet interception & manipulation suite** — capture traffic in line, edit any
header field or payload byte, and forward the modified packet in place of the original;
craft packets from scratch; automate it all with a match→action rule engine.

For **authorized security testing and research only.** Built to run fully offline on an
airgapped Linux host (Kali / Debian).

See [`PLAN.md`](PLAN.md) for the full design and roadmap, and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit.

## Status

**Phase 6 — diagnostics & troubleshooting.** On top of Phases 0-5 (capture, stylized GUI,
rule engine + NFQUEUE, userspace bridge, interactive intercept, packet crafting), the tool
now has a Diagnostics tab so the operator can find and fix problems without leaving the app:
a Doctor self-check panel, a live Health dashboard (counters + rates), a packet-path Tracer
that explains why each rule did/didn't fire on a selected packet, an end-to-end pipeline
Self-test, a Logs viewer with one-click diagnostic-bundle export, and a searchable offline
Knowledge base of common inline-tool pitfalls. Next: advanced protocols & fuzzing (Phase 7).

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
