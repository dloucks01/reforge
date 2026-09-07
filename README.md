# Reforge

**Inline packet interception & manipulation suite** — capture traffic in line, edit any
header field or payload byte, and forward the modified packet in place of the original;
craft packets from scratch; automate it all with a match→action rule engine.

For **authorized security testing and research only.** Built to run fully offline on an
airgapped Linux host (Kali / Debian).

See [`PLAN.md`](PLAN.md) for the full design and roadmap, and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit.

## Status

**Phase 8 — performance backends & no-install packaging (final phase).** On top of
Phases 0-7, the capture ladder now has AF_XDP/PF_RING/DPDK backends behind the same
interface with real host-capability detection (`reforge backends` reports what's usable),
a backend recommender by link speed, and a tuning module (hugepages, CPU/IRQ affinity, NIC
queues). Reforge is delivered as a **self-contained tarball** — copy it to the airgapped
target, extract, and run `./reforge`; the Python runtime, Scapy, and PySide6/Qt are bundled,
so nothing is installed. Build with `packaging/build_bundle.sh`; deploy per `docs/DEPLOYMENT.md`.

> The high-rate data planes need a compiled fast-path component per deployment; without it
> Reforge runs on AF_PACKET and reports what's missing. All eight roadmap phases are complete.

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

## Post-roadmap additions

- **Smart fuzzing** (`reforge/fuzzing/`): structure-aware / field-aware / dictionary
  / byte strategies, a seed corpus (incl. from pcap), a response monitor (reset /
  error / latency / crash), and a reproducible campaign runner with response-
  feedback guidance. GUI **Fuzzing** tab. See `docs/CAPABILITY-GAPS.md` for the
  offensive roadmap (active MITM modules, credential harvesting, HTTP attack
  toolkit, TLS interception, evasion, recon).
- **TCP seq/ack fix-up + checksum fix-up** wired into the live bridge.
