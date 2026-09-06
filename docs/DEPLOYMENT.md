# Reforge deployment (airgapped, no installation)

Reforge ships as a **self-contained tarball**. There is nothing to install: the
Python runtime, Scapy, PySide6/Qt, and Reforge are all inside the archive. Copy
it to the target, extract, and run.

## 1. Build the bundle (on a connected build host)

```bash
packaging/build_bundle.sh
# -> reforge-<version>-linux-<arch>.tar.gz  (+ .sha256)
```

The build host needs PyInstaller plus the same deps Reforge uses (Scapy,
PySide6). The output tarball is fully self-contained.

## 2. Transfer + verify

Copy the `.tar.gz` and its `.sha256` to the airgapped host (USB, one-way diode,
etc.), then verify integrity:

```bash
sha256sum -c reforge-<version>-linux-<arch>.tar.gz.sha256
```

## 3. Extract + run (no install)

```bash
tar xzf reforge-<version>-linux-<arch>.tar.gz
cd reforge
./reforge doctor            # environment self-check
./reforge backends          # what capture backends are usable here
sudo ./reforge gui          # GUI (live capture / bridge need root)
```

Only standard OS tools (`ip`, `ethtool`, `nft`, `tcpdump`) are expected on the
target — normal on Kali/Debian. Reforge itself needs no pip/apt.

### Privileges
Capture, bridging, and sending raw packets need `CAP_NET_RAW`/`CAP_NET_ADMIN`.
Either run as root, grant caps to the binary
(`sudo setcap cap_net_raw,cap_net_admin+eip ./reforge`), or run the privileged
helper and drive it from an unprivileged GUI.

## 4. Inline bridge

```bash
sudo ./reforge bridge --a eth0 --b eth1                       # fail-open
sudo ./reforge bridge --a eth0 --b eth1 --session job.json    # with rules
```

Interface prep (offload disable, promisc/allmulti, host-stack suppression) and
teardown are automatic and self-reverting.

## 5. Capture backends & performance

`./reforge backends` reports what the host supports. The pipeline is identical
across backends, so scaling up never changes rules/GUI:

| Backend    | Ceiling | Setup |
|------------|---------|-------|
| af_packet  | ~1-2 G  | none (default) |
| af_xdp     | 10-40 G | XDP-capable driver + fast-path component |
| pf_ring    | 10-100 G| PF_RING module + fast-path component |
| dpdk       | 100 G   | hugepages + NIC bind + fast-path component |

For 10G+ links, apply the tuning steps Reforge lists (offloads off, IRQ/CPU
affinity, NIC queues, and for DPDK hugepages + `isolcpus`). The Diagnostics tab
and `reforge.perf.tuning` provide the exact commands.

> The high-rate data planes (AF_XDP/PF_RING/DPDK zero-copy rings) require a
> compiled fast-path component delivered per deployment; without it Reforge runs
> on AF_PACKET and tells you what's missing. See PLAN.md sections 3 and 12.

## 6. Troubleshooting

Use the in-app **Diagnostics** tab: Doctor (self-checks + fixes), Tracer (why a
rule did/didn't fire), Self-test (end-to-end pipeline check), and the offline
Knowledge base. Export a **diagnostic bundle** (Logs tab) to hand off a single
JSON with environment, interface state, counters, and logs.
