# Deploying the compiled fast-path data plane

Reforge captures and forwards on pure-Python backends out of the box —
`af_packet`, `raw_afpacket` (bytes-level + mmap ring), and `af_packet_fanout`
(multi-core `PACKET_FANOUT`, which scales RX with cores to roughly 10 Gbps with
no special build). Above that, the kernel-bypass backends — **AF_XDP**,
**PF_RING**, and **DPDK** — need a zero-copy data plane that is **native code plus
(for AF_XDP) an eBPF program**. That component is **not shipped in the tarball**:
its build depends on the target's NIC driver, kernel version, and DMA/IOMMU
setup, so it is built and installed per deployment. This doc is how.

Reforge already *detects* these backends (`reforge backends` shows them and why
they are or aren't usable). Until the component is installed, selecting one is
honest about the gap:

```
$ ./reforge backends
  af_xdp     : kernel supports AF_XDP (driver-dependent; needs fast-path build)
...
# and opening it:
NotImplementedError: af_xdp: high-rate data plane not installed; build + install
the fast-path component (see docs/FAST-PATH.md)
```

Once the component is installed, that same backend runs and the selector
(`recommend_backend`) will step up to it for high-rate links.

---

## 1. How Reforge finds the component

Reforge discovers the data plane through a small provider contract
(`reforge/capture/fastpath.py`). A provider is any Python module that exposes:

```python
def create(backend: str, ifaces: list[str], **opts) -> object | None:
    """Return a data-plane object for `backend` ("af_xdp"/"pf_ring"/"dpdk"),
    or None if this component doesn't implement that backend."""

def supports(backend: str) -> bool:      # optional, for the selector
    """True if create(backend, ...) would return a provider."""
```

The object `create()` returns implements the **same data-plane methods as any
Reforge capture backend** — so the pipeline, rules, dissection, GUI, and bridge
are unchanged when a faster plane is underneath:

```python
class Provider:
    def open(self) -> None: ...
    def recv_burst(self, max_frames: int, timeout: float) -> list[Frame]: ...
    def send_burst(self, frames) -> int: ...
    def capture_stats(self) -> dict: ...        # {"received": int, "dropped": int}
    def close(self) -> None: ...
```

`Frame` is `reforge.capture.base.Frame` (`data`, `ingress`, `egress`, `meta`).
`recv_burst` returns raw Ethernet frames as bytes — no Scapy on the hot path;
`send_burst` transmits, honoring `Frame.egress` for the bridge's peer port.

**Discovery order** (first hit wins):

1. `REFORGE_FASTPATH` — an importable module name, or a path to a `.py` shim.
2. a `reforge_fastpath` module importable on `sys.path` (installed alongside the
   Reforge tarball).

So a deployment ships its compiled extension plus a thin `reforge_fastpath.py`
(or a native module named `reforge_fastpath`) whose `create()` wraps it, and
either drops it next to the `reforge` binary or points `REFORGE_FASTPATH` at it.

A typical shim over a native extension `_xdp`:

```python
# reforge_fastpath.py
import _xdp                       # the compiled per-deployment extension
from reforge.capture.base import Frame

def supports(backend): return backend == "af_xdp"

def create(backend, ifaces, **opts):
    if backend != "af_xdp":
        return None
    return _XdpProvider(ifaces, **opts)

class _XdpProvider:
    def __init__(self, ifaces, **opts): self._x = _xdp.open(ifaces[0], **opts)
    def open(self): self._x.start()
    def recv_burst(self, n, t):
        return [Frame(data=b, ingress=self._x.iface) for b in self._x.rx(n, t)]
    def send_burst(self, frames): return self._x.tx([bytes(f.data) for f in frames])
    def capture_stats(self): return self._x.stats()
    def close(self): self._x.stop()
```

---

## 2. Build + install per backend

Reforge does not prescribe the implementation; any provider satisfying §1 works.
These are the standard toolchains and the host prep each backend needs. Do the
build on a connected host with the **matching kernel headers**, then move the
artifacts to the airgapped target (§4).

### AF_XDP (10–40 Gbps)

- **Deps:** `libbpf` + `libxdp`, `clang`/`llvm` (to compile the XDP redirect
  program), kernel ≥ 5.4 with the NIC's native XDP driver (`ixgbe`, `i40e`,
  `ice`, `mlx5`, `virtio-net`…).
- **Data plane:** an XSK (AF_XDP socket) bound to a NIC queue with a UMEM shared
  memory region, plus a small XDP/eBPF program that `bpf_redirect_map`s frames
  into the XSK map. Zero-copy mode needs driver support; copy mode is the
  fallback. Bind one XSK per RX queue and fan the queues across cores.
- **Host prep:** set the NIC's channel count to the cores you'll use
  (`ethtool -L <iface> combined <n>`) and pin the poll threads there.

### PF_RING (10–100 Gbps)

- **Deps:** the `pf_ring` kernel module loaded (`modprobe pf_ring`; confirm
  `/proc/net/pf_ring` exists) and `libpfring`. For line rate, the ZC
  (zero-copy) drivers for your NIC.
- **Data plane:** open a PF_RING (or PF_RING-ZC) handle on the interface, poll
  bursts, and transmit through the same handle. Bind the provider's `send_burst`
  to the ZC TX path.
- **Host prep:** raise NIC queues (`ethtool -L`), disable offloads (Reforge does
  this in bridge prep), pin threads.

### DPDK (100 Gbps)

- **Deps:** DPDK built for the target, hugepages reserved, and the NIC bound to a
  userspace driver (`vfio-pci` via `dpdk-devbind.py`) — which removes it from the
  kernel, so use a **dedicated** capture NIC.
- **Data plane:** an EAL-initialized poll-mode driver; `rte_eth_rx_burst` /
  `rte_eth_tx_burst` behind the provider's `recv_burst` / `send_burst`. Reforge's
  `Frame` bytes map to mbuf payloads.
- **Host prep:** `sysctl -w vm.nr_hugepages=1024`, `isolcpus=` on the kernel
  cmdline for the poll cores, IOMMU enabled. `reforge.perf.tuning` and the
  Diagnostics tab print the exact commands (`tuning_plan(iface, "dpdk")`).

---

## 3. Tuning (all kernel-bypass backends)

The same steps Reforge already recommends for high-rate links, from
`reforge.perf.tuning` / the Diagnostics tab:

- Disable NIC offloads on the capture interface (automatic in bridge prep).
- Spread the NIC's IRQs across the capture cores (`/proc/irq/<n>/smp_affinity`).
- Pin the capture/forward threads to isolated cores (`taskset -pc`).
- Raise NIC queues to match cores (`ethtool -L <iface> combined <ncores>`).
- DPDK only: hugepages + `vfio-pci` bind + `isolcpus`.

---

## 4. Airgap packaging + verification

Package the compiled artifacts (the native extension, its shared-library deps,
and any eBPF object) alongside the Reforge tarball, transfer by the same
integrity-verified path (`sha256sum -c`), and either:

- drop `reforge_fastpath.py` (+ the extension) on `sys.path` next to `reforge`, or
- `export REFORGE_FASTPATH=/opt/reforge/fastpath/reforge_fastpath.py`.

Verify on the target:

```bash
./reforge doctor            # environment + capability checks
./reforge backends          # the kernel-bypass backend should now read as usable
REFORGE_FASTPATH=/opt/reforge/fastpath/reforge_fastpath.py \
  sudo ./reforge bridge --a eth0 --b eth1
```

If a backend is *detected* but its component is absent, Reforge keeps running on
`af_packet_fanout`/`raw_afpacket` and `recommend_with_note()` says which faster
backend was seen and that it needs the fast-path build — capture never silently
degrades.

---

## 5. Contract summary (for implementers)

| Item | Requirement |
|------|-------------|
| Entry point | module with `create(backend, ifaces, **opts)`; optional `supports(backend)` |
| Backends | one or more of `"af_xdp"`, `"pf_ring"`, `"dpdk"` |
| Provider methods | `open()`, `recv_burst(max_frames, timeout)`, `send_burst(frames)`, `capture_stats()`, `close()` |
| RX | `recv_burst` returns `list[Frame]` of raw Ethernet bytes (no Scapy) |
| TX | `send_burst` transmits, honoring `Frame.egress` for the bridge peer port |
| Stats | `capture_stats()` returns `{"received": int, "dropped": int}` |
| Discovery | `REFORGE_FASTPATH` env (module or `.py`), else a `reforge_fastpath` module |

Reforge treats any object meeting this contract as a first-class capture backend;
nothing above the data plane changes.
