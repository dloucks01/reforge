"""Performance tuning helpers: hugepages, CPU/IRQ affinity, NIC queues.

Command builders (so nothing runs without the operator/helper applying it) plus
light detection, used by the Diagnostics tab and the deployment docs to get the
high-speed backends to line rate.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


# ---- hugepages (DPDK) ------------------------------------------------------
def hugepages_status() -> dict:
    out: dict[str, int] = {}
    base = Path("/sys/kernel/mm/hugepages")
    if not base.exists():
        return out
    for p in sorted(base.glob("hugepages-*")):
        try:
            out[p.name] = int((p / "nr_hugepages").read_text().strip() or 0)
        except Exception:
            out[p.name] = -1
    return out


def hugepages_setup_cmd(nr_pages: int = 1024) -> list[str]:
    return ["sysctl", "-w", f"vm.nr_hugepages={nr_pages}"]


# ---- CPU / IRQ affinity ----------------------------------------------------
def cpu_affinity_cmd(pid: int, cpus: str) -> list[str]:
    """Pin a process to a CPU list, e.g. cpus='2,3'."""
    return ["taskset", "-pc", cpus, str(pid)]


def irq_affinity_hint(iface: str) -> str:
    return (f"Spread {iface} IRQs across the cores handling capture: see "
            f"/proc/interrupts and write CPU masks to /proc/irq/<n>/smp_affinity.")


# ---- NIC queues (RSS) ------------------------------------------------------
def nic_channels(iface: str) -> dict:
    """Best-effort ethtool -l parse: current/combined queue counts."""
    try:
        r = subprocess.run(["ethtool", "-l", iface], capture_output=True, text=True,
                           timeout=5, check=False)
    except Exception:
        return {}
    out: dict[str, str] = {}
    for line in r.stdout.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip().lower()] = v.strip()
    return out


def set_channels_cmd(iface: str, combined: int) -> list[str]:
    return ["ethtool", "-L", iface, "combined", str(combined)]


# ---- recommendations -------------------------------------------------------
def tuning_plan(iface: str, backend: str) -> list[str]:
    """Human-readable tuning steps for a backend/interface."""
    plan = [f"Disable NIC offloads on {iface} (Reforge does this in bridge prep).",
            irq_affinity_hint(iface),
            f"Pin the capture/forward threads to isolated cores (taskset -pc).",]
    if backend in ("pf_ring", "dpdk"):
        plan.append(f"Raise NIC queues: ethtool -L {iface} combined <ncores>.")
    if backend == "dpdk":
        plan += [
            "Reserve hugepages: sysctl -w vm.nr_hugepages=1024.",
            "Bind the NIC to vfio-pci with dpdk-devbind.py (leaves kernel control).",
            "Isolate cores with isolcpus= on the kernel cmdline for the poll loop.",
        ]
    return plan
