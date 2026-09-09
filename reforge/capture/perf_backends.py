"""High-speed capture backends: AF_XDP, PF_RING, DPDK.

These sit behind the same CaptureBackend interface as AF_PACKET, so the
pipeline, rules, dissection, and GUI never change when a faster backend is
selected. `is_available()` does real host-capability detection so the tool can
tell the operator (and Doctor) what's usable on this machine and pick a viable
backend for a given link speed.

The high-rate data plane itself (zero-copy rings / poll-mode drivers) is a
compiled fast-path component delivered per deployment; when it's absent, open()
raises a clear message pointing at docs/DEPLOYMENT.md rather than pretending to
run. See PLAN.md sections 3 and 12.
"""

from __future__ import annotations

import platform
import shutil
from collections.abc import Iterable
from pathlib import Path

from reforge.capture import fastpath
from reforge.capture.base import BackendCaps, CaptureBackend, Frame

_FASTPATH_MSG = ("high-rate data plane not installed; build + install the "
                 "fast-path component (see docs/FAST-PATH.md)")


def _kernel_ge(major: int, minor: int) -> bool:
    try:
        parts = platform.release().split("-", 1)[0].split(".")
        return (int(parts[0]), int(parts[1])) >= (major, minor)
    except Exception:
        return False


class _PerfBackend(CaptureBackend):
    def __init__(self, ifaces: list[str], **kw):
        if not ifaces:
            raise ValueError("performance backend needs at least one interface")
        self.ifaces = ifaces
        self._opts = kw
        self._provider = None       # the installed compiled data plane, once open()ed

    def open(self) -> None:
        # Delegate to the installed fast-path component if present; otherwise the
        # data plane isn't here — say so and point at how to build it.
        self._provider = fastpath.load_provider(self.caps.name, self.ifaces, **self._opts)
        if self._provider is None:
            raise NotImplementedError(f"{self.caps.name}: {_FASTPATH_MSG}")
        self._provider.open()

    def recv_burst(self, max_frames: int = 64, timeout: float = 0.5) -> list[Frame]:
        if self._provider is None:
            raise NotImplementedError(f"{self.caps.name}: {_FASTPATH_MSG}")
        return self._provider.recv_burst(max_frames, timeout)

    def send_burst(self, frames: Iterable[Frame]) -> int:
        if self._provider is None:
            raise NotImplementedError(f"{self.caps.name}: {_FASTPATH_MSG}")
        return self._provider.send_burst(frames)

    def capture_stats(self) -> dict:
        if self._provider is not None and hasattr(self._provider, "capture_stats"):
            return self._provider.capture_stats()
        return {"received": 0, "dropped": 0}

    def close(self) -> None:
        if self._provider is not None:
            try:
                self._provider.close()
            except Exception:
                pass
            self._provider = None


class AfXdpBackend(_PerfBackend):
    caps = BackendCaps(name="af_xdp", l2_rewrite=True, inject=True,
                       max_speed_hint="10-40G", needs_root=True, has_dataplane=False,
                       notes="Kernel-bypass-lite; needs XDP-capable driver.")

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        import socket

        if not hasattr(socket, "AF_XDP"):
            return False, "kernel/python lacks AF_XDP support"
        if not _kernel_ge(5, 4):
            return False, "kernel < 5.4 (AF_XDP immature)"
        return True, "kernel supports AF_XDP (driver-dependent; needs fast-path build)"


class PfRingBackend(_PerfBackend):
    caps = BackendCaps(name="pf_ring", l2_rewrite=True, inject=True,
                       max_speed_hint="10-100G", needs_root=True, has_dataplane=False,
                       notes="Zero-copy; needs PF_RING kernel module.")

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        if Path("/proc/net/pf_ring").exists():
            return True, "PF_RING module loaded (needs fast-path build)"
        return False, "PF_RING module not loaded (modprobe pf_ring)"


class DpdkBackend(_PerfBackend):
    caps = BackendCaps(name="dpdk", l2_rewrite=True, inject=True,
                       max_speed_hint="100G", needs_root=True, has_dataplane=False,
                       notes="Poll-mode driver; hugepages + NIC binding.")

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        huge = Path("/sys/kernel/mm/hugepages")
        has_huge = huge.exists() and any(
            (p / "nr_hugepages").exists() and int((p / "nr_hugepages").read_text() or 0) > 0
            for p in huge.glob("hugepages-*")
        )
        has_bind = bool(shutil.which("dpdk-devbind.py") or shutil.which("dpdk-devbind"))
        if has_huge and has_bind:
            return True, "hugepages + dpdk-devbind present (needs fast-path build)"
        missing = []
        if not has_huge:
            missing.append("hugepages")
        if not has_bind:
            missing.append("dpdk-devbind")
        return False, "missing: " + ", ".join(missing)
