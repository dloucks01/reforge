"""Discovery + loading of an optional compiled fast-path data-plane provider.

The kernel-bypass backends (AF_XDP / PF_RING / DPDK) need a native + eBPF data
plane that is built and installed **per deployment**, not bundled in the tarball
(it depends on the NIC driver, kernel, and DMA setup of the target). When such a
component is installed, this module finds it and hands the perf backend a
*provider* — an object implementing the same data-plane methods as any
CaptureBackend (open / recv_burst / send_burst / close / capture_stats). When
nothing is installed, the perf backend raises a clear "install the fast-path
component" message and Reforge stays on the pure-Python backends.

A provider module exposes one entry point::

    def create(backend: str, ifaces: list[str], **opts) -> object | None

returning a provider for `backend` ("af_xdp" / "pf_ring" / "dpdk"), or None if it
does not implement that backend. See docs/FAST-PATH.md for the full contract and
how to build the component for each backend.

Discovery order:
  1. ``REFORGE_FASTPATH`` env var — an importable module name, or a path to a .py
  2. a ``reforge_fastpath`` module importable on sys.path (installed alongside)
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import os

log = logging.getLogger("reforge.fastpath")


def _load_module():
    src = os.environ.get("REFORGE_FASTPATH")
    try:
        if src:
            if src.endswith(".py") or os.sep in src:
                spec = importlib.util.spec_from_file_location("reforge_fastpath_ext", src)
                if spec is None or spec.loader is None:
                    return None
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return mod
            return importlib.import_module(src)
        return importlib.import_module("reforge_fastpath")
    except Exception:
        return None


def provider_available(backend: str) -> bool:
    """True if a fast-path component that could serve `backend` is installed.

    Cheap module-presence check (per-backend support is confirmed at create()),
    used by the backend selector so it steps up to a kernel-bypass backend only
    when its data plane is actually present."""
    mod = _load_module()
    if mod is None or not hasattr(mod, "create"):
        return False
    check = getattr(mod, "supports", None)
    if callable(check):
        try:
            return bool(check(backend))
        except Exception:
            return False
    return True


def load_provider(backend: str, ifaces, **opts):
    """Return a provider for `backend`, or None if no component serves it."""
    mod = _load_module()
    if mod is None or not hasattr(mod, "create"):
        return None
    try:
        return mod.create(backend, list(ifaces), **opts)
    except Exception:
        log.warning("fast-path provider create(%s) failed", backend, exc_info=True)
        return None
