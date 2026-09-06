"""Plugin system.

A plugin is a Python module exposing `register(api)`. Through `api` it can add
named transforms (callables that mutate a Scapy packet in place) usable as rule
actions ({"type": "plugin", "name": ...}), and register custom protocols.

Plugins run operator-authored code with full Scapy access, for logic the
structured rules can't express. They are loaded from a directory the operator
controls (airgapped, local-only).
"""

from __future__ import annotations

import importlib.util
import logging
from pathlib import Path

log = logging.getLogger("reforge.plugins")

# Global registry so a PluginAction can resolve a transform by name.
TRANSFORMS: dict = {}


class PluginAPI:
    def __init__(self):
        self.protocols: list[dict] = []

    def register_transform(self, name: str, fn) -> None:
        TRANSFORMS[name] = fn
        log.info("plugin transform registered: %s", name)

    def register_protocol(self, spec: dict) -> None:
        from reforge.craft.custom_proto import define_protocol

        define_protocol(spec)
        self.protocols.append(spec)
        log.info("plugin protocol registered: %s", spec.get("name"))


class PluginManager:
    def __init__(self):
        self.api = PluginAPI()
        self.loaded: list[str] = []

    def load_file(self, path: str | Path) -> bool:
        path = Path(path)
        spec = importlib.util.spec_from_file_location(f"reforge_plugin_{path.stem}", path)
        if spec is None or spec.loader is None:
            return False
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception:
            log.exception("failed to import plugin %s", path)
            return False
        register = getattr(module, "register", None)
        if not callable(register):
            log.warning("plugin %s has no register(api)", path)
            return False
        try:
            register(self.api)
        except Exception:
            log.exception("plugin %s register() failed", path)
            return False
        self.loaded.append(str(path))
        return True

    def load_dir(self, directory: str | Path) -> int:
        directory = Path(directory)
        n = 0
        for py in sorted(directory.glob("*.py")):
            if py.name.startswith("_"):
                continue
            if self.load_file(py):
                n += 1
        return n


def transform(name: str):
    return TRANSFORMS.get(name)
