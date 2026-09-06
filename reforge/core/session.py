"""Session = the unit that gets saved/loaded/exported for an engagement.

Bundles interface config, mode/backend choice, rules, crafted-packet library,
and results. Serialized as JSON for airgap transfer. Also underpins crash
recovery: the last session state is persisted so a restart can restore it.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from reforge.constants import SESSION_DIR, ensure_dirs


@dataclass
class InterfaceConfig:
    ingress: str = ""
    egress: str = ""
    mode: str = "userspace_bridge"   # or nfqueue / bridged_nfqueue / arp / passive
    backend: str = "af_packet"
    fail_open: bool = True


@dataclass
class Session:
    name: str = "untitled"
    interfaces: InterfaceConfig = field(default_factory=InterfaceConfig)
    rules: list[dict] = field(default_factory=list)          # serialized rule specs
    crafted: list[dict] = field(default_factory=list)        # crafted-packet library
    notes: str = ""

    def path(self) -> Path:
        return SESSION_DIR / f"{self.name}.reforge.json"

    def save(self, path: Path | None = None) -> Path:
        ensure_dirs()
        target = path or self.path()
        target.write_text(json.dumps(asdict(self), indent=2))
        return target

    @classmethod
    def load(cls, path: Path) -> "Session":
        data = json.loads(Path(path).read_text())
        data["interfaces"] = InterfaceConfig(**data.get("interfaces", {}))
        return cls(**data)
