"""Message format for sensor→collector reporting (newline-delimited JSON)."""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class Message:
    sensor: str
    kind: str            # host | cred | event | scan
    data: dict

    def encode(self) -> bytes:
        return (json.dumps({"sensor": self.sensor, "kind": self.kind, "data": self.data})
                + "\n").encode()

    @classmethod
    def decode(cls, line: bytes | str) -> Message:
        d = json.loads(line)
        return cls(d["sensor"], d["kind"], d.get("data", {}))
