"""A concrete Dissector built from a declarative field spec.

The same JSON-friendly spec that `craft.custom_proto.define_protocol` turns into a
Scapy layer (for the tree view / field rules / builder) also drives this
Dissector, so the `dissect` registry is populated with real, editable
field layouts instead of sitting empty. Pure byte parsing — no Scapy, no root.

Field types (mirrors custom_proto): u8/u16/u32/u64 (big-endian), u16le/u32le
(little-endian), i8/i16/i32 (signed), bytes/str (size=N), rest (remaining).
"""

from __future__ import annotations

from reforge.dissect.base import DissectedLayer, Dissector, Field

_SIZES = {"u8": 1, "i8": 1, "u16": 2, "u16le": 2, "i16": 2,
          "u32": 4, "u32le": 4, "i32": 4, "u64": 8}
_INT_TYPES = set(_SIZES)


def _decode(t: str, raw: bytes):
    if t in ("bytes", "str", "rest"):
        return raw
    little = t.endswith("le")
    signed = t.startswith("i")
    return int.from_bytes(raw, "little" if little else "big", signed=signed)


def _encode(t: str, value, size: int) -> bytes:
    if t in ("bytes", "str", "rest"):
        if isinstance(value, str):
            value = value.encode("latin-1", "replace")
        value = bytes(value)
        if t == "rest":
            return value
        return value[:size].ljust(size, b"\x00")
    little = t.endswith("le")
    signed = t.startswith("i")
    return int(value).to_bytes(size, "little" if little else "big", signed=signed)


class SpecDissector(Dissector):
    """Dissect/rebuild a header from a custom_proto-style spec."""

    def __init__(self, spec: dict):
        self.name = spec["name"]
        self._fields = spec.get("fields", [])
        bind = spec.get("bind") or {}
        self.ports = {int(p) for p in bind.get("ports", [])}
        self.over = bind.get("over", "")

    def can_dissect(self, data: bytes, context: dict) -> bool:
        if not self.ports:
            return False
        return (context.get("dport") in self.ports
                or context.get("sport") in self.ports)

    def _field_size(self, fspec: dict, remaining: int) -> int:
        t = fspec.get("type", "u8")
        if t in _SIZES:
            return _SIZES[t]
        if t == "rest":
            return remaining
        return int(fspec.get("size", 0) or 0)

    def dissect(self, data: bytes) -> DissectedLayer:
        fields: list[Field] = []
        off = 0
        for fspec in self._fields:
            t = fspec.get("type", "u8")
            size = self._field_size(fspec, len(data) - off)
            raw = data[off:off + size]
            fields.append(Field(name=fspec["name"], value=_decode(t, raw),
                                offset=off, length=len(raw)))
            off += size
            if t == "rest":
                break
        return DissectedLayer(name=self.name, fields=fields, payload_offset=off)

    def build(self, layer: DissectedLayer) -> bytes:
        by_name = {f.name: f for f in layer.fields}
        out = bytearray()
        for fspec in self._fields:
            f = by_name.get(fspec["name"])
            if f is None:
                continue
            size = _SIZES.get(fspec.get("type", "u8"), f.length)
            out += _encode(fspec.get("type", "u8"), f.value, size)
        return bytes(out)
