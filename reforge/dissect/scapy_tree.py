"""Turn a Scapy packet into the three views the GUI needs:

1. a one-line summary row  (time, src, dst, proto, length, info)
2. a layer/field tree       (for the protocol tree pane)
3. a hex dump               (for the byte pane)

These are pure functions over a Scapy packet so they are trivially unit-tested
without any live capture or root.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Row:
    index: int
    time: float
    src: str
    dst: str
    proto: str
    length: int
    info: str


@dataclass
class FieldNode:
    name: str
    value: Any
    human: str          # display representation
    layer: str          # owning layer name (for edits)


@dataclass
class LayerNode:
    name: str
    fields: list[FieldNode] = field(default_factory=list)


def _layers(pkt) -> list:
    out = []
    layer = pkt
    while layer is not None and layer.__class__.__name__ != "NoPayload":
        out.append(layer)
        layer = layer.payload if getattr(layer, "payload", None) else None
    return out


def top_protocol(pkt) -> str:
    layers = _layers(pkt)
    if not layers:
        return "?"
    # Prefer the last named layer that isn't raw padding.
    for layer in reversed(layers):
        name = layer.name
        if name and name.lower() not in ("raw", "padding"):
            return name
    return layers[-1].name


def endpoints(pkt) -> tuple[str, str]:
    """Best-effort (src, dst) across IPv6 / IPv4 / ARP / Ethernet."""
    for lname, fsrc, fdst in (
        ("IPv6", "src", "dst"),
        ("IP", "src", "dst"),
        ("ARP", "psrc", "pdst"),
        ("Ether", "src", "dst"),
    ):
        if pkt.haslayer(lname):
            layer = pkt.getlayer(lname)
            return str(layer.getfieldval(fsrc)), str(layer.getfieldval(fdst))
    return "", ""


def summarize(pkt, index: int = 0, ts: float = 0.0) -> Row:
    src, dst = endpoints(pkt)
    return Row(
        index=index,
        time=ts,
        src=src,
        dst=dst,
        proto=top_protocol(pkt),
        length=len(bytes(pkt)),
        info=pkt.summary(),
    )


def to_tree(pkt) -> list[LayerNode]:
    tree: list[LayerNode] = []
    for layer in _layers(pkt):
        node = LayerNode(name=layer.name)
        for fdesc in layer.fields_desc:
            fname = fdesc.name
            try:
                val = layer.getfieldval(fname)
                human = fdesc.i2repr(layer, val)
            except Exception:
                val, human = None, "<unreadable>"
            node.fields.append(
                FieldNode(name=fname, value=val, human=human, layer=layer.name)
            )
        tree.append(node)
    return tree


def hexdump_lines(data: bytes, width: int = 16) -> list[str]:
    """Classic offset | hex | ascii hex dump, one string per line."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = f"{hexpart:<{width * 3 - 1}}"
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart}  {asciipart}")
    return lines
