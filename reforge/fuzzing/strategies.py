"""Fuzzing strategies (mutators).

Each mutator takes bytes + an RNG and returns mutated bytes, so a campaign can
mix strategies and reproduce any case from its seed.

- ByteMutator:       dumb bit/byte flips (length-preserving).
- FieldAwareMutator: pick a header field and set a type-appropriate bad value
                     (integer boundary/overflow, bad string), then rebuild so
                     lengths/checksums recompute — reaches deeper than byte flips.
- DictionaryMutator: splice a known-bad token (format string, traversal, huge,
                     injection metacharacters) into the payload.
- StructureAwareMutator: desync a length field vs. the actual payload (classic
                     parser breaker) while keeping the packet otherwise valid.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from reforge.craft.fuzz import mutate as _byte_mutate

# Known-bad values seeded into fields/payloads.
INT_BOUNDARIES = [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000,
                  0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
BAD_STRINGS = [b"%n%n%n%n%n", b"%s%s%s%s%s", b"../" * 12, b"A" * 2048, b"\x00" * 16,
               b"' OR '1'='1' -- ", b"; id;", b"\xff" * 128, b"${jndi:ldap://x}",
               b"\r\n\r\n", b"<script>alert(1)</script>"]


def _dissect(data: bytes, link: str = "ether"):
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether

    if link == "ip":
        base = IPv6 if (data and (data[0] >> 4) == 6) else IP
    else:
        base = Ether
    return base(data)


def _layers(pkt):
    out = []
    layer = pkt
    while layer is not None and layer.__class__.__name__ != "NoPayload":
        out.append(layer)
        layer = layer.payload if getattr(layer, "payload", None) is not None else None
    return out


def _clear_autofields(pkt) -> None:
    for lyr in _layers(pkt):
        for auto in ("len", "chksum", "plen", "ulen"):
            if hasattr(lyr, auto):
                try:
                    delattr(lyr, auto)
                except Exception:
                    pass


class Mutator:
    name = "mutator"

    def mutate(self, data: bytes, rng: random.Random, link: str = "ether") -> bytes:
        """Return mutated bytes (back-compat convenience over mutate_annotated)."""
        return self.mutate_annotated(data, rng, link)[0]

    def mutate_annotated(self, data: bytes, rng: random.Random,
                         link: str = "ether") -> tuple[bytes, dict]:
        """Return (mutated bytes, metadata). Metadata may carry {"field": "Layer.name"}
        so a campaign can track per-field coverage."""
        raise NotImplementedError


class ByteMutator(Mutator):
    name = "byte"

    def __init__(self, mutations: int = 4):
        self.mutations = mutations

    def mutate_annotated(self, data, rng, link="ether"):
        # reproducible: derive a sub-seed from the campaign rng
        return _byte_mutate(data, self.mutations, seed=rng.randrange(2**31)), {}


class FieldAwareMutator(Mutator):
    name = "field"

    def mutate_annotated(self, data, rng, link="ether"):
        try:
            pkt = _dissect(data, link)
            layers = _layers(pkt)
            # pick a layer/field with an editable value
            candidates = []
            for layer in layers:
                for f in layer.fields_desc:
                    candidates.append((layer, f.name))
            if not candidates:
                return data, {}
            layer, fname = rng.choice(candidates)
            cur = layer.getfieldval(fname)
            if isinstance(cur, int):
                setattr(layer, fname, rng.choice(INT_BOUNDARIES))
            else:
                setattr(layer, fname, rng.choice(BAD_STRINGS))
            _clear_autofields(pkt)              # recompute lengths/checksums
            return bytes(pkt), {"field": f"{layer.__class__.__name__}.{fname}"}
        except Exception:
            return _byte_mutate(data, 2, seed=rng.randrange(2**31)), {}


class DictionaryMutator(Mutator):
    name = "dict"

    def mutate_annotated(self, data, rng, link="ether"):
        from scapy.packet import Raw

        token = rng.choice(BAD_STRINGS)
        try:
            pkt = _dissect(data, link)
            if pkt.haslayer(Raw):
                load = bytes(pkt[Raw].load)
                pos = rng.randrange(len(load) + 1) if load else 0
                pkt[Raw].load = load[:pos] + token + load[pos:]
                _clear_autofields(pkt)
                return bytes(pkt), {"field": "Raw.load"}
        except Exception:
            pass
        # no payload layer: append the token
        return data + token, {"field": "Raw.load"}


class StructureAwareMutator(Mutator):
    name = "struct"

    def mutate_annotated(self, data, rng, link="ether"):
        try:
            pkt = _dissect(data, link)
            # find a length-like field and set it wrong WITHOUT recomputing (desync)
            for layer in _layers(pkt):
                for f in layer.fields_desc:
                    if "len" in f.name.lower() and isinstance(layer.getfieldval(f.name), int):
                        setattr(layer, f.name, rng.choice([0, 1, 0xFFFF, 0xFFFFFFFF]))
                        # do NOT clear it — keep the length lie
                        return bytes(pkt), {"field": f"{layer.__class__.__name__}.{f.name}"}
        except Exception:
            pass
        return _byte_mutate(data, 1, seed=rng.randrange(2**31)), {}


DEFAULT_STRATEGIES = [ByteMutator(), FieldAwareMutator(), DictionaryMutator(),
                      StructureAwareMutator()]


@dataclass
class FuzzCase:
    data: bytes
    seed: int
    strategy: str
    base: bytes = b""     # the corpus input this case was mutated from
