"""Mutation fuzzing helpers + a Fuzz rule action.

Byte/bit mutations for corrupting payloads, plus a rule Action that fuzzes the
payload of matched packets inline. Deterministic when seeded, for tests and
reproducible campaigns. Scapy's field-aware fuzz() is used for crafted packets.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from reforge.rules.base import Action, Verdict


def bit_flip(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return data
    i = rng.randrange(len(data))
    return data[:i] + bytes([data[i] ^ (1 << rng.randrange(8))]) + data[i + 1:]


def byte_set(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return data
    i = rng.randrange(len(data))
    return data[:i] + bytes([rng.randrange(256)]) + data[i + 1:]


_OPS = [bit_flip, byte_set]


def mutate(data: bytes, mutations: int = 1, seed: int | None = None) -> bytes:
    """Apply `mutations` random byte/bit mutations (length-preserving)."""
    rng = random.Random(seed)
    for _ in range(max(1, mutations)):
        data = rng.choice(_OPS)(data, rng)
    return data


def fuzz_fields(pkt):
    """Scapy field-aware fuzz of a packet (randomizes fields by type)."""
    from scapy.all import fuzz

    return fuzz(pkt)


@dataclass
class Fuzz(Action):
    """Mutate the payload (Raw) of a matched packet before forwarding."""

    mutations: int = 1
    seed: int | None = None

    def apply(self, pkt, verdict: Verdict) -> None:
        from scapy.layers.inet import TCP, UDP
        from scapy.packet import Raw

        p = pkt.scapy()
        if p.haslayer(Raw):
            p[Raw].load = mutate(bytes(p[Raw].load), self.mutations, self.seed)
            pkt.modified = True
            verdict.notes.append(f"fuzz x{self.mutations}")
            return
        # No Raw layer (e.g. the payload dissected as a protocol) — fuzz the
        # bytes of the transport payload directly.
        for l4 in (TCP, UDP):
            if p.haslayer(l4):
                layer = p[l4]
                payload = bytes(layer.payload)
                if payload:
                    layer.remove_payload()
                    layer.add_payload(Raw(mutate(payload, self.mutations, self.seed)))
                    pkt.modified = True
                    verdict.notes.append(f"fuzz x{self.mutations}")
                return
