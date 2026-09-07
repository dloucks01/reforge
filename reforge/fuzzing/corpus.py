"""Seed corpus helpers — build fuzzing seeds from captured traffic."""

from __future__ import annotations

from pathlib import Path


def seeds_from_pcap(path: str | Path, bpf_layer: str | None = None,
                    limit: int = 500) -> list[bytes]:
    """Load packet bytes from a pcap as fuzzing seeds.

    If `bpf_layer` is given (e.g. 'TCP', 'UDP', 'DNS'), keep only packets that
    carry that layer — a focused corpus for one protocol.
    """
    from reforge.core.pcaputil import read_packets

    seeds: list[bytes] = []
    for pkt in read_packets(path):
        if bpf_layer and not pkt.haslayer(bpf_layer):
            continue
        seeds.append(bytes(pkt))
        if len(seeds) >= limit:
            break
    return seeds
