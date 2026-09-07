"""Timing covert channel — encode bits in inter-packet delays."""

from __future__ import annotations


def encode_timing(bits: str, unit: float = 0.1) -> list[float]:
    """Map a bit string to inter-packet delays: 0 -> 1 unit, 1 -> 2 units."""
    return [unit * (2 if b == "1" else 1) for b in bits]


def decode_timing(delays: list[float], unit: float = 0.1, threshold: float = 1.5) -> str:
    """Recover bits from inter-packet delays."""
    return "".join("1" if d > unit * threshold else "0" for d in delays)


def delays_from_timestamps(timestamps: list[float]) -> list[float]:
    return [b - a for a, b in zip(timestamps, timestamps[1:])]
