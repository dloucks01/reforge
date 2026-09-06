"""Rule / match / action interfaces for the manipulation engine.

A Rule is (Match -> [Action...]). Matches decide whether a packet is in scope;
actions transform, drop, delay, duplicate, inject, or fuzz it. The verdict the
engine returns to the forward loop is a Verdict.
"""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reforge.core.packet import Packet


class Disposition(enum.Enum):
    FORWARD = "forward"          # send (possibly modified) packet
    DROP = "drop"               # do not forward
    HOLD = "hold"               # queue for interactive intercept & edit


@dataclass
class Verdict:
    disposition: Disposition = Disposition.FORWARD
    delay_s: float = 0.0                       # latency injection
    extra_sends: list["Packet"] = field(default_factory=list)  # injected/duplicated
    matched_rule: str | None = None
    notes: list[str] = field(default_factory=list)


class Match(abc.ABC):
    """Decides whether a packet is in scope for a rule."""

    @abc.abstractmethod
    def matches(self, pkt: "Packet") -> bool: ...


class Action(abc.ABC):
    """Transforms a packet and/or influences the verdict.

    Mutate `pkt` in place and/or adjust `verdict`. Return None.
    """

    @abc.abstractmethod
    def apply(self, pkt: "Packet", verdict: Verdict) -> None: ...


@dataclass
class Rule:
    name: str
    match: Match
    actions: list[Action]
    enabled: bool = True
    hits: int = 0
