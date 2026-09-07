"""Target response monitor — classify what the target did with a fuzz case.

Network targets give no code coverage, so we steer and triage by observable
behavior: no response, a reset, an error, an abnormal latency, or a sustained
loss of response (suspected crash).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Response:
    reply: bytes | None = None
    latency: float = 0.0
    error: str = ""


NORMAL = "normal"
NO_RESPONSE = "no-response"
RESET = "reset"
ERROR = "error"
SLOW = "slow"
CRASH = "crash"


class TargetMonitor:
    def __init__(self, slow_factor: float = 5.0, crash_after: int = 3):
        self.slow_factor = slow_factor
        self.crash_after = crash_after
        self._latencies: list[float] = []
        self._consecutive_no_response = 0
        self._seen_response = False

    def _baseline(self) -> float | None:
        if len(self._latencies) < 3:
            return None
        return sum(self._latencies) / len(self._latencies)

    def classify(self, resp: Response) -> str:
        if resp.reply is None:
            self._consecutive_no_response += 1
            # a sustained loss of response after the target had been answering
            if self._seen_response and self._consecutive_no_response >= self.crash_after:
                return CRASH
            return NO_RESPONSE

        self._consecutive_no_response = 0
        self._seen_response = True

        # TCP RST?
        try:
            from scapy.layers.inet import TCP
            from scapy.layers.l2 import Ether

            pkt = Ether(resp.reply)
            if pkt.haslayer(TCP) and (int(pkt[TCP].flags) & 0x04):
                return RESET
        except Exception:
            pass

        # crude application-error heuristic (HTTP 5xx / common error tokens)
        low = resp.reply[:64].lower()
        if b" 5" in low and b"http" in low:
            return ERROR

        base = self._baseline()
        self._latencies.append(resp.latency)
        if base is not None and resp.latency > base * self.slow_factor:
            return SLOW
        return NORMAL


def is_finding(classification: str) -> bool:
    return classification in (CRASH, RESET, ERROR, SLOW)
