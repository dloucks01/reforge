"""Message-level interactive interception for the HTTP relay.

Holding raw packets of a TCP stream can mean thousands of segments. At the relay
we already reassemble and frame whole HTTP messages, so this holds *messages*: a
stream becomes a handful of requests/responses the operator can actually read and
edit. Because each relay direction is a blocking pump, holding a message simply
blocks that one connection+direction until the operator resolves it (order is
inherently preserved), while other connections keep flowing.

Safeguards mirror the packet queue: a keyword/direction filter selects which
messages to hold, the shared InterceptQueue caps how many are held at once (over
the cap, messages pass through instead of blocking), and a per-message timeout
auto-forwards so a connection never hangs waiting on the operator.
"""

from __future__ import annotations

import threading

from reforge.attacks.http_relay import apply_transforms
from reforge.core.intercept import InterceptQueue


def _summary(raw: bytes) -> str:
    line = raw.split(b"\r\n", 1)[0][:120]
    try:
        return line.decode("latin-1")
    except Exception:
        return repr(line)


class MessageInterceptor:
    def __init__(self, queue: InterceptQueue, *, keyword: str = "",
                 direction: str = "both", hold_timeout: float = 30.0,
                 transforms: list | None = None):
        self.queue = queue
        self.keyword = keyword.lower().encode("latin-1", "ignore") if keyword else b""
        self.direction = direction if direction in ("both", "requests", "responses") else "both"
        self.hold_timeout = hold_timeout
        self.transforms = transforms or []

    def should_hold(self, raw: bytes, from_client: bool) -> bool:
        if self.direction == "requests" and not from_client:
            return False
        if self.direction == "responses" and from_client:
            return False
        return not (self.keyword and self.keyword not in raw.lower())

    def process(self, raw_msg: bytes, from_client: bool, flow_key: object) -> bytes | None:
        """Return bytes to forward, or None to drop the message.

        Non-held messages get the normal auto-transforms; held messages block for
        the operator (bounded by the queue cap and hold_timeout)."""
        if not self.should_hold(raw_msg, from_client):
            return apply_transforms(raw_msg, from_client, self.transforms)

        result: dict = {}
        done = threading.Event()

        def on_release(out: bytes | None) -> None:
            result["out"] = out
            done.set()

        label = "client→server" if from_client else "server→client"
        hp = self.queue.hold(label, raw_msg, on_release, flow_key=flow_key,
                             kind="message", meta={"summary": _summary(raw_msg),
                                                   "from_client": from_client})
        if hp is None:                          # queue at capacity: don't block
            return apply_transforms(raw_msg, from_client, self.transforms)

        if not done.wait(self.hold_timeout):    # operator too slow -> auto-forward
            self.queue.resolve(hp.id, "forward")
            done.wait(0.5)
        return result.get("out", raw_msg)
