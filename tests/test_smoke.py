"""Phase 0 smoke tests: the skeleton imports, wires together, and runs."""

from __future__ import annotations

from reforge.capture.registry import list_backends
from reforge.core.packet import Packet
from reforge.core.pipeline import Pipeline
from reforge.diagnostics.doctor import run_checks
from reforge.rules.base import Action, Disposition, Match, Rule
from reforge.rules.engine import RuleEngine


def test_version():
    import reforge

    assert reforge.__version__


def test_backends_listed():
    rows = list_backends()
    names = {n for n, _, _ in rows}
    assert "af_packet" in names


def test_doctor_runs():
    checks = run_checks()
    assert any(c.name == "scapy" for c in checks)


class _MatchAll(Match):
    def matches(self, pkt):
        return True


class _DropAction(Action):
    def apply(self, pkt, verdict):
        verdict.disposition = Disposition.DROP


def test_rule_engine_drops():
    engine = RuleEngine([Rule("drop-all", _MatchAll(), [_DropAction()])])
    pkt = Packet.from_bytes(b"\x00" * 14)
    verdict = engine.evaluate(pkt)
    assert verdict.disposition is Disposition.DROP
    assert engine.rules[0].hits == 1


def test_dry_run_does_not_apply():
    engine = RuleEngine([Rule("drop-all", _MatchAll(), [_DropAction()])], dry_run=True)
    verdict = engine.evaluate(Packet.from_bytes(b"\x00" * 14))
    assert verdict.disposition is Disposition.FORWARD
    assert any("dry-run" in n for n in verdict.notes)


def test_field_edit_and_rebuild():
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    raw = bytes(Ether() / IP(dst="10.0.0.1") / TCP(dport=80))
    pkt = Packet.from_bytes(raw)
    pkt.set_field("IP", "dst", "10.0.0.2")
    rebuilt = pkt.rebuild()
    assert Packet.from_bytes(rebuilt).get_field("IP", "dst") == "10.0.0.2"


class _CountingBackend:
    """Minimal in-memory backend to exercise the pipeline without root."""

    def __init__(self, frames):
        self._frames = frames
        self.sent = []

    def open(self): ...
    def close(self): ...
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def recv_burst(self, max_frames=64, timeout=0.5):
        batch, self._frames = self._frames[:max_frames], self._frames[max_frames:]
        return batch

    def send_burst(self, frames):
        frames = list(frames)
        self.sent.extend(frames)
        return len(frames)


def test_pipeline_forwards():
    from reforge.capture.base import Frame

    backend = _CountingBackend([Frame(data=b"\x00" * 14, ingress="a")])
    engine = RuleEngine([])
    pipe = Pipeline(backend, engine)
    pipe.run(max_iterations=1)
    assert pipe.counters.captured == 1
    assert pipe.counters.forwarded == 1
    assert len(backend.sent) == 1
