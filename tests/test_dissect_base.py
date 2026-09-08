"""Custom-dissector interface: Field/DissectedLayer + the registry."""

from __future__ import annotations

import pytest

from reforge.dissect.base import (
    DissectedLayer,
    Dissector,
    Field,
    register,
    registered,
)


class _ToyDissector(Dissector):
    name = "toy"

    def can_dissect(self, data: bytes, context: dict) -> bool:
        return data[:3] == b"TOY"

    def dissect(self, data: bytes) -> DissectedLayer:
        return DissectedLayer(
            name="toy",
            fields=[Field("magic", data[:3], 0, 3, editable=False),
                    Field("body", data[3:], 3, len(data) - 3)],
            payload_offset=len(data),
        )

    def build(self, layer: DissectedLayer) -> bytes:
        return b"".join(bytes(f.value) if isinstance(f.value, (bytes, bytearray))
                        else str(f.value).encode() for f in layer.fields)


def test_field_and_layer_dataclasses():
    f = Field("x", 5, 0, 1)
    assert f.editable is True and f.offset == 0 and f.length == 1
    layer = DissectedLayer("l", [f], payload_offset=1)
    assert layer.fields[0] is f and layer.payload_offset == 1


def test_can_dissect_gates_on_bytes():
    d = _ToyDissector()
    assert d.can_dissect(b"TOYload", {}) is True
    assert d.can_dissect(b"XXXload", {}) is False


def test_dissect_then_build_roundtrips():
    d = _ToyDissector()
    layer = d.dissect(b"TOYhello")
    assert [f.name for f in layer.fields] == ["magic", "body"]
    assert not layer.fields[0].editable            # magic is read-only
    assert d.build(layer) == b"TOYhello"


def test_register_and_registered_snapshot():
    before = registered()
    register(_ToyDissector())
    reg = registered()
    assert reg["toy"].name == "toy"
    # registered() returns a copy — mutating it must not affect the registry
    reg.clear()
    assert "toy" in registered()
    assert len(registered()) >= len(before)


def test_abstract_dissector_cannot_instantiate():
    with pytest.raises(TypeError):
        Dissector()                                 # abstract methods unimplemented
