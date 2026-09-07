"""Operator-facing error explanations."""

from __future__ import annotations

import errno
import socket

from reforge.gui.errors import explain


def test_permission_hint():
    assert "root" in explain(PermissionError(1, "Operation not permitted"))


def test_interface_and_port_hints():
    assert "interface" in explain(OSError(errno.ENODEV, "No such device"))
    assert "port" in explain(OSError(errno.EADDRINUSE, "Address already in use"))


def test_routing_and_resolution_hints():
    assert "route" in explain(OSError(errno.EHOSTUNREACH, "No route to host"))
    assert "resolve" in explain(socket.gaierror("Name or service not known"))
    assert "segment" in explain(RuntimeError("getmacbyip failed"))


def test_unknown_error_has_no_hint():
    out = explain(ValueError("some other thing"))
    assert out == "some other thing" and " — " not in out
