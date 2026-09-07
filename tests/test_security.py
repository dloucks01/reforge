"""Regression tests for security-hardening fixes."""

from __future__ import annotations

import os

import pytest

from reforge.privhelper.netconfig import (
    RevertJournal,
    fail_open_commands,
    prepare_bridge,
    prepare_capture_iface,
)


@pytest.mark.parametrize("bad", ["-K", "; rm -rf /", "eth0;reboot", "$(id)", "a" * 65, "eth 0"])
def test_iface_validation_rejects_bad_names(bad):
    with pytest.raises(ValueError):
        prepare_capture_iface(bad, RevertJournal(), apply=False)


def test_iface_validation_accepts_real_names():
    for good in ("eth0", "vlan100", "br-reforge", "ens1f0", "wlan0.5"):
        prepare_capture_iface(good, RevertJournal(), apply=False)


def test_bridge_and_failopen_validate_both_ifaces():
    with pytest.raises(ValueError):
        prepare_bridge("eth0", "-x", RevertJournal(), apply=False)
    with pytest.raises(ValueError):
        fail_open_commands("--evil", "eth1", RevertJournal(), apply=False)


def test_tls_ca_cleans_up_private_keys():
    from reforge.attacks.tls_ca import DynamicCA

    ca = DynamicCA()
    ca.cert_for("secure.test")
    tmp = str(ca._tmp)
    assert os.path.isdir(tmp)
    ca.close()
    assert not os.path.isdir(tmp)      # leaf private keys removed on close
