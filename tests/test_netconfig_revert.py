"""netconfig revert-journal correctness + nft ARP family (2026-09 review §3.3, §3.4)."""

from __future__ import annotations

from reforge.privhelper.netconfig import (
    HostState,
    RevertJournal,
    prepare_capture_iface,
    suppress_host_stack,
)


class FakeState(HostState):
    """Report a fully-configured interface: offloads off, promisc/allmulti on,
    ipv6 already disabled — the opposite of the old hardcoded assumptions."""

    def offload_on(self, iface, feat):
        return False          # already off before we touched it

    def has_flag(self, iface, flag):
        return True           # promisc + allmulti already on

    def ipv6_disabled(self, iface):
        return True           # ipv6 already disabled


def _reverts(journal):
    return [" ".join(c) for c in journal.entries]


# --- §3.4: revert restores ACTUAL prior state, not fixed defaults ------------
def test_revert_restores_prior_state_when_known():
    j = RevertJournal()
    prepare_capture_iface("eth0", j, apply=False, state=FakeState())
    reverts = _reverts(j)
    # offloads were already off -> revert must leave them off (not force "on")
    assert "ethtool -K eth0 tso off" in reverts
    assert "ethtool -K eth0 tso on" not in reverts
    # promisc/allmulti were already on -> revert leaves them on
    assert "ip link set eth0 promisc on" in reverts
    assert "ip link set eth0 allmulticast on" in reverts
    # ipv6 was already disabled -> revert keeps it disabled (=1)
    assert "sysctl -w net.ipv6.conf.eth0.disable_ipv6=1" in reverts


def test_revert_falls_back_to_defaults_when_state_unknown():
    # plan mode, no reader -> historical assumption (turn things back on/off)
    j = RevertJournal()
    prepare_capture_iface("eth0", j, apply=False, state=None)
    reverts = _reverts(j)
    assert "ethtool -K eth0 tso on" in reverts
    assert "ip link set eth0 promisc off" in reverts
    assert "sysctl -w net.ipv6.conf.eth0.disable_ipv6=0" in reverts


# --- §3.3: ARP suppression lives in the arp family, not inet -----------------
def test_arp_drop_uses_arp_family():
    j = RevertJournal()
    planned = [" ".join(c) for c in suppress_host_stack("eth0", j)]
    # the RST drop is inet; the ARP drop must be in the arp family
    assert any("rule inet reforge out oifname eth0 tcp flags rst drop" in c for c in planned)
    assert any(c.startswith("nft add table arp reforge") for c in planned)
    assert any("rule arp reforge out meta oifname eth0 drop" in c for c in planned)
    # no ARP match attempted inside an inet chain (the old bug)
    assert not any("inet reforge out oifname eth0 arp drop" in c for c in planned)
    # both tables get torn down on revert
    reverts = _reverts(j)
    assert "nft delete table inet reforge" in reverts
    assert "nft delete table arp reforge" in reverts


def test_suppress_is_idempotent_via_flush():
    planned = [" ".join(c) for c in suppress_host_stack("eth0", RevertJournal())]
    # each chain is flushed before rules are added, so repeated calls don't stack
    assert any(c == "nft flush chain inet reforge out" for c in planned)
    assert any(c == "nft flush chain arp reforge out" for c in planned)
