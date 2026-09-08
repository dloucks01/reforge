"""perf.tuning: command builders, ethtool parse, and per-backend plans."""

from __future__ import annotations

from reforge.perf import tuning


def test_command_builders():
    assert tuning.hugepages_setup_cmd(512) == ["sysctl", "-w", "vm.nr_hugepages=512"]
    assert tuning.cpu_affinity_cmd(1234, "2,3") == ["taskset", "-pc", "2,3", "1234"]
    assert tuning.set_channels_cmd("eth0", 8) == ["ethtool", "-L", "eth0", "combined", "8"]


def test_irq_hint_mentions_iface():
    assert "eth0" in tuning.irq_affinity_hint("eth0")


def test_tuning_plan_scales_with_backend():
    base = tuning.tuning_plan("eth0", "af_packet")
    assert base and all(isinstance(s, str) for s in base)
    assert not any("hugepages" in s for s in base)          # not for af_packet

    pfr = tuning.tuning_plan("eth0", "pf_ring")
    assert any("ethtool -L eth0" in s for s in pfr)         # raises NIC queues

    dpdk = tuning.tuning_plan("eth0", "dpdk")
    assert any("hugepages" in s for s in dpdk)
    assert any("dpdk-devbind" in s for s in dpdk)
    assert len(dpdk) > len(base)                            # dpdk needs the most steps


def test_hugepages_status_is_a_dict():
    # returns {} when the sysfs path is absent; a dict of counts when present
    assert isinstance(tuning.hugepages_status(), dict)


def test_nic_channels_best_effort():
    # ethtool may be absent / iface bogus -> must not raise, returns a dict
    assert isinstance(tuning.nic_channels("definitely-not-an-iface"), dict)
