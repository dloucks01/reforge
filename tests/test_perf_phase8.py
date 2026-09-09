"""Phase 8: backend registry/detection, recommendation, tuning builders."""

from __future__ import annotations

from reforge.capture import registry
from reforge.capture.perf_backends import AfXdpBackend, DpdkBackend, PfRingBackend
from reforge.perf import tuning


def test_registry_lists_perf_backends():
    names = {n for n, _, _ in registry.list_backends()}
    assert {"af_packet", "af_xdp", "pf_ring", "dpdk"} <= names


def test_perf_backend_availability_is_a_tuple():
    for cls in (AfXdpBackend, PfRingBackend, DpdkBackend):
        ok, note = cls.is_available()
        assert isinstance(ok, bool) and isinstance(note, str) and note


def test_recommend_backend_prefers_af_packet_for_slow_links():
    assert registry.recommend_backend(1000) == "af_packet"


def test_recommend_backend_returns_available_name():
    choice = registry.recommend_backend(50000)
    available = {n for n, ok, _ in registry.list_backends() if ok}
    assert choice in available


def test_tuning_command_builders():
    assert tuning.hugepages_setup_cmd(2048) == ["sysctl", "-w", "vm.nr_hugepages=2048"]
    assert tuning.cpu_affinity_cmd(4242, "2,3") == ["taskset", "-pc", "2,3", "4242"]
    assert tuning.set_channels_cmd("eth0", 8) == ["ethtool", "-L", "eth0", "combined", "8"]


def test_tuning_plan_dpdk_mentions_hugepages():
    plan = tuning.tuning_plan("eth0", "dpdk")
    assert any("hugepages" in step.lower() for step in plan)
    assert any("offload" in step.lower() for step in plan)


def test_perf_backend_open_raises_clear_message():
    be = AfXdpBackend(["eth0"])
    try:
        be.open()
        assert False, "expected NotImplementedError"
    except NotImplementedError as exc:
        assert "FAST-PATH" in str(exc)
