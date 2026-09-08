"""Real veth network lab for live testing (needs root).

Creates isolated virtual interfaces so the real capture/inject/bridge paths can
be exercised with actual kernel sockets, without touching a production NIC.

Two shapes:
- a single veth pair (capture on one end, inject on the other), and
- a bridge lab: two veth pairs whose inner ends (lab-a, lab-b) the userspace
  bridge sits between, and whose outer ends (lab-a-p, lab-b-p) are the client
  and server sides for injecting and observing traffic.

CLI:  sudo python -m reforge.testlab.netlab up      # create the bridge lab
      sudo python -m reforge.testlab.netlab down    # remove it

The GUI can then run Bridge mode on lab-a / lab-b.
"""

from __future__ import annotations

import os
import subprocess
from typing import Self

BRIDGE_LAB = [("lab-a", "lab-a-p"), ("lab-b", "lab-b-p")]


def _ip(*args: str) -> None:
    subprocess.run(["ip", *args], check=True, capture_output=True)


def is_root() -> bool:
    return os.geteuid() == 0


def iface_exists(name: str) -> bool:
    return subprocess.run(["ip", "link", "show", name],
                          capture_output=True, check=False).returncode == 0


def add_pair(a: str, b: str) -> None:
    """Create an up veth pair a<->b (idempotent)."""
    if not iface_exists(a):
        _ip("link", "add", a, "type", "veth", "peer", "name", b)
    _ip("link", "set", a, "up")
    _ip("link", "set", b, "up")


def del_iface(name: str) -> None:
    if iface_exists(name):
        subprocess.run(["ip", "link", "del", name], capture_output=True, check=False)


class VethPair:
    """A single up veth pair, cleaned up on exit (root required)."""

    def __init__(self, a: str = "rf-a", b: str = "rf-b"):
        self.a, self.b = a, b

    def __enter__(self) -> Self:
        add_pair(self.a, self.b)
        return self

    def __exit__(self, *exc) -> None:
        del_iface(self.a)          # deleting one end removes the pair


def up_bridge_lab() -> list[str]:
    """Create the two-pair bridge lab. Returns the interface names."""
    for a, b in BRIDGE_LAB:
        add_pair(a, b)
    return [n for pair in BRIDGE_LAB for n in pair]


def down_bridge_lab() -> None:
    for a, _b in BRIDGE_LAB:
        del_iface(a)


# ---------------------------------------------------------------------------
# Namespaced segment lab: a real L2 segment with distinct hosts, so on-path
# attacks (ARP/NDP MITM, NFQUEUE rewrite) can be proven end to end. A Linux
# bridge carries three hosts — a victim and a gateway each in their own network
# namespace, and the attacker in the default namespace (where the tool/tests
# run). Every host gets an IPv4 and an IPv6 address, so both ARP and NDP MITM
# have a genuine victim<->gateway path to intercept.
# ---------------------------------------------------------------------------
SEG_BRIDGE = "rf-br0"
SEG_GW4, SEG_GW6 = "10.9.9.254", "fd00:9::254"
SEG_ATTACKER = ("rf-atk", "rf-atk-br", "10.9.9.1/24", "fd00:9::1/64")
# (namespace, host-side veth, bridge-side veth, ipv4/cidr, ipv6/cidr)
SEG_HOSTS = [
    ("rf-victim", "rf-vic", "rf-vic-br", "10.9.9.50/24", "fd00:9::50/64"),
    ("rf-gw", "rf-gw-h", "rf-gw-br", f"{SEG_GW4}/24", f"{SEG_GW6}/64"),
]


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), check=check, capture_output=True, text=True)


def ns_exists(ns: str) -> bool:
    return subprocess.run(["ip", "netns", "pid", ns],
                          capture_output=True, check=False).returncode == 0


def netns_exec(ns: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command inside namespace `ns`."""
    return _run("ip", "netns", "exec", ns, *args, check=check)


def neigh_table(ns: str, family: str = "-4") -> str:
    """Return the neighbor (ARP/NDP) cache seen from inside `ns`."""
    return netns_exec(ns, "ip", family, "neigh", "show", check=False).stdout


def up_segment_lab() -> dict:
    """Create the bridge + attacker + victim/gateway namespaces (idempotent)."""
    if not iface_exists(SEG_BRIDGE):
        _run("ip", "link", "add", SEG_BRIDGE, "type", "bridge")
    _run("ip", "link", "set", SEG_BRIDGE, "up")

    # attacker lives in the default namespace
    atk, atk_br, atk4, atk6 = SEG_ATTACKER
    if not iface_exists(atk):
        _run("ip", "link", "add", atk, "type", "veth", "peer", "name", atk_br)
    _run("ip", "link", "set", atk_br, "master", SEG_BRIDGE)
    _run("ip", "link", "set", atk_br, "up")
    _run("ip", "link", "set", atk, "up")
    _run("sysctl", "-w", f"net.ipv6.conf.{atk}.accept_dad=0", check=False)
    _run("ip", "-4", "addr", "replace", atk4, "dev", atk)
    _run("ip", "-6", "addr", "replace", atk6, "dev", atk, check=False)

    for ns, hveth, bveth, ip4, ip6 in SEG_HOSTS:
        if not ns_exists(ns):
            _run("ip", "netns", "add", ns)
        if not iface_exists(bveth) and not _in_ns(ns, hveth):
            _run("ip", "link", "add", hveth, "type", "veth", "peer", "name", bveth)
        _run("ip", "link", "set", bveth, "master", SEG_BRIDGE, check=False)
        _run("ip", "link", "set", bveth, "up", check=False)
        _run("ip", "link", "set", hveth, "netns", ns, check=False)
        netns_exec(ns, "ip", "link", "set", "lo", "up", check=False)
        netns_exec(ns, "sysctl", "-w", f"net.ipv6.conf.{hveth}.accept_dad=0", check=False)
        netns_exec(ns, "ip", "link", "set", hveth, "up", check=False)
        netns_exec(ns, "ip", "-4", "addr", "replace", ip4, "dev", hveth, check=False)
        netns_exec(ns, "ip", "-6", "addr", "replace", ip6, "dev", hveth, check=False)

    # victim routes out via the gateway (so intercepting that path matters)
    netns_exec("rf-victim", "ip", "-4", "route", "replace", "default", "via", SEG_GW4,
               check=False)
    netns_exec("rf-victim", "ip", "-6", "route", "replace", "default", "via", SEG_GW6,
               check=False)
    # A MITM relays victim<->gateway by IP forwarding, but many hosts (Docker,
    # firewalld) ship a FORWARD policy of DROP and strict rp_filter that would
    # silently kill the relayed traffic. Permit forwarding for the lab subnet so
    # an end-to-end MITM actually delivers.
    _seg_forwarding(add=True)
    return {
        "bridge": SEG_BRIDGE, "attacker": atk,
        "attacker_ip4": atk4.split("/")[0], "attacker_ip6": atk6.split("/")[0],
        "victim_ip4": "10.9.9.50", "victim_ip6": "fd00:9::50",
        "gateway_ip4": SEG_GW4, "gateway_ip6": SEG_GW6,
    }


def _in_ns(ns: str, iface: str) -> bool:
    return netns_exec(ns, "ip", "link", "show", iface, check=False).returncode == 0


SEG_SUBNET4 = "10.9.9.0/24"


def _seg_forwarding(add: bool) -> None:
    """Allow (or remove) FORWARD-chain relaying for the lab subnet, and relax
    rp_filter / redirects that would otherwise drop same-segment MITM traffic."""
    flag = "-I" if add else "-D"
    for spec in (["-s", SEG_SUBNET4], ["-d", SEG_SUBNET4]):
        _run("iptables", flag, "FORWARD", *spec, "-j", "ACCEPT", check=False)
    if add:
        for k in ("all", "default", SEG_ATTACKER[0]):
            _run("sysctl", "-w", f"net.ipv4.conf.{k}.rp_filter=0", check=False)
            _run("sysctl", "-w", f"net.ipv4.conf.{k}.send_redirects=0", check=False)


def down_segment_lab() -> None:
    _seg_forwarding(add=False)
    for ns, _h, bveth, _4, _6 in SEG_HOSTS:
        if ns_exists(ns):
            subprocess.run(["ip", "netns", "del", ns], capture_output=True, check=False)
        del_iface(bveth)                       # bridge-side veth if it survived
    del_iface(SEG_ATTACKER[0])
    del_iface(SEG_BRIDGE)


def _resync_scapy() -> None:
    """Drop scapy's cached interface/route tables so it sees recreated veths.

    Recreating an identically-named interface changes its ifindex; scapy caches
    the old one and would then send on a stale index. Harmless if scapy isn't
    imported or has no caches."""
    try:
        from scapy.all import conf
        conf.ifaces.reload()
        conf.route.resync()
        conf.route6.resync()
        conf.netcache.flush()      # drop cached IP->MAC (same IPs, new MACs per lab)
    except Exception:
        pass


class SegmentLab:
    """The namespaced segment as a context manager (root required)."""

    def __enter__(self) -> dict:
        self.info = up_segment_lab()
        _resync_scapy()          # freshly-created veths -> drop scapy's stale iface cache
        return self.info

    def __exit__(self, *exc) -> None:
        down_segment_lab()


# ---------------------------------------------------------------------------
# Bridge-flow lab: a client and a server in separate namespaces whose only path
# to each other is through two veths (bf-c-br, bf-s-br) that a userspace bridge
# sits between. Lets a full real TCP flow traverse the tool's own L2 bridge so
# forwarding + inline manipulation can be proven end to end. Offloads are turned
# off on every veth so re-injected frames carry valid checksums (the same prep
# the production bridge does via privhelper.netconfig.prepare_bridge).
# ---------------------------------------------------------------------------
BRIDGE_FLOW = {
    "client_ns": "rf-bfc", "server_ns": "rf-bfs",
    "client_veth": "bf-c", "client_br": "bf-c-br",
    "server_veth": "bf-s", "server_br": "bf-s-br",
    "client_ip": "10.8.8.1", "server_ip": "10.8.8.2", "prefix": "/24",
    "client_ip6": "fd08::1", "server_ip6": "fd08::2", "prefix6": "/64",
    "port_a": "bf-c-br", "port_b": "bf-s-br",
}
_BF_OFFLOADS = ["tx", "rx", "gso", "tso", "gro", "sg"]


def up_bridge_flow_lab() -> dict:
    bf = BRIDGE_FLOW
    for nsn in (bf["client_ns"], bf["server_ns"]):
        if not ns_exists(nsn):
            _run("ip", "netns", "add", nsn)
    pairs = ((bf["client_veth"], bf["client_br"], bf["client_ns"], bf["client_ip"], bf["client_ip6"]),
             (bf["server_veth"], bf["server_br"], bf["server_ns"], bf["server_ip"], bf["server_ip6"]))
    for veth, bveth, nsn, ip, ip6 in pairs:
        if not iface_exists(bveth) and not _in_ns(nsn, veth):
            _run("ip", "link", "add", veth, "type", "veth", "peer", "name", bveth)
        _run("ip", "link", "set", veth, "netns", nsn, check=False)
        _run("ip", "link", "set", bveth, "up", check=False)
        for feat in _BF_OFFLOADS:               # bridge-side veth: offloads off
            _run("ethtool", "-K", bveth, feat, "off", check=False)
        netns_exec(nsn, "ip", "link", "set", "lo", "up", check=False)
        netns_exec(nsn, "sysctl", "-w", f"net.ipv6.conf.{veth}.accept_dad=0", check=False)
        netns_exec(nsn, "ip", "link", "set", veth, "up", check=False)
        netns_exec(nsn, "ip", "addr", "replace", ip + bf["prefix"], "dev", veth, check=False)
        netns_exec(nsn, "ip", "-6", "addr", "replace", ip6 + bf["prefix6"], "dev", veth, check=False)
        for feat in _BF_OFFLOADS:               # host-side veth: offloads off too
            netns_exec(nsn, "ethtool", "-K", veth, feat, "off", check=False)
    return dict(bf)


def down_bridge_flow_lab() -> None:
    bf = BRIDGE_FLOW
    for nsn in (bf["client_ns"], bf["server_ns"]):
        if ns_exists(nsn):
            subprocess.run(["ip", "netns", "del", nsn], capture_output=True, check=False)
    del_iface(bf["client_br"])
    del_iface(bf["server_br"])


class BridgeFlowLab:
    """Client/server split by a userspace bridge, as a context manager (root)."""

    def __enter__(self) -> dict:
        self.info = up_bridge_flow_lab()
        _resync_scapy()
        return self.info

    def __exit__(self, *exc) -> None:
        down_bridge_flow_lab()


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Reforge veth test lab (needs root).")
    ap.add_argument("action",
                    choices=["up", "down", "status", "seg-up", "seg-down", "seg-status"])
    args = ap.parse_args(argv)

    if args.action in ("up", "down", "seg-up", "seg-down") and not is_root():
        print("needs root: re-run with sudo")
        return 1
    if args.action == "up":
        names = up_bridge_lab()
        print("bridge lab up:", ", ".join(names))
        print("run the GUI, Bridge mode on lab-a / lab-b; inject on lab-a-p, watch lab-b-p")
    elif args.action == "down":
        down_bridge_lab()
        print("bridge lab removed")
    elif args.action == "seg-up":
        info = up_segment_lab()
        print("segment lab up:")
        for k, v in info.items():
            print(f"  {k}: {v}")
        print("attacker = default ns; MITM victim <-> gateway with the tool or "
              "tests/test_live_mitm.py")
    elif args.action == "seg-down":
        down_segment_lab()
        print("segment lab removed")
    elif args.action == "seg-status":
        print(f"{SEG_BRIDGE}: {'present' if iface_exists(SEG_BRIDGE) else 'absent'}")
        print(f"{SEG_ATTACKER[0]}: {'present' if iface_exists(SEG_ATTACKER[0]) else 'absent'}")
        for ns, *_ in SEG_HOSTS:
            print(f"{ns}: {'present' if ns_exists(ns) else 'absent'}")
    else:
        for _a, _b in BRIDGE_LAB:
            for n in (_a, _b):
                print(f"{n}: {'present' if iface_exists(n) else 'absent'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
