"""Target and port-range expansion for the scanner."""

from __future__ import annotations

import ipaddress


def expand_targets(spec: str, max_hosts: int = 65536) -> list[str]:
    """Expand a host / CIDR / 'a-b' range spec into a list of IP strings.

    Accepts comma-separated parts, each a single IP, a CIDR (10.0.0.0/24), or a
    last-octet range (10.0.0.1-20).
    """
    out: list[str] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            hosts = net.hosts() if net.num_addresses > 2 else net
            out += [str(ip) for ip in hosts]
        elif "-" in part and part.count(".") == 3:
            base, _, last = part.rpartition(".")
            lo, _, hi = last.partition("-")
            for n in range(int(lo), int(hi) + 1):
                out.append(f"{base}.{n}")
        else:
            out.append(str(ipaddress.ip_address(part)))
        if len(out) >= max_hosts:
            break
    # de-dupe, preserve order
    seen: set[str] = set()
    return [x for x in out if not (x in seen or seen.add(x))][:max_hosts]


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443,8000-8010' into a sorted unique port list."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)
