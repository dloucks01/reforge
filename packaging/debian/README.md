# Debian packaging (Phase 8)

Offline `.deb` as an alternative to the AppImage for Kali/Debian fleets.

- `Depends:` python3, python3-scapy, python3-pyside6.qtwidgets,
  python3-netfilterqueue, ethtool, iproute2, nftables
- Ships the `reforge` console script and a systemd unit for the privileged helper.
- Built and mirrored internally; installed from a local apt repo on the airgapped side.
