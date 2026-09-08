"""Synthetic traffic builders.

Each function returns a list of (timestamp, frame_bytes) with realistic Ethernet/
IP/TCP framing and correct sequence numbers, so the frames drive the real
reassembler, HTTP framer, credential extractor, and recon inventory — not just
smoke data. Timestamps are relative seconds from t0.
"""

from __future__ import annotations

import base64

TimedFrame = tuple[float, bytes]


def mac(n: int) -> str:
    return f"02:00:00:00:00:{n & 0xFF:02x}"


def _eth(src_mac: str, dst_mac: str):
    from scapy.layers.l2 import Ether

    return Ether(src=src_mac, dst=dst_mac)


def _segment(payload: bytes, mss: int) -> list[bytes]:
    return [payload[i:i + mss] for i in range(0, len(payload), mss)] or [b""]


def _l3(ipv6: bool):
    """Return an (IPClass, kwargs-builder) for IPv4 or IPv6 L3 headers."""
    if ipv6:
        from scapy.layers.inet6 import IPv6
        return lambda src, dst: IPv6(src=src, dst=dst)
    from scapy.layers.inet import IP
    return lambda src, dst: IP(src=src, dst=dst)


def tcp_flow(client_ip: str, server_ip: str, dport: int,
             client_data: bytes = b"", server_data: bytes = b"",
             *, sport: int = 40000, t0: float = 0.0, mss: int = 1400,
             cmac: int = 0x01, smac: int = 0x02, ipv6: bool = False) -> list[TimedFrame]:
    """A full bidirectional TCP flow: handshake, data both ways, teardown.

    Sequence/ack numbers are consistent so the reassembler reconstructs both
    directions exactly. Set `ipv6=True` for an IPv6 flow (same L4 semantics)."""
    from scapy.layers.inet import TCP

    IP = _l3(ipv6)
    ce, se = _eth(mac(cmac), mac(smac)), _eth(mac(smac), mac(cmac))
    isn_c, isn_s = 1000, 5000
    t = t0
    out: list[TimedFrame] = []

    def push(eth, ip, tcp, data=b""):
        nonlocal t
        out.append((t, bytes(eth / ip / tcp / data if data else eth / ip / tcp)))
        t += 0.001

    # 3-way handshake
    push(ce, IP(src=client_ip, dst=server_ip), TCP(sport=sport, dport=dport, flags="S", seq=isn_c))
    push(se, IP(src=server_ip, dst=client_ip),
         TCP(sport=dport, dport=sport, flags="SA", seq=isn_s, ack=isn_c + 1))
    push(ce, IP(src=client_ip, dst=server_ip),
         TCP(sport=sport, dport=dport, flags="A", seq=isn_c + 1, ack=isn_s + 1))

    # client -> server data (segmented)
    seq = isn_c + 1
    for seg in _segment(client_data, mss) if client_data else []:
        push(ce, IP(src=client_ip, dst=server_ip),
             TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=isn_s + 1), seg)
        seq += len(seg)
    cend = seq

    # server -> client data (segmented)
    sseq = isn_s + 1
    for seg in _segment(server_data, mss) if server_data else []:
        push(se, IP(src=server_ip, dst=client_ip),
             TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cend), seg)
        sseq += len(seg)

    # teardown
    push(ce, IP(src=client_ip, dst=server_ip),
         TCP(sport=sport, dport=dport, flags="FA", seq=cend, ack=sseq))
    push(se, IP(src=server_ip, dst=client_ip),
         TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cend + 1))
    return out


def http_login(client_ip: str = "10.0.0.50", server_ip: str = "10.0.0.10",
               user: str = "admin", password: str = "s3cr3t",
               t0: float = 0.0) -> list[TimedFrame]:
    """An HTTP POST login carrying both Basic auth and form credentials."""
    tok = base64.b64encode(f"{user}:{password}".encode()).decode()
    body = f"username={user}&password={password}".encode()
    req = (f"POST /login HTTP/1.1\r\nHost: {server_ip}\r\n"
           f"Authorization: Basic {tok}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\n\r\n").encode() + body
    resp = (b"HTTP/1.1 302 Found\r\nLocation: /home\r\n"
            b"Set-Cookie: session=abc123; Secure; HttpOnly\r\nContent-Length: 0\r\n\r\n")
    return tcp_flow(client_ip, server_ip, 80, req, resp, sport=44001, t0=t0)


def http_large_response(client_ip: str = "10.0.0.51", server_ip: str = "10.0.0.10",
                        body_size: int = 8000, t0: float = 0.0) -> list[TimedFrame]:
    """A GET whose large response body spans many TCP segments (reassembly)."""
    body = b"A" * body_size
    req = (f"GET /big HTTP/1.1\r\nHost: {server_ip}\r\n\r\n").encode()
    resp = (f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
    return tcp_flow(client_ip, server_ip, 80, req, resp, sport=44002, t0=t0, mss=1400)


def ftp_login(client_ip: str = "10.0.0.52", server_ip: str = "10.0.0.20",
              user: str = "ftpuser", password: str = "ftppass",
              t0: float = 0.0) -> list[TimedFrame]:
    """An FTP USER/PASS exchange (cleartext credentials)."""
    client = f"USER {user}\r\nPASS {password}\r\n".encode()
    server = b"220 ready\r\n331 need password\r\n230 logged in\r\n"
    return tcp_flow(client_ip, server_ip, 21, client, server, sport=44003, t0=t0)


def dns_lookup(client_ip: str = "10.0.0.50", server_ip: str = "10.0.0.1",
               qname: str = "intranet.corp.local", answer_ip: str = "10.0.0.10",
               t0: float = 0.0) -> list[TimedFrame]:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, UDP

    ce, se = _eth(mac(1), mac(3)), _eth(mac(3), mac(1))
    q = ce / IP(src=client_ip, dst=server_ip) / UDP(sport=55000, dport=53) / \
        DNS(id=0x1234, rd=1, qd=DNSQR(qname=qname))
    a = se / IP(src=server_ip, dst=client_ip) / UDP(sport=53, dport=55000) / \
        DNS(id=0x1234, qr=1, aa=1, qd=DNSQR(qname=qname),
            an=DNSRR(rrname=qname, rdata=answer_ip))
    return [(t0, bytes(q)), (t0 + 0.01, bytes(a))]


def arp_who_has(sender_ip: str = "10.0.0.50", target_ip: str = "10.0.0.10",
                t0: float = 0.0) -> list[TimedFrame]:
    from scapy.layers.l2 import ARP, Ether

    who = Ether(src=mac(1), dst="ff:ff:ff:ff:ff:ff") / \
        ARP(op=1, psrc=sender_ip, pdst=target_ip, hwsrc=mac(1))
    reply = Ether(src=mac(2), dst=mac(1)) / \
        ARP(op=2, psrc=target_ip, pdst=sender_ip, hwsrc=mac(2), hwdst=mac(1))
    return [(t0, bytes(who)), (t0 + 0.005, bytes(reply))]


def http6_login(client_ip: str = "fd00::50", server_ip: str = "fd00::10",
                user: str = "v6user", password: str = "v6pass",
                t0: float = 0.0) -> list[TimedFrame]:
    """An IPv6 HTTP POST login (Basic + form creds over IPv6)."""
    tok = base64.b64encode(f"{user}:{password}".encode()).decode()
    body = f"username={user}&password={password}".encode()
    req = (f"POST /login HTTP/1.1\r\nHost: [{server_ip}]\r\n"
           f"Authorization: Basic {tok}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\n\r\n").encode() + body
    resp = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    return tcp_flow(client_ip, server_ip, 80, req, resp, sport=44010, t0=t0,
                    cmac=0x11, smac=0x12, ipv6=True)


def tls_client_hello(sni: str) -> bytes:
    """A valid TLS 1.2 ClientHello record carrying an SNI extension.

    Hand-built to be parseable by attacks.tls_sni.extract_sni and scapy, so the
    recon SNI/fingerprint path sees a real hostname."""
    import struct

    name = sni.encode()
    sni_ext_data = struct.pack("!H", 3 + len(name)) + b"\x00" + \
        struct.pack("!H", len(name)) + name
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"            # version, random, sid_len=0
            + struct.pack("!H", 2) + b"\x13\x01"            # cipher_suites (TLS_AES_128_GCM)
            + b"\x01\x00"                                   # compression: 1 method, null
            + struct.pack("!H", len(sni_ext)) + sni_ext)    # extensions
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body  # ClientHello, 24-bit len
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def https_client_hello(client_ip: str = "10.0.0.53", server_ip: str = "10.0.0.10",
                       sni: str = "secure.corp.local", t0: float = 0.0) -> list[TimedFrame]:
    """A TCP flow to :443 whose first client segment is a real TLS ClientHello."""
    return tcp_flow(client_ip, server_ip, 443, tls_client_hello(sni), b"",
                    sport=44004, t0=t0)


def tcp_flow_out_of_order(client_ip: str = "10.0.0.54", server_ip: str = "10.0.0.10",
                          t0: float = 0.0) -> list[TimedFrame]:
    """A flow whose server payload arrives reordered, with one retransmit.

    Stresses the reassembler: segment 2 precedes segment 1, and segment 1 is
    duplicated. The reconstructed body must still be 'PART1PART2PART3' exactly."""
    from scapy.layers.inet import IP, TCP

    ce, se = _eth(mac(0x21), mac(0x22)), _eth(mac(0x22), mac(0x21))
    isn_c, isn_s = 2000, 9000
    sport, dport = 44005, 80
    out: list[TimedFrame] = []
    t = t0

    def push(eth, ip, tcp, data=b""):
        nonlocal t
        out.append((t, bytes(eth / ip / tcp / data if data else eth / ip / tcp)))
        t += 0.001

    push(ce, IP(src=client_ip, dst=server_ip), TCP(sport=sport, dport=dport, flags="S", seq=isn_c))
    push(se, IP(src=server_ip, dst=client_ip),
         TCP(sport=dport, dport=sport, flags="SA", seq=isn_s, ack=isn_c + 1))
    push(ce, IP(src=client_ip, dst=server_ip),
         TCP(sport=sport, dport=dport, flags="A", seq=isn_c + 1, ack=isn_s + 1))

    segs = [b"PART1", b"PART2", b"PART3"]
    seqs = [isn_s + 1, isn_s + 1 + 5, isn_s + 1 + 10]
    order = [1, 0, 0, 2]                      # seg2, seg1, seg1-again (dup), seg3
    for idx in order:
        push(se, IP(src=server_ip, dst=client_ip),
             TCP(sport=dport, dport=sport, flags="PA", seq=seqs[idx], ack=isn_c + 1), segs[idx])
    return out


def icmp_echo(src_ip: str = "10.0.0.50", dst_ip: str = "10.0.0.1",
              t0: float = 0.0) -> list[TimedFrame]:
    """An ICMP echo request/reply pair."""
    from scapy.layers.inet import ICMP, IP

    ce, se = _eth(mac(1), mac(4)), _eth(mac(4), mac(1))
    req = ce / IP(src=src_ip, dst=dst_ip) / ICMP(type=8, id=0x2a, seq=1) / b"ping"
    rep = se / IP(src=dst_ip, dst=src_ip) / ICMP(type=0, id=0x2a, seq=1) / b"ping"
    return [(t0, bytes(req)), (t0 + 0.01, bytes(rep))]


def udp_syslog(client_ip: str = "10.0.0.55", server_ip: str = "10.0.0.30",
               t0: float = 0.0) -> list[TimedFrame]:
    """A cleartext UDP syslog datagram."""
    from scapy.layers.inet import IP, UDP

    msg = b"<134>corp-sw1: user admin logged in from 10.0.0.55"
    dg = _eth(mac(1), mac(5)) / IP(src=client_ip, dst=server_ip) / \
        UDP(sport=51000, dport=514) / msg
    return [(t0, bytes(dg))]


def mixed_scenario() -> list[TimedFrame]:
    """A realistic mix across several hosts/protocols, ordered by timestamp.

    Spans IPv4 and IPv6, TCP/UDP/ICMP/ARP, cleartext logins (HTTP/FTP), a large
    reassembled body, a reordered+retransmitted flow, and a TLS ClientHello with
    SNI — enough to drive reassembly, flows, credential harvest, recon inventory,
    and fingerprinting end to end."""
    frames: list[TimedFrame] = []
    frames += arp_who_has(t0=0.0)
    frames += dns_lookup(t0=0.1)
    frames += icmp_echo(t0=0.3)
    frames += http_login(t0=0.5)
    frames += udp_syslog(t0=0.9)
    frames += ftp_login(t0=1.2)
    frames += https_client_hello(t0=1.6)
    frames += http_large_response(t0=2.0, body_size=6000)
    frames += tcp_flow_out_of_order(t0=2.6)
    frames += http_login(client_ip="10.0.0.60", user="bob", password="hunter2", t0=3.0)
    frames += http6_login(t0=3.4)
    frames.sort(key=lambda tf: tf[0])
    return frames
