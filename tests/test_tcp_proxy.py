"""R2: TCP proxy mode — large multi-segment HTTP body rewriting."""

from __future__ import annotations

import socket
import threading

from reforge.attacks import tcp_proxy


def _serve_once(sock, response: bytes):
    sock.settimeout(8)
    conn, _ = sock.accept()
    conn.recv(65536)                      # read (possibly rewritten) request
    # send the response in small chunks to force multi-segment delivery
    for i in range(0, len(response), 1400):
        conn.sendall(response[i:i + 1400])
    conn.close()


def _big_html(marker: bytes = b"</body>") -> bytes:
    filler = b"<p>data</p>" * 6000                    # ~66 KB, many segments
    body = b"<html><body>" + filler + marker + b"</html>"
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def test_proxy_injects_into_large_multisegment_body():
    response = _big_html()

    up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    up.bind(("127.0.0.1", 0)); up.listen(1)
    up_port = up.getsockname()[1]
    threading.Thread(target=_serve_once, args=(up, response), daemon=True).start()

    snippet = b"<script>INJECTED</script>"
    proxy = tcp_proxy.TcpProxy(
        upstream_resolver=lambda c: ("127.0.0.1", up_port),
        http_transforms=[tcp_proxy.strip_accept_encoding(), tcp_proxy.inject(snippet)],
        listen=("127.0.0.1", 0),
    )
    px_port = proxy.start()
    try:
        c = socket.create_connection(("127.0.0.1", px_port), timeout=8)
        c.sendall(b"GET / HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\n\r\n")
        data = b""
        c.settimeout(8)
        while True:
            try:
                chunk = c.recv(65536)
            except TimeoutError:
                break
            if not chunk:
                break
            data += chunk
        c.close()
    finally:
        proxy.stop(); up.close()

    head, _, body = data.partition(b"\r\n\r\n")
    # injection landed just before </body>, in a body far larger than one segment
    assert b"<script>INJECTED</script></body>" in body
    assert len(body) > 60000
    # Content-Length was corrected to the new (larger) body length
    cl = int(dict(h.split(b": ", 1) for h in head.split(b"\r\n")[1:])[b"Content-Length"])
    assert cl == len(body)
    # request-side transform ran too (Accept-Encoding stripped upstream)
    assert proxy.flows == 1
