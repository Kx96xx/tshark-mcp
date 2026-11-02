"""TLS handshakes per connection, from ``-T fields`` output. No decryption.

Everything here is read from what a TLS handshake sends in clear: the
ClientHello (SNI, ALPN, offered versions and cipher suites), the ServerHello
(chosen version, suite and ALPN, or a HelloRetryRequest), alerts sent before
encryption starts, and for TLS 1.2 and older the server's certificate. The
leaf certificate is parsed from its DER bytes for subject, issuer, SAN and
validity; nothing else is taken from it and no key material is ever read.

Each connection gets an ``outcome``. After a TLS 1.3 ServerHello the rest of
the handshake is encrypted, so the outcome there comes from the record
pattern: application data from both sides means established; a client that
sends one 19-byte record (the size of an encrypted alert: 2 bytes of alert, 1
of inner content type, 16 of AEAD tag) and closes most likely rejected the
server, typically its certificate. That case is labelled as likely, not known.

QUIC carries the same ClientHello and ServerHello in its Initial packets,
which tshark decrypts with the version's public keys; those connections are
reported with ``transport: quic`` and an outcome up to the ServerHello.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .copies import CopyTracker, ZeroedIdTracker, copy_key, nonzero
from .fields import compact, iso, parse_time, split_fields_line, to_int
from .packets import record as packet_record, zeroed_tcp_header

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.protocols",
    "ip.src", "ip.dst", "ip.id", "ip.len", "ipv6.src", "ipv6.dst", "ipv6.plen",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.flags", "tcp.checksum",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
    "udp.stream", "udp.srcport", "udp.dstport", "udp.length", "udp.checksum",
    "tls.record.content_type", "tls.record.opaque_type", "tls.record.length", "tls.handshake.type",
    "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str",
    "tls.handshake.extensions.supported_version", "tls.handshake.version", "tls.handshake.ciphersuite",
    "tls.handshake.random", "tls.alert_message.level", "tls.alert_message.desc",
    "tls.handshake.certificate", "quic.cc.error_code",
]
AGGREGATOR = "|"

# TCP segments with payload are kept too: a segment tshark did not reassemble into TLS records (a gap, or a
# tap that rewrote the TCP header on its copy) still shows that a side kept sending after the ServerHello.
BASE_FILTER = ("tls || quic.cc.error_code || tcp.flags.syn == 1 || tcp.flags.fin == 1 || tcp.flags.reset == 1"
               " || tcp.len > 0")

HRR_RANDOM = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
ENCRYPTED_ALERT_LEN = 19  # TLS 1.3: alert (2) + inner content type (1) + AEAD tag (16)
# Copies with a non-zero IP ID count within this distance, as in tcp_health; with IP ID 0 the shared
# detector needs the same transport checksum within a few milliseconds (see ``copies``).
COPY_WINDOW_S = 1.0

VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x5600: "TLS_FALLBACK_SCSV",
}
ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed", 22: "record_overflow",
    30: "decompression_failure", 40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error", 51: "decrypt_error",
    60: "export_restriction", 70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 90: "user_canceled", 100: "no_renegotiation", 109: "missing_extension",
    110: "unsupported_extension", 111: "certificate_unobtainable", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 114: "bad_certificate_hash_value", 115: "unknown_psk_identity",
    116: "certificate_required", 120: "no_application_protocol", 121: "ech_required",
}


def display_filter() -> str:
    return BASE_FILTER


def _truthy(value: str) -> bool:
    return value in ("1", "True", "true")


def _nth(values: list[str], n: int) -> str:
    return values[n] if 0 <= n < len(values) else ""


def _last(values: list[str]) -> str:
    return values[-1] if values else ""


def _grease(code: int) -> bool:
    """RFC 8701 GREASE values (0x0a0a, 0x1a1a, ... 0xfafa) are placeholders, not real offers."""
    return (code & 0x0F0F) == 0x0A0A and (code >> 8) == (code & 0xFF)


def version_name(code: int | None) -> str | None:
    if code is None:
        return None
    return VERSIONS.get(code, f"0x{code:04x}")


def suite_name(code: int | None) -> str | None:
    if code is None:
        return None
    return SUITES.get(code, f"0x{code:04x}")


def alert_name(code: int | None) -> str | None:
    if code is None:
        return None
    return ALERTS.get(code, f"alert {code}")


def matches_name(sni: str | None, wanted: str) -> bool:
    if not sni:
        return False
    s = sni.lower().rstrip(".")
    return s == wanted or s.endswith("." + wanted)


# ----------------------------------------------------------------- DER (leaf certificate only)
def _tlv(buf: bytes, i: int) -> tuple[int, int, int]:
    """(tag, content start, content end) of the DER element at ``i``."""
    tag = buf[i]
    length = buf[i + 1]
    j = i + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(buf[j:j + n], "big")
        j += n
    if j + length > len(buf):
        raise ValueError("DER element runs past the end")
    return tag, j, j + length


def _children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    i = start
    while i < end:
        tag, s, e = _tlv(buf, i)
        out.append((tag, s, e))
        i = e
    return out


_OID_CN = bytes.fromhex("550403")
_OID_O = bytes.fromhex("55040a")
_OID_SAN = bytes.fromhex("551d11")


def _name(buf: bytes, start: int, end: int) -> dict[str, str]:
    out: dict[str, str] = {}
    for _, s, e in _children(buf, start, end):           # SET OF
        for _, s2, e2 in _children(buf, s, e):           # SEQUENCE {OID, value}
            parts = _children(buf, s2, e2)
            if len(parts) < 2:
                continue
            oid = buf[parts[0][1]:parts[0][2]]
            value = buf[parts[1][1]:parts[1][2]].decode("utf-8", "replace")
            if oid == _OID_CN:
                out.setdefault("cn", value)
            elif oid == _OID_O:
                out.setdefault("o", value)
    return out


def _time(buf: bytes, tag: int, start: int, end: int) -> float | None:
    text = buf[start:end].decode("ascii", "replace").rstrip("Z")
    try:
        if tag == 0x17:  # UTCTime YYMMDDHHMMSS
            year = int(text[:2])
            text = f"{1900 + year if year >= 50 else 2000 + year}{text[2:]}"
        return datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def parse_certificate(der: bytes) -> dict[str, Any] | None:
    """Subject and issuer CN/O, SAN DNS names and IP addresses, notBefore and notAfter of one certificate."""
    try:
        _, s, e = _tlv(der, 0)                            # Certificate
        _, ts, te = _tlv(der, s)                          # TBSCertificate
        items = _children(der, ts, te)
        if items and items[0][0] == 0xA0:                 # [0] version
            items = items[1:]
        # serial, signature, issuer, validity, subject, spki, then optional [1] [2] [3]
        issuer = _name(der, items[2][1], items[2][2])
        validity = _children(der, items[3][1], items[3][2])
        subject = _name(der, items[4][1], items[4][2])
        out: dict[str, Any] = {
            "subject_cn": subject.get("cn"), "subject_o": subject.get("o"),
            "issuer_cn": issuer.get("cn"), "issuer_o": issuer.get("o"),
            "not_before": _time(der, *validity[0]) if len(validity) > 0 else None,
            "not_after": _time(der, *validity[1]) if len(validity) > 1 else None,
        }
        dns_names: list[str] = []
        ips: list[str] = []
        for tag, xs, xe in items[6:]:
            if tag != 0xA3:
                continue
            for _, es, ee in _children(der, *_tlv(der, xs)[1:]):  # Extensions SEQUENCE OF Extension
                parts = _children(der, es, ee)
                if not parts or der[parts[0][1]:parts[0][2]] != _OID_SAN:
                    continue
                octets = parts[-1]
                _, ns, ne = _tlv(der, octets[1])
                for gtag, gs, ge in _children(der, ns, ne):
                    if gtag == 0x82:
                        dns_names.append(der[gs:ge].decode("ascii", "replace"))
                    elif gtag == 0x87 and ge - gs == 4:
                        ips.append(".".join(str(b) for b in der[gs:ge]))
        out["san_dns"] = dns_names
        out["san_ip"] = ips
        return out
    except (ValueError, IndexError):
        return None


def name_covered(sni: str, cert: dict[str, Any]) -> bool:
    """Whether the SNI is one of the certificate's names (SAN, or CN when there is no SAN), wildcards included."""
    names = cert.get("san_dns") or ([cert["subject_cn"]] if cert.get("subject_cn") else [])
    host = sni.lower().rstrip(".")
    for name in names:
        n = name.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]:
            return True
    return False


# ----------------------------------------------------------------- per-packet parsing
def parse(stdout: str) -> list[dict[str, Any]]:
    packets = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(FIELDS):
            continue
        raw = {k: (v.split(AGGREGATOR) if v else []) for k, v in zip(FIELDS, cols)}
        layers = [p for p in _nth(raw["frame.protocols"], 0).split(":") if p]
        if "icmp" in layers or "icmpv6" in layers:
            continue  # an ICMP error quoting a TLS segment is not part of the connection
        transport = "quic" if "quic" in layers else ("tcp" if "tcp" in layers else None)
        if transport is None:
            continue
        ip_layers = [p for p in layers if p in ("ip", "ipv6")]
        v6 = bool(ip_layers) and ip_layers[-1] == "ipv6"
        src = _last(raw["ipv6.src"]) if v6 else _last(raw["ip.src"])
        dst = _last(raw["ipv6.dst"]) if v6 else _last(raw["ip.dst"])
        if transport == "tcp":
            stream, sport, dport = _last(raw["tcp.stream"]), _last(raw["tcp.srcport"]), _last(raw["tcp.dstport"])
        else:
            stream, sport, dport = _last(raw["udp.stream"]), _last(raw["udp.srcport"]), _last(raw["udp.dstport"])
        # The shared copy detector (``copies``) on the generic record: same IP ID, length and transport
        # header. Only the IP ID that is in the key (the innermost one) says whether the window is the
        # IP-ID one or the short zero-ID one; an outer tunnel ID differs between legs and proves nothing.
        rec = packet_record(raw)
        has_id = nonzero(rec.get("id"))
        packets.append({
            "copy_key": copy_key(rec, has_id), "has_id": has_id, "zeroed": zeroed_tcp_header(rec), "rec": rec,
            "frame": to_int(_nth(raw["frame.number"], 0)), "time": parse_time(_nth(raw["frame.time_epoch"], 0)),
            "transport": transport, "stream": stream, "src": src, "dst": dst, "sport": sport, "dport": dport,
            "len": _last(raw["tcp.len"]), "seq": _last(raw["tcp.seq_raw"]),
            "syn": _truthy(_last(raw["tcp.flags.syn"])), "ack": _truthy(_last(raw["tcp.flags.ack"])),
            "fin": _truthy(_last(raw["tcp.flags.fin"])), "rst": _truthy(_last(raw["tcp.flags.reset"])),
            # TLS 1.3 encrypted records carry an opaque type instead of a content type. In every
            # flight the clear records come first, so the lengths line up as clear ones then opaque ones.
            "content_types": [to_int(v) for v in raw["tls.record.content_type"]]
            + [to_int(v) for v in raw["tls.record.opaque_type"]],
            "clear_records": len(raw["tls.record.content_type"]),
            "record_lengths": [to_int(v) for v in raw["tls.record.length"]],
            "hs_types": [to_int(v) for v in raw["tls.handshake.type"]],
            "sni": _nth(raw["tls.handshake.extensions_server_name"], 0),
            "alpn": raw["tls.handshake.extensions_alpn_str"],
            "supported_versions": [to_int(v) for v in raw["tls.handshake.extensions.supported_version"]],
            "legacy_versions": [to_int(v) for v in raw["tls.handshake.version"]],
            "suites": [to_int(v) for v in raw["tls.handshake.ciphersuite"]],
            "randoms": [v.replace(":", "").lower() for v in raw["tls.handshake.random"]],
            "alert_levels": [to_int(v) for v in raw["tls.alert_message.level"]],
            "alert_descs": [to_int(v) for v in raw["tls.alert_message.desc"]],
            "certificates": raw["tls.handshake.certificate"],
            "quic_close": [to_int(v) for v in raw["quic.cc.error_code"]],
        })
    return packets


# ----------------------------------------------------------------- per-connection state
def _new_conn(p: dict[str, Any]) -> dict[str, Any]:
    return {"transport": p["transport"], "stream": p["stream"], "first": p["time"], "frame": p["frame"],
            "client": None, "server": None, "syn": None, "hellos": [], "server_hello": None, "certificate": None,
            "chain_length": 0, "alerts": [], "app": {"client": [], "server": []}, "ccs": set(),
            "closed": {}, "last": p["time"]}


def _side(conn: dict[str, Any], p: dict[str, Any]) -> str | None:
    if conn["client"] is None:
        return None
    return "client" if (p["src"], p["sport"]) == conn["client"] else "server"


def _is_copy(tracker: CopyTracker, zeroed_ids: ZeroedIdTracker, p: dict[str, Any]) -> bool:
    """A second copy of a packet already seen (``copies``): the same IP ID, length and transport header
    within ``COPY_WINDOW_S``, or with IP ID 0 the same checksum within a few milliseconds. Two more kinds
    come from a tap that writes a decapsulated copy of each tunnelled packet: one with the TCP header zeroed
    (no flags, sequence and acknowledgement 0), and one (QUIC and other UDP) whose IP ID was set to 0
    while the original keeps its own; the original of both is in the capture too."""
    if p["zeroed"]:
        return True
    strict = p["copy_key"] is not None and tracker.check(p["copy_key"], p["has_id"], p["time"])[0]
    loose = zeroed_ids.check(p["rec"], p["time"])  # always called, so every packet is remembered
    return strict or loose


def _repeat(seen: list[dict[str, Any]], p: dict[str, Any], copy: bool) -> bool:
    """A handshake message or alert already recorded: a capture copy of it (at the same TCP sequence number,
    or either one with a tap's zeroed header; QUIC has no sequence number to compare), or a TCP
    retransmission of the same bytes at the same sequence number. A QUIC packet that is not a copy is a new
    packet (a resent Initial), so it is a new message."""
    for x in seen[-2:]:
        if copy and (x.get("seq") in (None, "", "0") or p["seq"] in ("", "0") or x["seq"] == p["seq"]):
            return True
        if not copy and p["transport"] == "tcp" and p["seq"] not in ("", "0") and x.get("seq") == p["seq"]:
            return True
    return False


def build(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    conns: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[dict[str, Any]] = []
    tracker, zeroed_ids = CopyTracker(id_window=COPY_WINDOW_S), ZeroedIdTracker()
    for p in packets:
        key = (p["transport"], p["stream"])
        conn = conns.get(key)
        if conn is None:
            conn = conns[key] = _new_conn(p)
            order.append(conn)
        # A copy still has its handshake read (a tap's copy is sometimes the one tshark could reassemble),
        # but it adds nothing to the record, byte and close accounting below.
        copy = _is_copy(tracker, zeroed_ids, p)
        if copy:
            conn["copies"] = conn.get("copies", 0) + 1
        conn["last"] = p["time"] if p["time"] is not None else conn["last"]
        if p["syn"] and not p["ack"] and conn["client"] is None:
            conn["client"], conn["server"] = (p["src"], p["sport"]), (p["dst"], p["dport"])
            conn["syn"] = p["time"]
        hs = p["hs_types"]
        if 1 in hs and not _repeat(conn["hellos"], p, copy):  # ClientHello
            if conn["client"] is None:
                conn["client"], conn["server"] = (p["src"], p["sport"]), (p["dst"], p["dport"])
            offered = [v for v in p["supported_versions"] if v is not None and not _grease(v)]
            suites = [s for s in p["suites"] if s is not None and not _grease(s)]
            conn["hellos"].append({
                "frame": p["frame"], "time": p["time"], "seq": p["seq"], "sni": p["sni"] or None,
                "alpn": [a for a in p["alpn"] if a][:8],
                "versions": offered or [v for v in p["legacy_versions"][:1] if v is not None],
                "versions_from_extension": bool(offered),
                "cipher_suites": len(suites),
                "fallback_scsv": 0x5600 in suites,
            })
        if 2 in hs and conn["client"] is None:  # no SYN and no readable ClientHello: the ServerHello names the server
            conn["client"], conn["server"] = (p["dst"], p["dport"]), (p["src"], p["sport"])
        side = _side(conn, p)
        if 2 in hs and side == "server":  # ServerHello (or HelloRetryRequest)
            idx = hs.index(2)
            random = _nth(p["randoms"], idx if len(p["randoms"]) > idx else 0)
            chosen = [v for v in p["supported_versions"] if v is not None and not _grease(v)]
            legacy = [v for v in p["legacy_versions"] if v is not None]
            sh = {
                "frame": p["frame"], "time": p["time"],
                "version": chosen[0] if chosen else (legacy[idx] if idx < len(legacy) else (legacy[0] if legacy else None)),
                "suite": next((s for s in p["suites"] if s is not None), None),
                "alpn": next((a for a in p["alpn"] if a), None),
            }
            if random == HRR_RANDOM:
                conn["hrr"] = sh
            elif conn["server_hello"] is None:
                conn["server_hello"] = sh
        if 11 in hs and side == "server" and p["certificates"] and conn["certificate"] is None:
            conn["chain_length"] = len(p["certificates"])
            try:
                conn["certificate"] = parse_certificate(bytes.fromhex(p["certificates"][0].replace(":", "")))
            except ValueError:
                conn["certificate"] = None
        for level, desc in zip(p["alert_levels"], p["alert_descs"]):
            if _repeat([a for a in conn["alerts"] if a["description"] == alert_name(desc)], p, copy):
                continue
            conn["alerts"].append({"frame": p["frame"], "time": p["time"], "seq": p["seq"], "from": side or "?",
                                   "level": "fatal" if level == 2 else "warning", "description": alert_name(desc)})
        for code in p["quic_close"]:
            if code and not copy:  # 0 is NO_ERROR, an orderly close
                name = alert_name(code - 0x100) if 0x100 <= code <= 0x1FF else f"transport error 0x{code:x}"
                conn["alerts"].append({"frame": p["frame"], "time": p["time"], "from": side or "?", "level": "fatal",
                                       "description": name, "quic_connection_close": True})
        if side is not None and not copy:
            n_alert_desc = len(p["alert_descs"])
            for ct, length in zip(p["content_types"], p["record_lengths"] + [None] * len(p["content_types"])):
                if ct == 20:
                    conn["ccs"].add(side)
                elif ct == 23 and conn["server_hello"] is not None:
                    conn["app"][side].append((p["time"], length))
                elif ct == 21 and not n_alert_desc and conn["server_hello"] is not None:
                    conn.setdefault("encrypted_alerts", Counter())[side] += 1
            if side == "server" and conn["server_hello"] is None and conn["hellos"]:
                conn["server_bytes_before_hello"] = conn.get("server_bytes_before_hello", 0) + (to_int(p["len"], 0) or 0)
            if not p["content_types"] and to_int(p["len"], 0) and conn["server_hello"] is not None:
                conn["app"][side].append((p["time"], None))  # payload tshark did not dissect as TLS
            if (p["fin"] or p["rst"]) and side not in conn["closed"]:
                conn["closed"][side] = {"how": "reset" if p["rst"] else "fin", "time": p["time"], "frame": p["frame"]}
    return order


def _outcome(conn: dict[str, Any]) -> tuple[str, str | None]:
    """(outcome, note). Outcomes: established, alert, client_rejected_likely, no_server_hello, reset_by_server,
    closed_by_server, client_gave_up, unreadable, incomplete, server_hello (QUIC: handshake reached the ServerHello)."""
    fatal = [a for a in conn["alerts"] if a["level"] == "fatal"]
    if fatal:
        a = fatal[0]
        return "alert", f"{a['from']} sent {a['description']}"
    sh = conn["server_hello"]
    closed = conn["closed"]
    first_close = min(closed.items(), key=lambda kv: kv[1]["time"] or 0) if closed else None
    if sh is None:
        if conn["transport"] == "quic":
            return "no_server_hello", None
        if conn.get("server_bytes_before_hello"):
            return "unreadable", (f"the server answered with {conn['server_bytes_before_hello']} bytes that tshark could not "
                                  "read as a ServerHello (segments missing or out of order, or a tap that rewrote the TCP header)")
        if first_close is None:
            return "no_server_hello", "the capture shows no answer to the ClientHello"
        who, how = first_close[0], first_close[1]["how"]
        if who == "server":
            return ("reset_by_server" if how == "reset" else "closed_by_server"), f"server sent {how.upper()} before a ServerHello"
        return "client_gave_up", f"client sent {how.upper()} before a ServerHello"
    if conn["transport"] == "quic":
        return "server_hello", None
    client_app, server_app = conn["app"]["client"], conn["app"]["server"]
    version = sh.get("version")
    if version == 0x0304:
        lengths = [n for _, n in client_app]
        if lengths == [ENCRYPTED_ALERT_LEN] and "client" in closed:
            return "client_rejected_likely", ("instead of its Finished the client sent one alert-sized record (19 bytes) "
                                              "and closed: most likely it rejected the server's certificate")
        if len(lengths) == 2 and lengths[1] == ENCRYPTED_ALERT_LEN and "client" in closed:
            return "established", "the client finished the handshake and closed at once without sending data (an unused connection)"
        if len(client_app) >= 2 or (client_app and any(t > client_app[0][0] for t, _ in server_app)):
            return "established", None
    else:
        if "server" in conn["ccs"] and (client_app or server_app):
            return "established", None
        enc = conn.get("encrypted_alerts") or {}
        if "server" in conn["ccs"] and enc and not (client_app or server_app):
            side = next(iter(enc))
            return "alert", f"{side} sent an encrypted alert right after the handshake"
    if first_close is not None:
        who, how = first_close[0], first_close[1]["how"]
        return "incomplete", f"{who} sent {how.upper()} during the handshake"
    return "incomplete", "the handshake did not finish in the capture"


def summarise(conns: list[dict[str, Any]], server_name: str | None = None) -> dict[str, Any]:
    rows = []
    without_hello = 0
    for conn in conns:
        if not conn["hellos"]:
            if conn["server_hello"] is None and conn["certificate"] is None and not conn["alerts"]:
                without_hello += 1
                continue
            # The ClientHello is not readable (not captured, or split over segments tshark could not put
            # together) but the server's side of the handshake is: report what is there.
            sh = conn["server_hello"]
            conn["hellos"] = [{"frame": sh["frame"] if sh else conn["frame"], "time": None, "seq": None, "sni": None,
                               "alpn": [], "versions": [], "versions_from_extension": False, "cipher_suites": None,
                               "fallback_scsv": False, "missing": True}]
        hello = conn["hellos"][0]
        if server_name and not (matches_name(hello["sni"], server_name)
                                or (not hello["sni"] and conn["certificate"]
                                    and name_covered(server_name, conn["certificate"]))):
            continue
        outcome, note = _outcome(conn)
        sh = conn["server_hello"]
        client = conn["client"] or ("", "")
        server = conn["server"] or ("", "")
        row: dict[str, Any] = {
            "transport": conn["transport"], "stream": to_int(conn["stream"]),
            "client": f"{client[0]}:{client[1]}", "server": f"{server[0]}:{server[1]}",
            "frame": hello["frame"], "time": iso(hello["time"]), "sni": hello["sni"],
            "offered": compact({"versions": [version_name(v) for v in hello["versions"]], "alpn": hello["alpn"],
                                "cipher_suites": hello["cipher_suites"],
                                "fallback_scsv": True if hello["fallback_scsv"] else None}),
            "client_hellos": len(conn["hellos"]) if len(conn["hellos"]) > 1 else None,
            "client_hello_missing": True if hello.get("missing") else None,
            "outcome": outcome, "note": note,
        }
        if conn.get("syn") is not None and hello["time"] is not None:
            row["tcp_to_hello_ms"] = round((hello["time"] - conn["syn"]) * 1000, 3)
        if conn.get("hrr"):
            row["hello_retry_request"] = True
        if sh is not None:
            row["chosen"] = compact({"version": version_name(sh["version"]), "cipher_suite": suite_name(sh["suite"]),
                                     "alpn": sh["alpn"]})
            if sh["time"] is not None and hello["time"] is not None:
                row["server_hello_ms"] = round((sh["time"] - hello["time"]) * 1000, 3)
        if conn["alerts"]:
            row["alerts"] = [compact({"from": a["from"], "level": a["level"], "description": a["description"],
                                      "frame": a["frame"], "quic": a.get("quic_connection_close")})
                             for a in conn["alerts"][:5]]
        cert = conn["certificate"]
        if cert:
            row["certificate"] = compact({
                "subject_cn": cert.get("subject_cn"), "subject_o": cert.get("subject_o"),
                "issuer_cn": cert.get("issuer_cn"), "issuer_o": cert.get("issuer_o"),
                "san": (cert.get("san_dns") or [])[:20] + (cert.get("san_ip") or [])[:5],
                "san_total": len(cert.get("san_dns") or []) + len(cert.get("san_ip") or []),
                "not_before": iso(cert.get("not_before")), "not_after": iso(cert.get("not_after")),
                "chain_length": conn["chain_length"],
            })
        if conn["closed"]:
            row["closed"] = {side: c["how"] for side, c in sorted(conn["closed"].items())}
        if conn.get("copies"):
            row["duplicate_copies"] = conn["copies"]
        row["issues"] = _conn_issues(conn, hello, cert, outcome, note)
        rows.append(compact(row))
    summary = {
        "connections": len(rows),
        "outcomes": dict(Counter(r["outcome"] for r in rows)),
        "versions": dict(Counter(r["chosen"]["version"] for r in rows if r.get("chosen", {}).get("version"))),
        "alerts": dict(Counter(f"{a['from']}: {a['description']}" for r in rows for a in r.get("alerts", []))),
        "transports": dict(Counter(r["transport"] for r in rows)),
        "streams_without_client_hello": without_hello if not server_name else None,
    }
    failing = Counter(r.get("sni") or r["server"] for r in rows if r["outcome"] not in ("established", "server_hello"))
    issues = []
    if failing:
        top = ", ".join(f"{k} ({v})" for k, v in failing.most_common(5))
        issues.append(f"{sum(failing.values())} of {len(rows)} handshakes did not complete; by server: {top}")
    for text, n in Counter(i for r in rows for i in r.get("issues", []) if not i.startswith("outcome")).most_common(10):
        issues.append(text if n == 1 else f"{text} ({n} connections)")
    return {"connections": rows, "summary": compact(summary), "issues": issues}


def _conn_issues(conn: dict[str, Any], hello: dict[str, Any], cert: dict[str, Any] | None, outcome: str,
                 note: str | None) -> list[str]:
    out = []
    target = hello["sni"] or (conn["server"][0] if conn["server"] else "?")
    if outcome == "alert" and note:
        out.append(f"{target}: {note}")
    elif outcome in ("no_server_hello", "reset_by_server", "closed_by_server", "client_gave_up",
                     "client_rejected_likely", "unreadable"):
        out.append(f"{target}: {outcome.replace('_', ' ')}")
    sh = conn["server_hello"]
    if sh is not None and sh["version"] is not None and hello["versions"] and (
            sh["version"] > max(hello["versions"])
            or (hello["versions_from_extension"] and sh["version"] not in hello["versions"])):
        out.append(f"{target}: server chose {version_name(sh['version'])}, which the client did not offer")
    if sh is not None and sh["version"] is not None and sh["version"] < 0x0303:
        out.append(f"{target}: negotiated {version_name(sh['version'])}, which is deprecated")
    if conn.get("hrr"):
        out.append(f"{target}: server asked for a second ClientHello (HelloRetryRequest)")
    if cert:
        at = hello["time"]
        if at is not None and cert.get("not_after") is not None and cert["not_after"] < at:
            out.append(f"{target}: certificate expired {iso(cert['not_after'])}, before the handshake")
        if at is not None and cert.get("not_before") is not None and cert["not_before"] > at:
            out.append(f"{target}: certificate not valid until {iso(cert['not_before'])}")
        if hello["sni"] and not name_covered(hello["sni"], cert):
            out.append(f"{target}: the certificate does not name {hello['sni']} (SAN/CN mismatch)")
    if len(conn["hellos"]) > 1 and not conn.get("hrr"):
        out.append(f"{target}: ClientHello sent {len(conn['hellos'])} times")
    return out


def is_problem(row: dict[str, Any]) -> bool:
    return row.get("outcome") not in ("established", "server_hello") or bool(row.get("issues"))
