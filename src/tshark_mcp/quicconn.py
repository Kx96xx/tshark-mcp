"""quic_connections: QUIC connections from their clear headers, and the TCP fallback after them.

QUIC encrypts everything but the long-header fields (version, connection IDs, packet type,
Retry token, Version Negotiation list) and the short-header DCID and spin bit, so the tool reads
headers only: it needs no keys and works on a capture whose Initials tshark cannot decrypt. When
tshark can decrypt an Initial (it derives the keys from the DCID), the SNI and a CONNECTION_CLOSE
in clear are read too.

A connection starts at a client Initial. Later packets join it by connection ID (any CID either
side announced) or by UDP 4-tuple; a packet that joins by CID from a new 4-tuple marks the
connection as migrated. The client of a TCP ClientHello to the same server (same SNI when both
are known) within 2 s after an unanswered Initial is a TCP fallback.
"""

from __future__ import annotations

from collections import Counter
from statistics import median
from typing import Any

from .fields import compact, iso, parse_time, split_fields_line, to_int

AGGREGATOR = "|"
FIELDS = [
    "frame.number", "frame.time_epoch", "frame.protocols", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport", "tcp.stream",
    "quic.header_form", "quic.long.packet_type", "quic.long.packet_type_v2", "quic.version", "quic.dcid", "quic.scid",
    "quic.supported_version", "quic.retry_token", "quic.spin_bit", "quic.cc.error_code", "quic.cc.reason_phrase",
    "tls.handshake.type", "tls.handshake.extensions_server_name",
]
FILTER = "quic || (tcp && tls.handshake.type == 1)"
FALLBACK_WINDOW_S = 2.0

QUIC_V1, QUIC_V2 = 0x00000001, 0x6B3343CF
VERSION_NAMES = {QUIC_V1: "QUICv1", QUIC_V2: "QUICv2", 0xFF00001D: "draft-29", 0xFF000020: "draft-32",
                 0x51303530: "Q050", 0x54303530: "T050", 0x54303531: "T051"}
V1_TYPES = {0: "initial", 1: "0rtt", 2: "handshake", 3: "retry"}
V2_TYPES = {1: "initial", 2: "0rtt", 3: "handshake", 0: "retry"}
TRANSPORT_ERRORS = {0: "NO_ERROR", 1: "INTERNAL_ERROR", 2: "CONNECTION_REFUSED", 3: "FLOW_CONTROL_ERROR",
                    4: "STREAM_LIMIT_ERROR", 5: "STREAM_STATE_ERROR", 6: "FINAL_SIZE_ERROR", 7: "FRAME_ENCODING_ERROR",
                    8: "TRANSPORT_PARAMETER_ERROR", 9: "CONNECTION_ID_LIMIT_ERROR", 10: "PROTOCOL_VIOLATION",
                    11: "INVALID_TOKEN", 12: "APPLICATION_ERROR", 13: "CRYPTO_BUFFER_EXCEEDED", 14: "KEY_UPDATE_ERROR",
                    15: "AEAD_LIMIT_REACHED", 16: "NO_VIABLE_PATH"}


def version_name(v: int | None) -> str | None:
    if v is None:
        return None
    if v & 0x0F0F0F0F == 0x0A0A0A0A:
        return f"0x{v:08x} (reserved, forces negotiation)"
    return VERSION_NAMES.get(v, f"0x{v:08x}")


def _nth(values: list[str], n: int) -> str:
    return values[n] if 0 <= n < len(values) else ""


def _hex(value: str) -> int | None:
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def parse(stdout: str, names: list[str] | None = None) -> list[dict[str, Any]]:
    names = names or FIELDS
    out = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(names):
            continue
        raw = {k: (v.split(AGGREGATOR) if v else []) for k, v in zip(names, cols)}
        get = lambda f: raw.get(f, [])  # noqa: E731
        layers = _nth(get("frame.protocols"), 0).split(":")
        v6 = "ipv6" in layers and ("ip" not in layers or layers.index("ipv6") < layers.index("ip"))
        # The innermost addresses: QUIC inside a GTP-U tunnel is read from the user's packet.
        srcs, dsts = get("ipv6.src" if v6 else "ip.src"), get("ipv6.dst" if v6 else "ip.dst")
        src, dst = (srcs[-1] if srcs else ""), (dsts[-1] if dsts else "")
        rec: dict[str, Any] = {"frame": to_int(_nth(get("frame.number"), 0)), "time": parse_time(_nth(get("frame.time_epoch"), 0)),
                               "src": src, "dst": dst}
        if "quic" in layers:
            forms = get("quic.header_form")
            versions = [_hex(v) for v in get("quic.version")]
            types: list[str] = []
            v1_types, v2_types = get("quic.long.packet_type"), get("quic.long.packet_type_v2")
            i1 = i2 = 0
            for v in versions:
                if v == QUIC_V2 and i2 < len(v2_types):
                    types.append(V2_TYPES.get(to_int(v2_types[i2]) or 0, "?"))
                    i2 += 1
                elif v not in (None, 0) and (v == QUIC_V1 or v & 0xFF000000 == 0xFF000000) and i1 < len(v1_types):
                    types.append(V1_TYPES.get(to_int(v1_types[i1]) or 0, "?"))
                    i1 += 1
                elif v == 0:
                    types.append("version_negotiation")
                else:
                    types.append("initial" if not types else "long")  # an unknown version: tshark reads no type
            rec.update({
                "kind": "quic", "sport": _nth(get("udp.srcport"), 0), "dport": _nth(get("udp.dstport"), 0),
                "long_types": types, "short": "0" in forms, "versions": versions,
                "dcids": get("quic.dcid"), "scids": get("quic.scid"),
                "supported": [_hex(v) for v in get("quic.supported_version")],
                "retry_token": bool(get("quic.retry_token")),
                "spin": [v in ("1", "True", "true") for v in get("quic.spin_bit")],
                "close_codes": [_hex(v) for v in get("quic.cc.error_code")],
                "close_reasons": get("quic.cc.reason_phrase"),
                "sni": _nth(get("tls.handshake.extensions_server_name"), 0) or None,
            })
        else:
            rec.update({"kind": "tcp_hello", "sport": _nth(get("tcp.srcport"), 0), "dport": _nth(get("tcp.dstport"), 0),
                        "stream": to_int(_nth(get("tcp.stream"), 0)),
                        "sni": _nth(get("tls.handshake.extensions_server_name"), 0) or None})
        out.append(rec)
    return out


def _new(rec: dict[str, Any]) -> dict[str, Any]:
    return {"client": (rec["src"], rec["sport"]), "server": (rec["dst"], rec["dport"]), "tuples": {_tuple(rec)},
            "cids": set(), "first": rec["time"], "last": rec["time"], "first_frame": rec["frame"],
            "last_frame": rec["frame"], "packets": Counter(), "client_version": None, "server_version": None,
            "vn": None, "retry": None, "sni": None, "short": {"client": [], "server": []}, "close": None,
            "migrated_frames": [], "initials": 0, "initial_frames": []}


def _tuple(rec: dict[str, Any]) -> tuple[Any, ...]:
    a, b = (rec["src"], rec["sport"]), (rec["dst"], rec["dport"])
    return tuple(sorted((a, b)))


def build(recs: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(QUIC connections in order of their first packet, TCP ClientHellos)."""
    conns: list[dict[str, Any]] = []
    by_cid: dict[str, dict[str, Any]] = {}
    by_tuple: dict[tuple[Any, ...], dict[str, Any]] = {}
    hellos = []
    for rec in recs:
        if rec["kind"] == "tcp_hello":
            hellos.append(rec)
            continue
        dcid = _nth(rec["dcids"], 0)
        conn = by_cid.get(dcid) if dcid else None
        tup = _tuple(rec)
        if conn is None:
            conn = by_tuple.get(tup)
        if conn is None:
            conn = _new(rec)
            conns.append(conn)
        if tup not in conn["tuples"]:
            if dcid and dcid in conn["cids"]:
                conn["migrated_frames"].append(rec["frame"])
            conn["tuples"].add(tup)
        by_tuple[tup] = conn
        for cid in rec["dcids"] + rec["scids"]:
            if cid:
                conn["cids"].add(cid)
                by_cid[cid] = conn
        side = "client" if (rec["src"], rec["sport"]) == conn["client"] or rec["src"] == conn["client"][0] else "server"
        conn["last"], conn["last_frame"] = rec["time"], rec["frame"]
        if rec["sni"] and not conn["sni"]:
            conn["sni"] = rec["sni"]
        for i, kind in enumerate(rec["long_types"]):
            conn["packets"][(side, kind)] += 1
            version = rec["versions"][i] if i < len(rec["versions"]) else None
            if kind == "version_negotiation":
                conn["vn"] = {"frame": rec["frame"], "supported": [v for v in rec["supported"] if v is not None]}
                continue
            if side == "client" and conn["client_version"] is None:
                conn["client_version"] = version
            if side == "server" and version:
                conn["server_version"] = version
            if kind == "retry" and side == "server":
                conn["retry"] = {"frame": rec["frame"], "token": rec["retry_token"]}
            if kind == "initial" and side == "client":
                conn["initials"] += 1
                if len(conn["initial_frames"]) < 5:
                    conn["initial_frames"].append(rec["frame"])
        if rec["short"]:
            conn["packets"][(side, "1rtt")] += 1
            if rec["spin"]:
                conn["short"][side].append((rec["time"], rec["spin"][-1]))
        for code, reason in zip(rec["close_codes"], rec["close_reasons"] + [""] * len(rec["close_codes"])):
            if code is not None and conn["close"] is None:
                conn["close"] = {"from": side, "frame": rec["frame"], "code": code,
                                 "name": TRANSPORT_ERRORS.get(code, (f"TLS alert {code - 0x100}" if 0x100 <= code <= 0x1FF
                                                                     else f"0x{code:x}")),
                                 "reason": reason or None}
    return conns, hellos


def _spin_rtt(samples: list[tuple[float, bool]]) -> float | None:
    """The spin bit flips once per round trip in each direction: the median time between flips."""
    flips = [t for (t, s), (_, prev) in zip(samples[1:], samples[:-1]) if s != prev and t is not None]
    gaps = [b - a for a, b in zip(flips, flips[1:]) if b > a]
    return round(median(gaps) * 1000, 3) if gaps else None


def rows(conns: list[dict[str, Any]], hellos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for conn in conns:
        p = conn["packets"]
        c = lambda side, kind: p.get((side, kind), 0)  # noqa: E731
        server_answered = any(n for (side, _), n in p.items() if side == "server")
        hs_both = c("client", "handshake") > 0 and c("server", "handshake") > 0
        onertt_both = c("client", "1rtt") > 0 and c("server", "1rtt") > 0
        if conn["close"] and conn["close"]["code"] not in (0, None):
            outcome = "closed_with_error"
        elif onertt_both:
            outcome = "established"
        elif conn["vn"] and not hs_both:
            outcome = "version_negotiation"
        elif conn["retry"] and not c("server", "initial"):
            outcome = "retry_unanswered"
        elif hs_both:
            outcome = "handshake_only"
        elif server_answered:
            outcome = "handshake_incomplete"
        else:
            outcome = "no_response"
        row: dict[str, Any] = {
            "client": f"{conn['client'][0]}:{conn['client'][1]}", "server": f"{conn['server'][0]}:{conn['server'][1]}",
            "sni": conn["sni"], "version": version_name(conn["client_version"]),
            "server_version": version_name(conn["server_version"]) if conn["server_version"] not in (None, conn["client_version"]) else None,
            "first": iso(conn["first"]), "last": iso(conn["last"]), "first_frame": conn["first_frame"],
            "last_frame": conn["last_frame"],
            "initial_sent": conn["initials"], "server_initial": c("server", "initial") > 0,
            "handshake_packets_both_ways": hs_both, "one_rtt_both_ways": onertt_both,
            "zero_rtt": c("client", "0rtt") or None,
            "retry": compact({"frame": conn["retry"]["frame"], "token": conn["retry"]["token"] or None}) if conn["retry"] else None,
            "version_negotiation": {"frame": conn["vn"]["frame"], "offered": version_name(conn["client_version"]),
                                    "supported": [version_name(v) for v in conn["vn"]["supported"]]} if conn["vn"] else None,
            "connection_close": compact(conn["close"]) if conn["close"] else None,
            "migrated": bool(conn["migrated_frames"]) or None,
            "migration_frames": conn["migrated_frames"][:5] or None,
            "spin_rtt_ms": _spin_rtt(conn["short"]["client"]) or _spin_rtt(conn["short"]["server"]),
            "packets": {f"{side}_{kind}": n for (side, kind), n in sorted(p.items())},
            "outcome": outcome,
        }
        if outcome in ("no_response", "retry_unanswered", "version_negotiation", "handshake_incomplete"):
            fb = _fallback(conn, hellos)
            if fb:
                row["tcp_fallback"] = fb
        row["issues"] = _issues(row, conn)
        out.append(compact(row))
    return out


def _fallback(conn: dict[str, Any], hellos: list[dict[str, Any]]) -> dict[str, Any] | None:
    last = conn["last"] or conn["first"]
    for h in hellos:
        if h["src"] != conn["client"][0] or h["time"] is None or last is None:
            continue
        if not 0 <= h["time"] - last <= FALLBACK_WINDOW_S:
            continue
        same_name = conn["sni"] and h["sni"] and conn["sni"] == h["sni"]
        if same_name or h["dst"] == conn["server"][0]:
            return compact({"frame": h["frame"], "tcp_stream": h["stream"], "server": f"{h['dst']}:{h['dport']}",
                            "sni": h["sni"], "after_ms": round((h["time"] - last) * 1000, 3)})
    return None


def _issues(row: dict[str, Any], conn: dict[str, Any]) -> list[str]:
    who = row.get("sni") or row["server"]
    out = []
    o = row["outcome"]
    if o == "no_response":
        out.append(f"{who}: {row['initial_sent']} QUIC Initial(s) from {row['client']} and no answer: UDP 443 blocked "
                   "or the server does not speak QUIC")
    elif o == "version_negotiation":
        vn = row["version_negotiation"]
        out.append(f"{who}: the server does not support {vn['offered']} and offered {', '.join(vn['supported'])}; "
                   "the client did not retry with one of them")
    elif o == "retry_unanswered":
        out.append(f"{who}: the server sent a Retry and the client never came back with the token")
    elif o == "handshake_incomplete":
        out.append(f"{who}: the server answered but the handshake did not reach 1-RTT data both ways")
    elif o == "closed_with_error":
        cc = row["connection_close"]
        out.append(f"{who}: CONNECTION_CLOSE {cc.get('name')} from the {cc.get('from')}"
                   + (f" ({cc['reason']})" if cc.get("reason") else ""))
    if row.get("tcp_fallback"):
        fb = row["tcp_fallback"]
        out.append(f"{who}: the client fell back to TCP {fb['after_ms']} ms later (frame {fb['frame']})")
    if row.get("migrated"):
        out.append(f"{who}: the connection moved to a new address or port (frames {row['migration_frames']}); "
                   "a NAT rebinding or a network change")
    return out


def summary(out_rows: list[dict[str, Any]]) -> dict[str, Any]:
    outcomes = Counter(r["outcome"] for r in out_rows)
    versions = Counter(r["version"] for r in out_rows if r.get("version"))
    by_server: dict[str, list[dict[str, Any]]] = {}
    for r in out_rows:
        by_server.setdefault(r["server"].rsplit(":", 1)[0], []).append(r)
    blocked = [s for s, rs in by_server.items() if all(r["outcome"] == "no_response" for r in rs)]
    fell_back = sum(1 for r in out_rows if r.get("tcp_fallback"))
    s: dict[str, Any] = {
        "connections": len(out_rows), "outcomes": dict(outcomes), "versions": dict(versions),
        "tcp_fallbacks": fell_back or None, "migrated": sum(1 for r in out_rows if r.get("migrated")) or None,
        "servers_never_answering": blocked[:10] or None,
    }
    if out_rows and blocked and len(blocked) == len(by_server) and fell_back:
        s["udp_443_blocked_likely"] = True
    return compact(s)
