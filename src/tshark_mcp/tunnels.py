"""User-plane health per GTP-U tunnel (TS 29.281) from ``-T fields`` output.

For every G-PDU the outer and inner IP layers are told apart with
``frame.protocols`` (the layer list, e.g. ``eth:ethertype:ip:udp:gtp:ip:tcp``),
so the inner TCP and ICMP fields are read from the user's packet and not from
the transport. An ICMP error whose quoted packet is a G-PDU (``ip:icmp:ip:udp:
gtp``) is an outer, transport-level error and is reported apart.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .fields import compact, iso, parse_time, split_fields_line, to_int

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "ip.src", "ip.dst", "ip.len", "ip.flags.df", "ip.id", "ipv6.src", "ipv6.dst", "ipv6.plen",
    "gtp.teid",
    "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.window_size_value",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset", "tcp.options.mss_val",
    "icmp.type", "icmp.code", "icmp.mtu", "icmpv6.type", "icmpv6.code", "icmpv6.mtu",
]
AGGREGATOR = "|"

ICMP_ERROR_TYPES = "icmp.type == 3 || icmp.type == 11 || icmpv6.type == 1 || icmpv6.type == 2 || icmpv6.type == 3"

ICMP_NAMES = {
    (0, 0): "echo reply", (8, 0): "echo request", (3, 0): "net unreachable", (3, 1): "host unreachable",
    (3, 2): "protocol unreachable", (3, 3): "port unreachable", (3, 4): "fragmentation needed",
    (3, 9): "net administratively prohibited", (3, 10): "host administratively prohibited",
    (3, 13): "communication administratively prohibited", (11, 0): "TTL exceeded in transit",
    (11, 1): "fragment reassembly time exceeded",
}
ICMPV6_NAMES = {
    (128, 0): "echo request", (129, 0): "echo reply", (1, 0): "no route", (1, 1): "administratively prohibited",
    (1, 3): "address unreachable", (1, 4): "port unreachable", (2, 0): "packet too big",
    (3, 0): "hop limit exceeded", (3, 1): "fragment reassembly time exceeded",
}

RETRANSMISSION_ALERT = 0.05  # share of inner TCP data segments
MIN_SEGMENTS_FOR_RATIO = 20


def display_filter(teid: int | None) -> str:
    """G-PDUs (one tunnel when ``teid`` is given) and the ICMP errors that quote one."""
    gpdu = "gtp.message == 0xff" + (f" && gtp.teid == 0x{teid:08x}" if teid is not None else "")
    return f"({gpdu}) || (({ICMP_ERROR_TYPES}) && udp.port == 2152)"


def _truthy(value: str) -> bool:
    return value in ("1", "True", "true")


def _layers(protocols: str) -> list[str]:
    return [p for p in protocols.split(":") if p not in ("eth", "ethertype", "sll", "vlan", "frame")]


def _nth(values: list[str], n: int) -> str:
    return values[n] if 0 <= n < len(values) else ""


def parse(stdout: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(G-PDU records, outer ICMP error records)."""
    gpdus, outer = [], []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(FIELDS):
            continue
        raw = {k: (v.split(AGGREGATOR) if v else []) for k, v in zip(FIELDS, cols)}
        layers = _layers(_nth(raw["frame.protocols"], 0))
        if "gtp" not in layers and "icmp" not in layers and "icmpv6" not in layers:
            continue
        gtp_at = layers.index("gtp") if "gtp" in layers else len(layers)
        icmp_at = min((layers.index(p) for p in ("icmp", "icmpv6") if p in layers), default=len(layers))
        rec = _common(raw, layers, gtp_at)
        if icmp_at < gtp_at:
            rec.update(_icmp(raw, layers, 0))
            outer.append(rec)
            continue
        inner = layers[gtp_at + 1] if gtp_at + 1 < len(layers) else None
        inner_ip, inner_v6 = _inner_index(layers, gtp_at)
        rec["inner_family"] = "ipv6" if inner == "ipv6" else ("ipv4" if inner == "ip" else None)
        if inner == "ip":
            rec["inner_src"], rec["inner_dst"] = _nth(raw["ip.src"], inner_ip), _nth(raw["ip.dst"], inner_ip)
            rec["inner_len"] = to_int(_nth(raw["ip.len"], inner_ip))
            rec["inner_df"] = _truthy(_nth(raw["ip.flags.df"], inner_ip))
        elif inner == "ipv6":
            rec["inner_src"], rec["inner_dst"] = _nth(raw["ipv6.src"], inner_v6), _nth(raw["ipv6.dst"], inner_v6)
            plen = to_int(_nth(raw["ipv6.plen"], inner_v6))
            rec["inner_len"] = plen + 40 if plen is not None else None
            rec["inner_df"] = True  # IPv6 routers never fragment
        transport = layers[gtp_at + 2] if gtp_at + 2 < len(layers) else None
        rec["inner_proto"] = transport
        rec["outer_id"] = _nth(raw["ip.id"], 0) if layers and layers[0] == "ip" else ""
        rec["inner_id"] = _nth(raw["ip.id"], inner_ip) if inner == "ip" else ""
        if transport == "tcp":
            # tshark's tcp.analysis flags are not used: they also fire on a second copy of the
            # same packet (captured on two interfaces, or tunnelled and decapsulated), which
            # is not a retransmission. summarise() tells the two apart by IP ID.
            rec["tcp"] = {
                "sport": _nth(raw["tcp.srcport"], 0), "dport": _nth(raw["tcp.dstport"], 0),
                "seq": to_int(_nth(raw["tcp.seq_raw"], 0)), "ack_no": to_int(_nth(raw["tcp.ack_raw"], 0)),
                "len": to_int(_nth(raw["tcp.len"], 0), 0) or 0,
                "window": to_int(_nth(raw["tcp.window_size_value"], 0)),
                "syn": _truthy(_nth(raw["tcp.flags.syn"], 0)),
                "ack": _truthy(_nth(raw["tcp.flags.ack"], 0)),
                "fin": _truthy(_nth(raw["tcp.flags.fin"], 0)),
                "rst": _truthy(_nth(raw["tcp.flags.reset"], 0)),
                "mss": to_int(_nth(raw["tcp.options.mss_val"], 0)),
            }
        elif transport in ("icmp", "icmpv6"):
            rec.update(_icmp(raw, layers, 0))
        gpdus.append(rec)
    return gpdus, outer


def _inner_index(layers: list[str], gtp_at: int) -> tuple[int, int]:
    """Occurrence index of the inner IPv4 and IPv6 layer among all ip / ipv6 layers."""
    return layers[: gtp_at + 1].count("ip"), layers[: gtp_at + 1].count("ipv6")


def _common(raw: dict[str, list[str]], layers: list[str], gtp_at: int) -> dict[str, Any]:
    outer_v6 = bool(layers) and layers[0] == "ipv6"
    if outer_v6:
        src, dst = _nth(raw["ipv6.src"], 0), _nth(raw["ipv6.dst"], 0)
        plen = to_int(_nth(raw["ipv6.plen"], 0))
        outer_len = plen + 40 if plen is not None else None
    else:
        src, dst = _nth(raw["ip.src"], 0), _nth(raw["ip.dst"], 0)
        outer_len = to_int(_nth(raw["ip.len"], 0))
    return {
        "frame": to_int(_nth(raw["frame.number"], 0)),
        "time": parse_time(_nth(raw["frame.time_epoch"], 0)),
        "frame_len": to_int(_nth(raw["frame.len"], 0), 0) or 0,
        "outer_src": src, "outer_dst": dst, "outer_len": outer_len,
        "teid": _nth(raw["gtp.teid"], 0) or None,
    }


def _icmp(raw: dict[str, list[str]], layers: list[str], n: int) -> dict[str, Any]:
    first = next((p for p in layers if p in ("icmp", "icmpv6")), None)
    key = "icmpv6" if first == "icmpv6" else "icmp"
    itype, icode = to_int(_nth(raw[f"{key}.type"], n)), to_int(_nth(raw[f"{key}.code"], n))
    names = ICMPV6_NAMES if key == "icmpv6" else ICMP_NAMES
    name = names.get((itype, icode), f"{key} type {itype} code {icode}")
    return {"icmp": {"family": key, "type": itype, "code": icode, "name": name, "mtu": to_int(_nth(raw[f"{key}.mtu"], n))}}


def summarise(gpdus: list[dict[str, Any]], outer: list[dict[str, Any]], mtu: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(one row per TEID, outer ICMP errors grouped by sender, type and MTU)."""
    buckets: dict[str, dict[str, Any]] = {}
    for rec in gpdus:
        teid = rec.get("teid")
        if not teid:
            continue
        b = buckets.get(teid)
        if b is None:
            b = buckets[teid] = {
                "teid": teid, "outer_src": rec["outer_src"], "outer_dst": rec["outer_dst"], "packets": 0, "frame_bytes": 0,
                "first": rec["time"], "last": rec["time"], "protocols": Counter(), "inner_src": Counter(),
                "inner_dst": Counter(), "overheads": Counter(), "max_outer": 0, "max_inner": 0, "families": Counter(),
                "df_large": 0, "tcp": Counter(), "streams": set(), "mss": Counter(), "icmp": Counter(), "frag_mtus": Counter(),
                "syns_seen": set(), "last_ack": {}, "packets_seen": {}, "flow_end": {}, "last_ip_id": {}, "id_steps": {},
            }
        if _duplicate_copy(b, rec):
            b["copies"] = b.get("copies", 0) + 1
            if rec.get("tcp"):
                b["tcp"]["duplicate_copies"] += 1
            continue
        b["packets"] += 1
        b["frame_bytes"] += rec["frame_len"]
        if rec["time"] is not None:
            b["first"] = rec["time"] if b["first"] is None else min(b["first"], rec["time"])
            b["last"] = rec["time"] if b["last"] is None else max(b["last"], rec["time"])
        b["protocols"][rec.get("inner_proto") or "other"] += 1
        if rec.get("inner_src"):
            b["inner_src"][rec["inner_src"]] += 1
            b["inner_dst"][rec["inner_dst"]] += 1
        if rec.get("inner_family"):
            b["families"][rec["inner_family"]] += 1
        outer_len, inner_len = rec.get("outer_len"), rec.get("inner_len")
        if outer_len:
            b["max_outer"] = max(b["max_outer"], outer_len)
        if inner_len:
            b["max_inner"] = max(b["max_inner"], inner_len)
        if outer_len and inner_len:
            b["overheads"][outer_len - inner_len] += 1
            if rec.get("inner_df") and outer_len > mtu:
                b["df_large"] += 1
        tcp = rec.get("tcp")
        if tcp:
            _tcp_stats(b, rec, tcp)
        icmp = rec.get("icmp")
        if icmp:
            b["icmp"][icmp["name"]] += 1
            if icmp["mtu"]:
                b["frag_mtus"][icmp["mtu"]] += 1
    rows = [_row(b, mtu) for b in buckets.values()]
    _link_directions(rows)
    rows.sort(key=lambda r: (-len(r.get("issues", [])), -r["packets"], r["teid"]))
    return rows, _outer_errors(outer)


DUPLICATE_WINDOW_S = 0.005


def _duplicate_copy(b: dict[str, Any], rec: dict[str, Any]) -> bool:
    """The same tunnelled packet seen again: same outer and inner IP ID (and, when both
    IDs are zero, within a few milliseconds). Capturing on several interfaces does this."""
    outer_id, inner_id = rec.get("outer_id") or "", rec.get("inner_id") or ""
    tcp = rec.get("tcp") or {}
    key = (rec["outer_src"], rec["outer_dst"], outer_id, inner_id, rec.get("inner_src"), rec.get("inner_dst"),
           tcp.get("seq"), tcp.get("ack_no"), tcp.get("len"), rec.get("inner_len"))
    seen = b["packets_seen"].get(key)
    b["packets_seen"][key] = rec["time"]
    if seen is None:
        return False
    if (outer_id and int(outer_id, 16) != 0) or (inner_id and int(inner_id, 16) != 0):
        return True
    return rec["time"] is not None and abs(rec["time"] - seen) <= DUPLICATE_WINDOW_S


def _tcp_stats(b: dict[str, Any], rec: dict[str, Any], tcp: dict[str, Any]) -> None:
    t = b["tcp"]
    t["segments"] += 1
    flow = (rec.get("inner_src"), rec.get("inner_dst"), tcp["sport"], tcp["dport"])
    b["streams"].add(tuple(sorted([(flow[0], flow[2]), (flow[1], flow[3])])))
    if tcp["syn"]:
        t["synack" if tcp["ack"] else "syn"] += 1
        if tcp["mss"] is not None:
            b["mss"][tcp["mss"]] += 1
    if tcp["rst"]:
        t["rst"] += 1
    if tcp["window"] == 0 and not (tcp["rst"] or tcp["syn"] or tcp["fin"]):
        t["zero_window"] += 1
    seq = tcp["seq"]
    if tcp["syn"] and seq is not None and (flow, seq) not in b["syns_seen"]:
        b["flow_end"].pop(flow, None)  # a new connection on a reused 4-tuple starts its own sequence space
    end = b["flow_end"].get(flow)
    if (tcp["len"] <= 1 and not (tcp["syn"] or tcp["fin"] or tcp["rst"]) and seq is not None
            and end is not None and seq == (end - 1) % 2**32):
        t["keepalives"] += 1  # one byte (or none) just below the next sequence number: a keep-alive probe
        return
    inner_id = to_int(rec.get("inner_id") or "", None) if rec.get("inner_id") else None
    last_id = b["last_ip_id"].get(flow)
    if inner_id:
        b["last_ip_id"][flow] = inner_id if last_id is None or 0 < (inner_id - last_id) % 65536 < 32768 else last_id
        if last_id is not None:
            steps = b["id_steps"].setdefault(flow, [0, 0])
            steps[1] += 1
            if min((inner_id - last_id) % 65536, (last_id - inner_id) % 65536) <= 64:
                steps[0] += 1  # neighbouring IDs: the sender numbers packets in order, not at random
    if seq is not None and not tcp["rst"]:
        nxt = (seq + tcp["len"] + (1 if tcp["syn"] or tcp["fin"] else 0)) % 2**32
        if end is None or 0 < (nxt - end) % 2**32 < 2**31:
            b["flow_end"][flow] = nxt
    if tcp["len"] > 0 or tcp["syn"] or tcp["fin"]:
        if tcp["len"] > 0:
            t["data_segments"] += 1
        # Like tshark: a segment that starts below the highest sequence number already seen
        # in this flow is a retransmission, unless its IP ID shows it was sent before the
        # packet seen ahead of it, which makes it a reordered segment.
        behind = seq is not None and end is not None and 0 < (end - seq) % 2**32 < 2**31
        if tcp["syn"] and seq is not None and (flow, seq) in b["syns_seen"]:
            behind = True
        if behind:
            steps = b["id_steps"].get(flow, [0, 0])
            sequential_ids = steps[1] >= 2 and steps[0] >= 0.8 * steps[1]
            if sequential_ids and inner_id and last_id and 0 < (last_id - inner_id) % 65536 < 32768:
                t["out_of_order"] += 1
            else:
                t["retrans"] += 1
                if tcp["len"] > 0:
                    t["data_retrans"] += 1
                elif tcp["syn"]:
                    t["syn_retrans"] += 1
        if tcp["syn"] and seq is not None:
            b["syns_seen"].add((flow, seq))
        return
    if tcp["rst"] or tcp["ack_no"] is None:
        return
    previous = b["last_ack"].get(flow)
    if previous == (tcp["ack_no"], tcp["window"]):
        t["dup_ack"] += 1
    b["last_ack"][flow] = (tcp["ack_no"], tcp["window"])


def _row(b: dict[str, Any], mtu: int) -> dict[str, Any]:
    overhead = b["overheads"].most_common(1)[0][0] if b["overheads"] else None
    t = b["tcp"]
    tcp: dict[str, Any] = {}
    if t["segments"]:
        tcp = {
            "segments": t["segments"], "data_segments": t["data_segments"], "flows": len(b["streams"]),
            "syn": t["syn"], "syn_ack": t["synack"], "mss_in_syn": {str(k): v for k, v in sorted(b["mss"].items())},
            "retransmissions": t["retrans"], "data_retransmissions": t["data_retrans"],
            "syn_retransmissions": t["syn_retrans"], "duplicate_acks": t["dup_ack"], "zero_windows": t["zero_window"],
            "resets": t["rst"], "keepalives": t["keepalives"], "out_of_order": t["out_of_order"],
        }
        if t["data_segments"]:
            tcp["retransmission_ratio"] = round(t["data_retrans"] / t["data_segments"], 3)
        tcp = {k: v for k, v in tcp.items() if v not in (0, {}, None) or k in ("segments", "retransmissions")}
    duration = (b["last"] - b["first"]) if (b["first"] is not None and b["last"] is not None) else None
    row = {
        "teid": b["teid"], "outer_src": b["outer_src"], "outer_dst": b["outer_dst"], "packets": b["packets"],
        "frame_bytes": b["frame_bytes"], "first": iso(b["first"]), "last": iso(b["last"]),
        "duration_s": round(duration, 6) if duration is not None else None,
        "inner_protocols": dict(b["protocols"]),
        "inner_src": [a for a, _ in b["inner_src"].most_common(3)],
        "inner_dst": [a for a, _ in b["inner_dst"].most_common(3)],
        "max_outer_ip_len": b["max_outer"] or None, "max_inner_ip_len": b["max_inner"] or None,
        "tunnel_overhead": overhead,
        "inner_df_above_mtu": b["df_large"] or None,
        "duplicate_copies": b.get("copies") or None,
        "tcp": tcp or None,
        "icmp": dict(b["icmp"]) or None,
        "icmp_frag_needed_mtu": {str(k): v for k, v in sorted(b["frag_mtus"].items())} or None,
    }
    row["issues"] = _issues(row, b, overhead, mtu)
    return compact(row)


def _issues(row: dict[str, Any], b: dict[str, Any], overhead: int | None, mtu: int) -> list[str]:
    issues = []
    tcp = row.get("tcp") or {}
    over = overhead if overhead is not None else 36
    family_extra = 60 if b["families"].get("ipv6", 0) > b["families"].get("ipv4", 0) else 40
    for mss in sorted(b["mss"]):
        needed = mss + family_extra + over
        if needed > mtu:
            issues.append(f"MSS {mss} in a SYN on this tunnel lets the peer send inner packets of {mss + family_extra} bytes, "
                          f"{needed} bytes once tunnelled ({over} bytes of overhead), above the {mtu}-byte path MTU; "
                          f"an MSS of at most {mtu - family_extra - over} fits")
    ratio = tcp.get("retransmission_ratio")
    if ratio is not None and ratio >= RETRANSMISSION_ALERT and tcp.get("data_segments", 0) >= MIN_SEGMENTS_FOR_RATIO:
        issues.append(f"{round(ratio * 100, 1)}% of inner TCP data segments are retransmissions "
                      f"({tcp['data_retransmissions']} of {tcp['data_segments']})")
    ooo = tcp.get("out_of_order", 0)
    if tcp.get("data_segments", 0) >= MIN_SEGMENTS_FOR_RATIO and ooo >= RETRANSMISSION_ALERT * tcp["data_segments"]:
        issues.append(f"{ooo} inner TCP segments arrived out of order (their IP ID shows they were sent before the "
                      "packet ahead of them); tshark's analysis flags these as retransmissions, they are not")
    if row.get("duplicate_copies"):
        issues.append(f"{row['duplicate_copies']} extra copies of packets already seen (same IP IDs): the capture "
                      "holds the tunnel more than once; they are left out of every count")
    if tcp.get("syn_retransmissions"):
        issues.append(f"{tcp['syn_retransmissions']} SYN or SYN-ACK retransmissions (connection attempts not answered)")
    if b["frag_mtus"]:
        issues.append("ICMP fragmentation needed / packet too big inside the tunnel, next-hop MTU "
                      + ", ".join(str(m) for m in sorted(b["frag_mtus"])))
    if b["df_large"]:
        issues.append(f"{b['df_large']} tunnelled packets with DF set are larger than the {mtu}-byte path MTU")
    if tcp.get("resets"):
        issues.append(f"{tcp['resets']} inner TCP resets")
    return issues


def _link_directions(rows: list[dict[str, Any]]) -> None:
    """Mark tunnels whose reverse direction (swapped outer endpoints) carries no G-PDU."""
    by_pair: dict[tuple[str, str], list[str]] = defaultdict(list)
    for r in rows:
        by_pair[(r["outer_src"], r["outer_dst"])].append(r["teid"])
    for r in rows:
        reverse = by_pair.get((r["outer_dst"], r["outer_src"]), [])
        if reverse:
            r["reverse_teids"] = reverse[:5]
        else:
            r["reverse_seen"] = False
            r.setdefault("issues", []).append("no G-PDU seen in the reverse direction between these tunnel endpoints")


def _outer_errors(outer: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple, dict[str, Any]] = {}
    for rec in outer:
        icmp = rec.get("icmp") or {}
        key = (rec["outer_src"], icmp.get("name"), icmp.get("mtu"))
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"from": rec["outer_src"], "to": rec["outer_dst"], "error": icmp.get("name"),
                               "mtu": icmp.get("mtu"), "count": 0, "teids": Counter(), "first": rec["time"]}
        g["count"] += 1
        if rec.get("teid"):
            g["teids"][rec["teid"]] += 1
    return [compact({"from": g["from"], "to": g["to"], "error": g["error"], "mtu": g["mtu"], "count": g["count"],
                     "first": iso(g["first"]), "teids": [t for t, _ in g["teids"].most_common(5)]})
            for g in sorted(groups.values(), key=lambda g: -g["count"])]
