"""Message rates over time and storm detection, from one ``-T fields`` pass.

Every Diameter, GTPv2-C, GTPv1-C, SIP and MAP message is reduced to (time, protocol,
message name, request or answer, subscriber), then counted per interval. A
burst is a run of intervals where one message type runs at three times its
usual rate or more (and at least ``burst_min`` per interval); a subscriber loop
is one subscriber sending the same request again and again, reported with the
interval between repeats. A message seen more than once (on both legs of a relay
or proxy, or retransmitted) is one distinct message: the Diameter End-to-End id,
the GTP sequence number, the TCAP transaction id or the SIP Call-ID and CSeq
identify it, and bursts and loops count distinct messages.

Subscribers: Diameter requests carry User-Name and GTP requests the IMSI; a GTP
response takes the IMSI of the request with the same sequence number. MAP messages
are tied to an IMSI through their TCAP dialogue: every message of a dialogue
(Begin, Continue, End, Abort, linked by transaction ids) takes the IMSI that any
message of the dialogue carries, so a sendAuthenticationInfo invoke in a Continue,
or a routing result that names the IMSI, is counted for that subscriber. A message
that names one IMSI itself always keeps it; a message without one in a dialogue that
names two IMSIs (a transaction id reused by another dialogue), and packets carrying
several bundled TCAP messages, are left unattributed.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Any

from . import diameter, gtp, gtpv1, sip
from .fields import iso, parse_time, split_fields_line, to_int
from .sigtran import MAP_OPERATIONS, decode_tbcd

PROTOCOLS = ("auto", "diameter", "gtpv2", "gtpv1", "sip", "map")
FILTERS = {"diameter": "diameter", "gtpv2": "gtpv2", "gtpv1": f"({gtpv1.BASE_FILTER})", "sip": "sip", "map": "gsm_map"}
AGGREGATOR = "|"

_DIAMETER = ["diameter.cmd.code", "diameter.flags.request", "diameter.User-Name", "diameter.endtoendid",
             "diameter.Origin-Host", "diameter.Destination-Host", "diameter.Destination-Realm"]
_GTP = ["gtpv2.message_type", "e212.imsi", "gtpv2.seq"]
_GTPV1 = ["gtp.message", "gtp.seq_number"]
# Raw TBCD IMSI fields, decoded when the build does not emit e212.imsi for them.
_MAP_RAW_IMSI = ["gsm_map.imsi", "gsm_map.ms.imsi", "gsm_map.sm.imsi", "gsm_map.ch.imsi", "gsm_old.imsi"]
_MAP = ["gsm_map.old.Component", "gsm_old.localValue", "gsm_old.invokeID", "tcap.tid", "tcap.otid", "tcap.dtid", *_MAP_RAW_IMSI,
        "sccp.calling.digits", "sccp.called.digits", "m3ua.protocol_data_opc", "m3ua.protocol_data_dpc"]
_SIP = [f for f in sip.FIELDS if f not in ("frame.number", "frame.time_epoch", "ip.src", "ip.dst")]
FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", *_DIAMETER, *_GTP, *_GTPV1, *_MAP,
          *[f for f in _SIP if f not in _DIAMETER + _GTP + _GTPV1 + _MAP]]

MAP_COMPONENTS = {1: "invoke", 2: "returnResultLast", 3: "returnError", 4: "reject", 7: "returnResultNotLast"}
MAX_TIMELINE = 500
MAX_SUBSCRIBERS = 50
BURST_FACTOR = 3.0


def display_filter(protocol: str) -> str:
    if protocol == "auto":
        return " || ".join(FILTERS.values())
    return FILTERS[protocol]


def events(stdout: str, protocol: str) -> list[dict[str, Any]]:
    """One event per message: time, protocol, name, request flag, subscriber."""
    out: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(FIELDS):
            continue
        rec = dict(zip(FIELDS, cols))
        ts = parse_time(rec["frame.time_epoch"].split(AGGREGATOR)[0])
        if ts is None:
            continue
        before = len(out)
        _add_events(out, rec, ts, protocol)
        frame = to_int(rec["frame.number"].split(AGGREGATOR)[0])
        for e in out[before:]:
            e["frame"] = frame
    _gtp_response_subscribers(out)
    _map_dialogue_subscribers(out)
    return out


def _add_events(out: list[dict[str, Any]], rec: dict[str, str], ts: float, protocol: str) -> None:
    if rec["diameter.cmd.code"] and protocol in ("auto", "diameter"):
        out.extend(_diameter(rec, ts))
    elif rec["gtpv2.message_type"] and protocol in ("auto", "gtpv2"):
        out.extend(_gtpv2(rec, ts))
    elif rec["gtp.message"] and protocol in ("auto", "gtpv1"):
        out.extend(_gtpv1(rec, ts))
    elif rec["gsm_map.old.Component"] and protocol in ("auto", "map"):
        out.extend(_map(rec, ts))
    elif rec["sip.Call-ID"] and protocol in ("auto", "sip"):
        out.extend(_sip(rec, ts))


def _split(value: str) -> list[str]:
    return value.split(AGGREGATOR) if value else []


def _pick(values: list[str], i: int, n: int) -> str | None:
    """The value for message ``i`` of ``n`` in one packet: by position when every message
    has one, else the packet's only value."""
    if len(values) == n and values[i]:
        return values[i]
    distinct = {v for v in values if v}
    return distinct.pop() if len(distinct) == 1 else None


def _ip(rec: dict[str, str], name: str) -> str | None:
    """The innermost address (the signalling's own header when it is tunnelled)."""
    values = [v for v in _split(rec.get(name, "")) if v]
    return values[-1] if values else None


def _map_node(rec: dict[str, str], gt: str, pc: str, ip: str) -> str | None:
    """A MAP node: the SCCP global title, else the M3UA point code, else the IP address.
    Bundled messages with different values give the next identifier down."""
    for field, label in ((gt, "GT"), (pc, "PC")):
        distinct = {v for v in _split(rec[field]) if v}
        if len(distinct) == 1:
            return f"{label} {distinct.pop()}"
    return _ip(rec, ip)


def _diameter(rec: dict[str, str], ts: float) -> list[dict[str, Any]]:
    codes, flags = _split(rec["diameter.cmd.code"]), _split(rec["diameter.flags.request"])
    users = _split(rec["diameter.User-Name"])
    e2e = _split(rec["diameter.endtoendid"])
    requests = [f in ("1", "True") for f in flags] if len(flags) == len(codes) else [None] * len(codes)
    # User-Name is in requests only; it can be matched to a message when every request of the packet has one.
    req_idx = [i for i, r in enumerate(requests) if r]
    user_of = dict(zip(req_idx, users)) if len(users) == len(req_idx) else {}
    origins = _split(rec["diameter.Origin-Host"])
    dest_hosts, dest_realms = _split(rec["diameter.Destination-Host"]), _split(rec["diameter.Destination-Realm"])
    out = []
    for i, code in enumerate(codes):
        c = to_int(code)
        if c is None:
            continue
        is_req = requests[i]
        dest_host = _pick(dest_hosts, i, len(codes))
        dest_realm = _pick(dest_realms, i, len(codes))
        out.append({"t": ts, "protocol": "diameter", "message": diameter.command_name(c, bool(is_req)),
                    "request": is_req, "subscriber": user_of.get(i),
                    "key": ("diameter", e2e[i], c, is_req) if len(e2e) == len(codes) else None,
                    "from": _pick(origins, i, len(codes)) or _ip(rec, "ip.src"),
                    "to": dest_host or (f"realm {dest_realm}" if dest_realm else _ip(rec, "ip.dst"))})
    return out


def _gtpv2(rec: dict[str, str], ts: float) -> list[dict[str, Any]]:
    types = _split(rec["gtpv2.message_type"])
    imsis = _split(rec["e212.imsi"])
    seqs = _split(rec["gtpv2.seq"])
    out = []
    for i, mt in enumerate(types):
        m = to_int(mt)
        if m is None:
            continue
        out.append({"t": ts, "protocol": "gtpv2", "message": gtp.message_name(m), "request": m not in gtp.RESPONSE_TYPES,
                    "subscriber": imsis[i] if len(imsis) == len(types) else None,
                    "key": ("gtpv2", seqs[i], m) if len(seqs) == len(types) else None,
                    "seq": seqs[i] if len(seqs) == len(types) else None, "type": m,
                    "from": _ip(rec, "ip.src"), "to": _ip(rec, "ip.dst")})
    return out


def _gtpv1(rec: dict[str, str], ts: float) -> list[dict[str, Any]]:
    m = to_int(rec["gtp.message"].split(AGGREGATOR)[0])
    if m is None or m == 0xFF:
        return []
    imsi = rec["e212.imsi"].split(AGGREGATOR)[0] or None
    seq = rec["gtp.seq_number"].split(AGGREGATOR)[0] or None
    return [{"t": ts, "protocol": "gtpv1", "message": gtpv1.message_name(m), "request": m not in gtpv1.RESPONSE_TYPES,
             "subscriber": imsi, "key": ("gtpv1", seq, m) if seq else None, "seq": seq, "type": m,
             "from": _ip(rec, "ip.src"), "to": _ip(rec, "ip.dst")}]


def _gtp_response_subscribers(evts: list[dict[str, Any]]) -> None:
    """A GTP response names no IMSI; it takes the IMSI of the request it answers
    (same sequence number, the matching type, sent up to 30 s earlier)."""
    pairs = {"gtpv1": gtpv1.REQUEST_TO_RESPONSE, "gtpv2": gtp.REQUEST_TO_RESPONSE}
    last: dict[tuple, tuple[float, str]] = {}
    for e in sorted((e for e in evts if e["protocol"] in pairs and e.get("seq")), key=lambda e: e["t"]):
        proto = e["protocol"]
        if e["request"]:
            resp = pairs[proto].get(e["type"])
            if resp is not None and e["subscriber"]:
                last[(proto, e["seq"], resp)] = (e["t"], e["subscriber"])
        elif not e["subscriber"]:
            hit = last.get((proto, e["seq"], e["type"]))
            if hit and e["t"] - hit[0] <= COPY_WINDOW_S:
                e["subscriber"] = hit[1]
    for e in evts:
        e.pop("seq", None)
        e.pop("type", None)


def _map_imsis(rec: dict[str, str]) -> set[str]:
    found = {v for v in _split(rec["e212.imsi"]) if v}
    if found:
        return found
    for f in _MAP_RAW_IMSI:
        for raw in _split(rec[f]):
            digits = decode_tbcd(raw)
            if digits and digits.isdigit():
                found.add(digits)
    return found


def _tid_norm(value: str) -> str:
    return value.replace(":", "").lower()


def _map(rec: dict[str, str], ts: float) -> list[dict[str, Any]]:
    comps = [to_int(c) for c in _split(rec["gsm_map.old.Component"])]
    invoke_ids = _split(rec["gsm_old.invokeID"])
    if len(invoke_ids) != len(comps):
        invoke_ids = [None] * len(comps)
    values = [to_int(v) for v in _split(rec["gsm_old.localValue"])]
    # Both transaction ids and the invoke id identify the message: a Continue carries the
    # Begin's otid too, and later Continues of one dialogue carry the same pair of ids.
    tid = AGGREGATOR.join(_tid_norm(v) for v in _split(rec["tcap.tid"])) or None
    otids, dtids = [_tid_norm(v) for v in _split(rec["tcap.otid"])], [_tid_norm(v) for v in _split(rec["tcap.dtid"])]
    # One TCAP message per packet: its transaction ids and IMSI can be trusted. With
    # several bundled messages the fields no longer line up, so the packet is not linked.
    single = len(otids) <= 1 and len(dtids) <= 1 and (otids or dtids)
    dialogue = {"otid": otids[0] if otids else None, "dtid": dtids[0] if dtids else None,
                "imsis": _map_imsis(rec)} if single else None
    calling = _map_node(rec, "sccp.calling.digits", "m3ua.protocol_data_opc", "ip.src")
    called = _map_node(rec, "sccp.called.digits", "m3ua.protocol_data_dpc", "ip.dst")
    invokes = [i for i, c in enumerate(comps) if c == 1]
    op_of = dict(zip(invokes, values)) if len(values) >= len(invokes) and len(values) == len(comps) else {}
    if not op_of and len(invokes) == 1 and len(values) == 1:
        op_of = {invokes[0]: values[0]}
    out = []
    for i, c in enumerate(comps):
        kind = MAP_COMPONENTS.get(c, f"component-{c}")
        if c == 1:
            op = op_of.get(i)
            name = MAP_OPERATIONS.get(op, f"op-{op}") if op is not None else "invoke"
        else:
            name = kind
        out.append({"t": ts, "protocol": "map", "message": name, "request": c == 1, "subscriber": None,
                    "key": ("map", tid, i, invoke_ids[i], c, name) if tid else None, "dialogue": dialogue,
                    "from": calling, "to": called})
    return out


def _map_dialogue_subscribers(evts: list[dict[str, Any]]) -> None:
    """Link MAP messages into TCAP dialogues and give each message the dialogue's IMSI.

    A Begin (otid only) opens a dialogue; a Continue (otid and dtid) joins the dialogue
    its dtid names and binds its own otid to it; an End or Abort (dtid only) joins the
    dialogue its dtid names. The same Begin seen again within 30 s (the other leg of an
    STP) joins the open dialogue, so both copies get the IMSI."""
    tid_dialogue: dict[str, tuple[int, float]] = {}
    dialogue_imsis: dict[int, set[str]] = defaultdict(set)
    packet_dialogue: dict[int, int] = {}
    next_id = 0
    for e in sorted((e for e in evts if e.get("dialogue")), key=lambda e: e["t"]):
        d = e["dialogue"]
        pid = id(d)
        if pid not in packet_dialogue:
            otid, dtid = d["otid"], d["dtid"]
            did = None
            if dtid:
                hit = tid_dialogue.get(dtid)
                if hit and e["t"] - hit[1] <= DIALOGUE_IDLE_S:
                    did = hit[0]
            elif otid:
                hit = tid_dialogue.get(otid)
                if hit and e["t"] - hit[1] <= COPY_WINDOW_S:
                    did = hit[0]
            if did is None:
                did, next_id = next_id, next_id + 1
            for t in (otid, dtid):
                if t:
                    tid_dialogue[t] = (did, e["t"])
            dialogue_imsis[did] |= d["imsis"]
            packet_dialogue[pid] = did
        e["_did"] = packet_dialogue[pid]
        e["imsis"] = d["imsis"]
    for e in evts:
        did = e.pop("_did", None)
        e.pop("dialogue", None)
        own = e.pop("imsis", set())
        if len(own) == 1:
            e["subscriber"] = next(iter(own))
        elif not own and did is not None and len(dialogue_imsis[did]) == 1:
            e["subscriber"] = next(iter(dialogue_imsis[did]))


def _sip(rec: dict[str, str], ts: float) -> list[dict[str, Any]]:
    line = "\t".join(rec.get(f, "") for f in sip.FIELDS)
    out = []
    for m in sip.parse_messages(line):
        if m["sip.Method"]:
            name, is_req = m["sip.Method"], True
        else:
            status = to_int(m["sip.Status-Code"])
            name = f"{status // 100}xx {m['sip.CSeq.method']}" if status is not None else "response"
            is_req = False
        user = m["sip.from.addr"] or None
        out.append({"t": ts, "protocol": "sip", "message": name, "request": is_req,
                    "subscriber": user.split("@")[0].replace("sip:", "").replace("tel:", "") if user else None,
                    "key": ("sip", m["sip.Call-ID"], m["sip.CSeq.seq"], m["sip.CSeq.method"], name),
                    "from": _ip(rec, "ip.src"), "to": _ip(rec, "ip.dst")})
    return out


# ----------------------------------------------------------------- aggregation
COPY_WINDOW_S = 30.0
DIALOGUE_IDLE_S = 300.0


def mark_copies(evts: list[dict[str, Any]]) -> int:
    """Flag every message already seen with the same identity in the last 30 s as a copy."""
    last: dict[tuple, float] = {}
    copies = 0
    for e in evts:
        key = e.get("key")
        if key is None:
            continue
        seen = last.get(key)
        last[key] = e["t"]
        if seen is not None and e["t"] - seen <= COPY_WINDOW_S:
            e["copy"] = True
            copies += 1
    return copies


def summarise(evts: list[dict[str, Any]], interval: float, burst_min: int, storm_min: int,
              limit: int) -> dict[str, Any]:
    if not evts:
        return {"messages": 0, "distinct_messages": 0, "by_message": [], "timeline": [], "bursts": [],
                "subscriber_loops": [], "storms": []}
    evts.sort(key=lambda e: e["t"])
    copies = mark_copies(evts)
    totals = Counter((e["protocol"], e["message"]) for e in evts)
    all_evts, evts = evts, [e for e in evts if not e.get("copy")]
    t0, t1 = evts[0]["t"], evts[-1]["t"]
    n_bins = int((t1 - t0) // interval) + 1
    timeline_interval = interval
    while n_bins / max(1, round(timeline_interval / interval)) > MAX_TIMELINE:
        timeline_interval *= 2
    per_name: dict[tuple[str, str], Counter] = defaultdict(Counter)
    meta: dict[tuple[str, str], dict[str, Any]] = {}
    for e in evts:
        key = (e["protocol"], e["message"])
        per_name[key][int((e["t"] - t0) // interval)] += 1
        meta.setdefault(key, {"request": e["request"], "first_frame": e.get("frame")})
    rows, bursts = [], []
    for key, bins in per_name.items():
        counts = [bins.get(i, 0) for i in range(n_bins)]
        total = sum(counts)
        peak_bin = max(bins, key=lambda i: (bins[i], -i))
        baseline = statistics.median(counts)
        row = {
            "protocol": key[0], "message": key[1], "request": meta[key]["request"], "total": totals[key], "distinct": total,
            "first_frame": meta[key]["first_frame"],
            "peak": bins[peak_bin], "peak_at": iso(t0 + peak_bin * interval),
            "mean_per_s": round(total / max(t1 - t0, interval), 4),
            "active_intervals": len(bins),
        }
        found = _bursts(counts, baseline, burst_min)
        if found:
            row["bursts"] = len(found)
        rows.append(row)
        for start, end, msgs, peak in found:
            bursts.append({"protocol": key[0], "message": key[1], "start": iso(t0 + start * interval),
                           "end": iso(t0 + (end + 1) * interval), "duration_s": round((end - start + 1) * interval, 6),
                           "messages": msgs, "peak_per_interval": peak, "baseline_per_interval": baseline})
    rows.sort(key=lambda r: (-r["distinct"], r["protocol"], r["message"]))
    bursts.sort(key=lambda b: -b["messages"])
    loops = _loops(evts, storm_min)
    timeline = _timeline(evts, t0, timeline_interval)
    out = {
        "messages": len(all_evts), "distinct_messages": len(evts), "copies": copies,
        "attributed_messages": sum(1 for e in evts if e["subscriber"]),
        "first": iso(t0), "last": iso(t1), "duration_s": round(t1 - t0, 6),
        "by_message": rows[:limit], "bursts": bursts[:limit], "subscriber_loops": loops[:MAX_SUBSCRIBERS],
        "timeline": timeline, "storms": _storm_lines(bursts, loops, interval),
    }
    if timeline_interval != interval:
        out["timeline_interval_s"] = timeline_interval
    return out


def _bursts(counts: list[int], baseline: float, burst_min: int) -> list[tuple[int, int, int, int]]:
    threshold = max(burst_min, BURST_FACTOR * baseline)
    found = []
    start = None
    for i, c in enumerate(counts + [0]):
        hot = c >= threshold and c > baseline
        if hot and start is None:
            start = i
        elif not hot and start is not None:
            seg = counts[start:i]
            found.append((start, i - 1, sum(seg), max(seg)))
            start = None
    return found


MAX_NODES = 5


def _loops(evts: list[dict[str, Any]], storm_min: int) -> list[dict[str, Any]]:
    """Subscribers repeating one request: count, rate, how regular the repeats are, and
    the nodes that sent and received them (`from_nodes`, `to_nodes`: the SCCP global
    title for MAP, Origin-Host and Destination-Host or realm for Diameter, else the IP
    address). When the repeats switch back and forth between exactly two nodes (at least
    every other repeat, such as a location ping-pong between two VLRs), `alternating`
    names the side: from, to, or both. A Diameter realm and the subscriber's MGT (labelled
    `MGT`) are not nodes for this."""
    times: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    frames: dict[tuple[str, str, str], list[int | None]] = defaultdict(list)
    nodes: dict[tuple[str, str, str], list[tuple[str | None, str | None]]] = defaultdict(list)
    for e in evts:
        if e["request"] and e["subscriber"]:
            k = (e["subscriber"], e["protocol"], e["message"])
            times[k].append(e["t"])
            frames[k].append(e.get("frame"))
            nodes[k].append((e.get("from"), e.get("to")))
    rows = []
    for (who, proto, msg), ts in times.items():
        fr = frames[(who, proto, msg)]
        if len(ts) < max(storm_min, 2):  # a loop is at least two repeats, whatever storm_min says
            continue
        sides = {}
        for side, idx in (("from", 0), ("to", 1)):
            seq = [_mgt_label(n[idx], who) for n in nodes[(who, proto, msg)] if n[idx]]
            sides[side] = (Counter(seq), seq)
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        median = statistics.median(gaps)
        spread = statistics.pstdev(gaps) / statistics.mean(gaps) if statistics.mean(gaps) > 0 else 0.0
        rows.append({
            "subscriber": who, "protocol": proto, "message": msg, "count": len(ts), "first": iso(ts[0]),
            "last": iso(ts[-1]), "span_s": round(ts[-1] - ts[0], 3), "median_gap_s": round(median, 3),
            "min_gap_s": round(min(gaps), 3), "max_gap_s": round(max(gaps), 3), "regular": spread < 0.5,
            "first_frame": fr[0], "last_frame": fr[-1],
        })
        alternating = []
        for side, (counts, seq) in sides.items():
            if counts:
                rows[-1][f"{side}_nodes"] = [{"node": n, "count": c} for n, c in counts.most_common(MAX_NODES)]
            switches = sum(1 for a, b in zip(seq, seq[1:]) if a != b)
            # A Diameter request without Destination-Host names only the realm, and a MAP
            # request routed on the subscriber's MGT names the HLR by the IMSI: neither is
            # a node of its own, so a host and its realm (or an HLR's GT and the MGT) in
            # turn are not a ping-pong.
            concrete = not any(n.startswith(("realm ", "MGT ")) for n in counts)
            if len(counts) == 2 and concrete and switches * 2 >= len(seq) - 1:
                alternating.append(side)
        if alternating:
            rows[-1]["alternating"] = " and ".join(alternating)
    rows.sort(key=lambda r: (-r["count"], r["subscriber"], r["message"]))
    return rows


def _mgt_label(node: str, imsi: str) -> str:
    """'GT <digits>' becomes 'MGT <digits>' when the digits are the subscriber's E.214
    mobile global title: the HLR's country and network code followed by the start of the
    MSIN (at least six digits of it), as a request routed on the IMSI is addressed."""
    if not node.startswith("GT ") or not imsi.isdigit():
        return node
    gt = node[3:]
    for mnc_len in (2, 3):
        msin = imsi[3 + mnc_len:]
        for k in range(len(msin), 5, -1):
            if len(gt) > k and gt.endswith(msin[:k]):
                return f"MGT {gt}"
    return node


def _timeline(evts: list[dict[str, Any]], t0: float, step: float) -> list[dict[str, Any]]:
    bins: dict[int, Counter] = defaultdict(Counter)
    for e in evts:
        bins[int((e["t"] - t0) // step)][e["message"]] += 1
    rows = []
    for i in sorted(bins)[:MAX_TIMELINE]:
        c = bins[i]
        rows.append({"t": iso(t0 + i * step), "total": sum(c.values()), "top": dict(c.most_common(5))})
    return rows


def _storm_lines(bursts: list[dict[str, Any]], loops: list[dict[str, Any]], interval: float) -> list[str]:
    lines = []
    for b in bursts[:5]:
        lines.append(f'{b["messages"]} {b["message"]} in {b["duration_s"]} s from {b["start"]} '
                     f'(peak {b["peak_per_interval"]} per {interval} s, usually {b["baseline_per_interval"]})')
    for lp in loops[:5]:
        how = f'about every {lp["median_gap_s"]} s' if lp["regular"] else f'{lp["min_gap_s"]} to {lp["max_gap_s"]} s apart'
        lines.append(f'{lp["count"]} {lp["message"]} for {lp["subscriber"]} over {lp["span_s"]} s, {how}{_route(lp)}')
    return lines


def _route(lp: dict[str, Any]) -> str:
    """', from A (66) and B (65), alternating, to C' for a loop row."""
    out = ""
    for side in ("from", "to"):
        found = lp.get(f"{side}_nodes")
        if not found:
            continue
        if len(found) == 1:
            out += f", {side} {found[0]['node']}"
        else:
            named = [f"{n['node']} ({n['count']})" for n in found[:3]]
            listed = ", ".join(named[:-1]) + f" and {named[-1]}" if len(found) <= 3 else ", ".join(named) + " and others"
            out += f", {side} {listed}"
            if side in lp.get("alternating", ""):
                out += ", alternating"
    return out
