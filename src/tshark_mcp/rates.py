"""Message rates over time and storm detection, from one ``-T fields`` pass.

Every Diameter, GTPv2-C, SIP and MAP message is reduced to (time, protocol,
message name, request or answer, subscriber), then counted per interval. A
burst is a run of intervals where one message type runs at three times its
usual rate or more (and at least ``burst_min`` per interval); a subscriber loop
is one subscriber sending the same request again and again, reported with the
interval between repeats. A message seen more than once (on both legs of a relay
or proxy, or retransmitted) is one distinct message: the Diameter End-to-End id,
the GTP sequence number, the TCAP transaction id or the SIP Call-ID and CSeq
identify it, and bursts and loops count distinct messages.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Any

from . import diameter, gtp, sip
from .fields import iso, parse_time, split_fields_line, to_int
from .sigtran import MAP_OPERATIONS

PROTOCOLS = ("auto", "diameter", "gtpv2", "sip", "map")
FILTERS = {"diameter": "diameter", "gtpv2": "gtpv2", "sip": "sip", "map": "gsm_map"}
AGGREGATOR = "|"

_DIAMETER = ["diameter.cmd.code", "diameter.flags.request", "diameter.User-Name", "diameter.endtoendid"]
_GTP = ["gtpv2.message_type", "e212.imsi", "gtpv2.seq"]
_MAP = ["gsm_map.old.Component", "gsm_old.localValue", "tcap.tid"]
_SIP = [f for f in sip.FIELDS if f not in ("frame.number", "frame.time_epoch", "ip.src", "ip.dst")]
FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", *_DIAMETER, *_GTP, *_MAP,
          *[f for f in _SIP if f not in _DIAMETER + _GTP + _MAP]]

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
        if rec["diameter.cmd.code"] and protocol in ("auto", "diameter"):
            out.extend(_diameter(rec, ts))
        elif rec["gtpv2.message_type"] and protocol in ("auto", "gtpv2"):
            out.extend(_gtpv2(rec, ts))
        elif rec["gsm_map.old.Component"] and protocol in ("auto", "map"):
            out.extend(_map(rec, ts))
        elif rec["sip.Call-ID"] and protocol in ("auto", "sip"):
            out.extend(_sip(rec, ts))
    return out


def _split(value: str) -> list[str]:
    return value.split(AGGREGATOR) if value else []


def _diameter(rec: dict[str, str], ts: float) -> list[dict[str, Any]]:
    codes, flags = _split(rec["diameter.cmd.code"]), _split(rec["diameter.flags.request"])
    users = _split(rec["diameter.User-Name"])
    e2e = _split(rec["diameter.endtoendid"])
    requests = [f in ("1", "True") for f in flags] if len(flags) == len(codes) else [None] * len(codes)
    # User-Name is in requests only; it can be matched to a message when every request of the packet has one.
    req_idx = [i for i, r in enumerate(requests) if r]
    user_of = dict(zip(req_idx, users)) if len(users) == len(req_idx) else {}
    out = []
    for i, code in enumerate(codes):
        c = to_int(code)
        if c is None:
            continue
        is_req = requests[i]
        out.append({"t": ts, "protocol": "diameter", "message": diameter.command_name(c, bool(is_req)),
                    "request": is_req, "subscriber": user_of.get(i),
                    "key": ("diameter", e2e[i], c, is_req) if len(e2e) == len(codes) else None})
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
                    "key": ("gtpv2", seqs[i], m) if len(seqs) == len(types) else None})
    return out


def _map(rec: dict[str, str], ts: float) -> list[dict[str, Any]]:
    comps = [to_int(c) for c in _split(rec["gsm_map.old.Component"])]
    values = [to_int(v) for v in _split(rec["gsm_old.localValue"])]
    tid = rec["tcap.tid"].split(AGGREGATOR)[0] or None
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
                    "key": ("map", tid, i, c, name) if tid else None})
    return out


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
                    "key": ("sip", m["sip.Call-ID"], m["sip.CSeq.seq"], m["sip.CSeq.method"], name)})
    return out


# ----------------------------------------------------------------- aggregation
COPY_WINDOW_S = 30.0


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
        meta.setdefault(key, {"request": e["request"]})
    rows, bursts = [], []
    for key, bins in per_name.items():
        counts = [bins.get(i, 0) for i in range(n_bins)]
        total = sum(counts)
        peak_bin = max(bins, key=lambda i: (bins[i], -i))
        baseline = statistics.median(counts)
        row = {
            "protocol": key[0], "message": key[1], "request": meta[key]["request"], "total": totals[key], "distinct": total,
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


def _loops(evts: list[dict[str, Any]], storm_min: int) -> list[dict[str, Any]]:
    """Subscribers repeating one request: count, rate and how regular the repeats are."""
    times: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for e in evts:
        if e["request"] and e["subscriber"]:
            times[(e["subscriber"], e["protocol"], e["message"])].append(e["t"])
    rows = []
    for (who, proto, msg), ts in times.items():
        if len(ts) < storm_min:
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        median = statistics.median(gaps)
        spread = statistics.pstdev(gaps) / statistics.mean(gaps) if statistics.mean(gaps) > 0 else 0.0
        rows.append({
            "subscriber": who, "protocol": proto, "message": msg, "count": len(ts), "first": iso(ts[0]),
            "last": iso(ts[-1]), "span_s": round(ts[-1] - ts[0], 3), "median_gap_s": round(median, 3),
            "min_gap_s": round(min(gaps), 3), "max_gap_s": round(max(gaps), 3), "regular": spread < 0.5,
        })
    rows.sort(key=lambda r: (-r["count"], r["subscriber"], r["message"]))
    return rows


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
        lines.append(f'{lp["subscriber"]} sent {lp["count"]} {lp["message"]} over {lp["span_s"]} s, {how}')
    return lines
