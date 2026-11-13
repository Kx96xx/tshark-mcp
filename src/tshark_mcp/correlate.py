"""correlate_captures: one traffic captured at two points (A upstream, B downstream), packet by packet.

A packet's identity must survive the path between the two points, NAT included, so it leaves
the addresses and ports out: IP protocol, IP ID and IP total length, plus the raw TCP sequence and
acknowledgement numbers (or the UDP length). A key seen more than once on one side is ambiguous
(IP ID reuse, retransmissions) and is counted, not matched.

From the matched pairs: the clock offset between the two capture points (median of B minus A),
the delay variation around it, address and port rewrites (NAT), TTL drops (hops between the
points) and DSCP changes. Packets of A that fall inside B's capture span (after the offset) but
never reach B are lost between the points; packets only in B entered the path between them or
came another way.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Any

FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ip.id", "ip.len", "ip.proto", "ip.ttl",
          "ip.dsfield.dscp", "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "udp.srcport",
          "udp.dstport", "udp.length"]
DISPLAY_FILTER = "ip && !icmp"


def _int(v: str) -> int | None:
    try:
        return int(v, 0) if v else None
    except ValueError:
        return None


def parse(lines: list[list[str]]) -> list[dict[str, Any]]:
    """Rows of FIELDS (first value of each, tunnels keep the outer header) as packets."""
    out = []
    for cols in lines:
        v = dict(zip(FIELDS, (c.split(",")[0] for c in cols)))
        try:
            t = float(v["frame.time_epoch"])
        except (TypeError, ValueError):
            continue
        proto = _int(v["ip.proto"])
        sport = v["tcp.srcport"] or v["udp.srcport"]
        dport = v["tcp.dstport"] or v["udp.dstport"]
        if proto == 6:
            l4 = (v["tcp.seq_raw"], v["tcp.ack_raw"])
        elif proto == 17:
            l4 = (v["udp.length"],)
        else:
            l4 = ()
        out.append({"frame": _int(v["frame.number"]), "t": t, "src": v["ip.src"], "dst": v["ip.dst"],
                    "sport": sport, "dport": dport, "proto": proto, "ttl": _int(v["ip.ttl"]),
                    "dscp": _int(v["ip.dsfield.dscp"]),
                    "key": (proto, v["ip.id"], v["ip.len"], *l4)})
    return out


def _flow(p: dict[str, Any]) -> str:
    name = {6: "tcp", 17: "udp"}.get(p["proto"], f"ip/{p['proto']}")
    a = f"{p['src']}:{p['sport']}" if p["sport"] else p["src"]
    b = f"{p['dst']}:{p['dport']}" if p["dport"] else p["dst"]
    return f"{name} {a} > {b}"


def _pct(xs: list[float], q: float) -> float:
    s = sorted(xs)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))]


def correlate(a: list[dict[str, Any]], b: list[dict[str, Any]], limit: int = 20) -> dict[str, Any]:
    by_a: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    by_b: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for p in a:
        by_a[p["key"]].append(p)
    for p in b:
        by_b[p["key"]].append(p)
    ambiguous = sum(len(v) for v in by_a.values() if len(v) > 1) + sum(len(v) for v in by_b.values() if len(v) > 1)
    pairs = [(by_a[k][0], by_b[k][0]) for k in by_a if len(by_a[k]) == 1 and len(by_b.get(k, ())) == 1]
    out: dict[str, Any] = {"summary": {"packets_a": len(a), "packets_b": len(b), "matched": len(pairs),
                                       "ambiguous": ambiguous}}
    if not pairs:
        out["verdict"] = ("No packet could be matched between the two captures: they do not hold the same "
                          "traffic, or every key is ambiguous.")
        out["summary"].update(only_a=len(a), only_b=len(b))
        return out
    deltas = [pb["t"] - pa["t"] for pa, pb in pairs]
    offset = statistics.median(deltas)
    jitter = [abs(d - offset) * 1000 for d in deltas]
    out["summary"].update(clock_offset_ms=round(offset * 1000, 3), delay_variation_ms={
        "p50": round(_pct(jitter, 0.5), 3), "p95": round(_pct(jitter, 0.95), 3), "max": round(max(jitter), 3)})
    # A packets that B should have seen: inside B's span once the offset is applied
    b_lo, b_hi = min(p["t"] for p in b), max(p["t"] for p in b)
    matched_a = {id(pa) for pa, _ in pairs}
    matched_b = {id(pb) for _, pb in pairs}
    unique_a = [p for p in a if len(by_a[p["key"]]) == 1]
    lost = [p for p in unique_a if id(p) not in matched_a and b_lo <= p["t"] + offset <= b_hi]
    outside = sum(1 for p in unique_a if id(p) not in matched_a and not b_lo <= p["t"] + offset <= b_hi)
    only_b = [p for p in b if len(by_b[p["key"]]) == 1 and id(p) not in matched_b]
    out["summary"].update(lost_between=len(lost), only_a_outside_b_span=outside, only_b=len(only_b))
    per_flow_total = Counter(_flow(p) for p in unique_a if b_lo <= p["t"] + offset <= b_hi)
    per_flow_lost: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for p in lost:
        per_flow_lost[_flow(p)].append(p)
    out["lost_flows"] = sorted(({"flow": f, "lost": len(ps), "of": per_flow_total[f],
                                 "lost_pct": round(100.0 * len(ps) / per_flow_total[f], 1),
                                 "first_frame_a": ps[0]["frame"]} for f, ps in per_flow_lost.items()),
                               key=lambda r: (-r["lost"], r["flow"]))[:limit]
    nat: Counter = Counter()
    ttl: Counter = Counter()
    dscp: Counter = Counter()
    for pa, pb in pairs:
        ea = (pa["src"], pa["sport"], pa["dst"], pa["dport"])
        eb = (pb["src"], pb["sport"], pb["dst"], pb["dport"])
        if ea != eb:
            nat[(_flow(pa), _flow(pb))] += 1
        if pa["ttl"] is not None and pb["ttl"] is not None:
            ttl[pa["ttl"] - pb["ttl"]] += 1
        if pa["dscp"] != pb["dscp"]:
            dscp[(pa["dscp"], pb["dscp"])] += 1
    out["rewrites"] = [{"a": fa, "b": fb, "packets": n} for (fa, fb), n in nat.most_common(limit)]
    out["ttl_drop"] = {str(k): v for k, v in sorted(ttl.items())}
    out["dscp_changes"] = [{"a": x, "b": y, "packets": n} for (x, y), n in dscp.most_common(limit)]
    out["only_b_flows"] = [{"flow": f, "packets": n} for f, n in Counter(_flow(p) for p in only_b).most_common(limit)]
    issues = []
    if lost:
        worst = out["lost_flows"][0]
        issues.append(f"{len(lost)} packet(s) seen at A never reached B (worst: {worst['flow']}, {worst['lost']} of "
                      f"{worst['of']}, first at A frame {worst['first_frame_a']})")
    if nat:
        issues.append(f"addresses or ports are rewritten between the points ({len(nat)} mapping(s)): NAT")
    if dscp:
        (x, y), n = dscp.most_common(1)[0]
        issues.append(f"DSCP changed on {sum(dscp.values())} packet(s) (most often {x} to {y})")
    if out["summary"]["delay_variation_ms"]["p95"] > 50:
        issues.append(f"delay between the points varies by {out['summary']['delay_variation_ms']['p95']} ms at p95: "
                      "queueing on the path")
    out["issues"] = issues
    hops = ", ".join(f"{k} hop(s)" for k in out["ttl_drop"]) or "unknown"
    out["verdict"] = (f"Matched {len(pairs)} packet(s); B's clock is {round(offset * 1000, 1)} ms from A's, "
                      f"{hops} between the points. " + ("; ".join(issues) + "." if issues else
                                                         "Nothing seen at A went missing before B."))
    return out
