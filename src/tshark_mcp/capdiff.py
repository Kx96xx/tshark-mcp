"""diff_captures: what changed between a capture from before and one from after a change.

The server runs the same tool on both captures for each section (destinations, dns, tls,
http, tcp); the functions here reduce each result to one metrics dict per key (a server, a
DNS name or resolver, an SNI, an HTTP endpoint), join the two sides by key and label each
key appeared, vanished, worse, better or same with a sentence. Counts are also given per
minute of capture, because the two captures rarely have the same length. Separate from
compare_captures, which aligns one procedure's message ladder.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Callable

SECTIONS = ("destinations", "dns", "tls", "http", "tcp")
CHANGES = ("worse", "vanished", "appeared", "better", "same")

# A change smaller than these is "same".
SHARE_STEP = 0.10        # success / answered share, absolute
ERROR_SHARE_STEP = 0.05  # 5xx share, absolute
RETRANS_STEP = 0.01      # retransmitted share of data segments, absolute
TIME_FACTOR = 1.5        # latency must grow or shrink by half ...
TIME_FLOOR_MS = 20.0     # ... and by at least this much
TLS_ORDER = {"SSL 3.0": 0, "TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4}


def _most(values: list[Any]) -> Any:
    values = [v for v in values if v is not None]
    return Counter(values).most_common(1)[0][0] if values else None


def _share(part: float, whole: float) -> float | None:
    return round(part / whole, 4) if whole else None


def _median(values: list[float]) -> float | None:
    values = sorted(v for v in values if isinstance(v, (int, float)))
    if not values:
        return None
    mid = len(values) // 2
    return round(values[mid] if len(values) % 2 else (values[mid - 1] + values[mid]) / 2, 3)


# ------------------------------------------------------------------ per-section metrics
def destinations(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out = {}
    for d in result.get("destinations") or []:
        out[str(d["server"])] = {
            "attempts": d.get("attempts") or 0, "connected": d.get("connected") or 0,
            "success_rate": d.get("success_rate"), "connect_ms_p50": d.get("connect_ms_p50"),
            "outcome": _failed_outcome(d), "frame": d.get("first_frame"),
        }
    return out


def _failed_outcome(d: dict[str, Any]) -> str:
    if (d.get("connected") or 0) >= (d.get("attempts") or 0):
        return "connected"
    for k in ("filtered", "refused", "prohibited", "unreachable", "reset_during_handshake", "handshake_incomplete"):
        if d.get(k):
            return k
    return "failed"


def dns(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out = {}
    groups: dict[str, list[dict[str, Any]]] = {}
    for t in result.get("transactions") or []:
        if t.get("name"):
            groups.setdefault(str(t["name"]).lower(), []).append(t)
    for name, rows in groups.items():
        answered = [t for t in rows if not t.get("unanswered")]
        out[f"name {name}"] = {"queries": len(rows), "answered_share": _share(len(answered), len(rows)),
                               "rcode": _most([t.get("rcode_name") for t in answered]),
                               "rtt_ms_p50": _median([t.get("rtt_ms") for t in answered]),
                               "frame": rows[0].get("frame")}
    for s in result.get("servers") or []:
        q = s.get("queries") or 0
        out[f"resolver {s['server']}"] = {"queries": q, "answered_share": _share(s.get("answered") or 0, q),
                                          "rtt_ms_p50": (s.get("rtt_ms") or {}).get("p50")}
    return out


def tls(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for c in result.get("connections") or []:
        key = c.get("sni") or str(c.get("server"))
        groups.setdefault(key, []).append(c)
    out = {}
    for key, rows in groups.items():
        est = [r for r in rows if r.get("outcome") == "established"]
        expiry = [((r.get("certificate") or {}).get("not_after")) for r in rows]
        out[key] = {"handshakes": len(rows), "established_share": _share(len(est), len(rows)),
                    "outcome": _most([r.get("outcome") for r in rows]),
                    "version": _most([(r.get("chosen") or {}).get("version") for r in rows]),
                    "cipher_suite": _most([(r.get("chosen") or {}).get("cipher_suite") for r in rows]),
                    "cert_not_after": _most(expiry), "frame": rows[0].get("frame")}
    return out


def http(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out = {}
    for e in result.get("endpoints") or []:
        n = e.get("count") or 0
        status = e.get("status") or {}
        times = e.get("response_ms") or {}
        out[f"{e.get('method')} {e.get('host') or ''}{e.get('uri') or ''}"] = {
            "requests": n, "share_5xx": _share(status.get("5xx") or 0, n), "share_4xx": _share(status.get("4xx") or 0, n),
            "status": max(status, key=status.get) if status else None,
            "p50_ms": times.get("p50"), "p99_ms": times.get("p99"), "frame": e.get("first_frame"),
        }
    return out


def tcp(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for s in result.get("streams") or []:
        groups.setdefault(str(s.get("server")), []).append(s)
    out = {}
    for server, rows in groups.items():
        segs = retrans = zero = 0
        for r in rows:
            for k in ("client_to_server", "server_to_client"):
                d = r.get(k) or {}
                segs += d.get("data_segments") or 0
                retrans += d.get("retransmissions") or 0
                zero += d.get("zero_windows") or 0
        hs = [r.get("handshake") or {} for r in rows]
        out[server] = {"streams": len(rows), "data_segments": segs, "retransmission_share": _share(retrans, segs),
                       "rtt_ms_p50": _median([h.get("rtt_ms") for h in hs]), "zero_windows": zero,
                       "resets": sum(len(r.get("resets") or []) for r in rows),
                       "mss": _most([h.get("server_mss") for h in hs]), "frame": rows[0].get("frame") or None}
    return out


METRICS: dict[str, Callable[[dict[str, Any]], dict[str, dict[str, Any]]]] = {
    "destinations": destinations, "dns": dns, "tls": tls, "http": http, "tcp": tcp,
}
VOLUME = {"destinations": "attempts", "dns": "queries", "tls": "handshakes", "http": "requests", "tcp": "streams"}


# ------------------------------------------------------------------ judging one key
def _slower(a: Any, b: Any) -> int:
    """+1 when ``b`` is clearly slower than ``a``, -1 clearly faster, 0 otherwise."""
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        return 0
    if b > a * TIME_FACTOR and b - a >= TIME_FLOOR_MS:
        return 1
    if a > b * TIME_FACTOR and a - b >= TIME_FLOOR_MS:
        return -1
    return 0


def _lower(a: Any, b: Any, step: float) -> int:
    """+1 when share ``b`` is lower than ``a`` by at least ``step`` (worse for a success share)."""
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        return 0
    return 1 if a - b >= step else -1 if b - a >= step else 0


def _pct(v: Any) -> str:
    return f"{round(100 * v, 1)}%" if isinstance(v, (int, float)) else "n/a"


def judge(section: str, key: str, a: dict[str, Any], b: dict[str, Any]) -> tuple[str, float, list[str]]:
    """(change, score, reasons) for one key present in both captures."""
    reasons: list[str] = []
    score = 0.0
    worse = better = 0

    def note(sign: int, weight: float, text_worse: str, text_better: str) -> None:
        nonlocal worse, better, score
        if sign > 0:
            worse += 1
            score += weight
            reasons.append(text_worse)
        elif sign < 0:
            better += 1
            score += weight / 2
            reasons.append(text_better)

    if section == "destinations":
        s = _lower(a["success_rate"], b["success_rate"], SHARE_STEP)
        note(s, 10 * abs((a["success_rate"] or 0) - (b["success_rate"] or 0)),
             f"went from {_pct(a['success_rate'])} connected to {_pct(b['success_rate'])} ({b['outcome']})",
             f"went from {_pct(a['success_rate'])} connected to {_pct(b['success_rate'])}")
        t = _slower(a["connect_ms_p50"], b["connect_ms_p50"])
        note(t, 1, f"connect time p50 went from {a['connect_ms_p50']} to {b['connect_ms_p50']} ms",
             f"connect time p50 went from {a['connect_ms_p50']} to {b['connect_ms_p50']} ms")
    elif section == "dns":
        s = _lower(a.get("answered_share"), b.get("answered_share"), SHARE_STEP)
        note(s, 10 * abs((a.get("answered_share") or 0) - (b.get("answered_share") or 0)),
             f"answered {_pct(a.get('answered_share'))} of queries before, {_pct(b.get('answered_share'))} after",
             f"answered {_pct(a.get('answered_share'))} of queries before, {_pct(b.get('answered_share'))} after")
        if a.get("rcode") != b.get("rcode") and a.get("rcode") and b.get("rcode"):
            note(1 if b["rcode"] != "NOERROR" else -1, 3, f"answer went from {a['rcode']} to {b['rcode']}",
                 f"answer went from {a['rcode']} to {b['rcode']}")
        t = _slower(a.get("rtt_ms_p50"), b.get("rtt_ms_p50"))
        note(t, 1, f"answer time p50 went from {a.get('rtt_ms_p50')} to {b.get('rtt_ms_p50')} ms",
             f"answer time p50 went from {a.get('rtt_ms_p50')} to {b.get('rtt_ms_p50')} ms")
    elif section == "tls":
        s = _lower(a["established_share"], b["established_share"], SHARE_STEP)
        note(s, 10 * abs((a["established_share"] or 0) - (b["established_share"] or 0)),
             f"handshakes established {_pct(a['established_share'])} before, {_pct(b['established_share'])} after "
             f"(now mostly {b['outcome']})",
             f"handshakes established {_pct(a['established_share'])} before, {_pct(b['established_share'])} after")
        va, vb = TLS_ORDER.get(a["version"]), TLS_ORDER.get(b["version"])
        if va is not None and vb is not None and va != vb:
            note(1 if vb < va else -1, 3, f"negotiates {b['version']} instead of {a['version']}",
                 f"negotiates {b['version']} instead of {a['version']}")
        elif a["cipher_suite"] and b["cipher_suite"] and a["cipher_suite"] != b["cipher_suite"]:
            reasons.append(f"cipher suite changed from {a['cipher_suite']} to {b['cipher_suite']}")
            score += 0.5
        if a["cert_not_after"] and b["cert_not_after"] and a["cert_not_after"] != b["cert_not_after"]:
            reasons.append(f"certificate expiry changed from {a['cert_not_after']} to {b['cert_not_after']}")
            score += 0.5
    elif section == "http":
        e = _lower(b["share_5xx"], a["share_5xx"], ERROR_SHARE_STEP)  # a higher 5xx share after is worse
        note(e, 10 * abs((a["share_5xx"] or 0) - (b["share_5xx"] or 0)),
             f"5xx share went from {_pct(a['share_5xx'])} to {_pct(b['share_5xx'])}",
             f"5xx share went from {_pct(a['share_5xx'])} to {_pct(b['share_5xx'])}")
        t = _slower(a["p99_ms"], b["p99_ms"])
        note(t, 1, f"p99 response went from {a['p99_ms']} to {b['p99_ms']} ms",
             f"p99 response went from {a['p99_ms']} to {b['p99_ms']} ms")
    elif section == "tcp":
        r = _lower(b["retransmission_share"], a["retransmission_share"], RETRANS_STEP)
        note(r, 20 * abs((a["retransmission_share"] or 0) - (b["retransmission_share"] or 0)),
             f"retransmitted {_pct(a['retransmission_share'])} of data segments before, "
             f"{_pct(b['retransmission_share'])} after",
             f"retransmitted {_pct(a['retransmission_share'])} of data segments before, "
             f"{_pct(b['retransmission_share'])} after")
        t = _slower(a["rtt_ms_p50"], b["rtt_ms_p50"])
        note(t, 1, f"handshake RTT p50 went from {a['rtt_ms_p50']} to {b['rtt_ms_p50']} ms",
             f"handshake RTT p50 went from {a['rtt_ms_p50']} to {b['rtt_ms_p50']} ms")
        for k, word in (("zero_windows", "zero windows"), ("resets", "resets")):
            if (a[k] == 0) != (b[k] == 0):
                note(1 if b[k] else -1, 1, f"{word}: {a[k]} before, {b[k]} after", f"{word}: {a[k]} before, {b[k]} after")
        if a["mss"] and b["mss"] and a["mss"] != b["mss"]:
            reasons.append(f"server MSS changed from {a['mss']} to {b['mss']}")
            score += 0.5
    change = "worse" if worse else "better" if better else "same"
    return change, round(score, 3), reasons


def join(section: str, a: dict[str, dict[str, Any]], b: dict[str, dict[str, Any]], minutes_a: float | None,
         minutes_b: float | None) -> list[dict[str, Any]]:
    """One row per key of either capture, with its change label, a sentence and a score for ranking."""
    rows = []
    vol = VOLUME[section]
    for key in sorted(set(a) | set(b)):
        ma, mb = a.get(key), b.get(key)
        row: dict[str, Any] = {"section": section, "key": key}
        if ma is None or mb is None:
            m = mb if ma is None else ma
            row["change"] = "appeared" if ma is None else "vanished"
            per_min = _per_min(m.get(vol), minutes_b if ma is None else minutes_a)
            row["sentence"] = (f"{section}: {key} {'appears only after' if ma is None else 'is gone after'} the change "
                               f"({m.get(vol)} {vol}" + (f", {per_min} per minute" if per_min is not None else "") + ")")
            row["score"] = float(per_min if per_min is not None else (m.get(vol) or 0))
        else:
            change, score, reasons = judge(section, key, ma, mb)
            row["change"] = change
            row["score"] = score
            if reasons:
                row["sentence"] = f"{section}: {key} " + "; ".join(reasons)
            ra, rb = _per_min(ma.get(vol), minutes_a), _per_min(mb.get(vol), minutes_b)
            if ra is not None and rb is not None:
                row["rate_per_min"] = {"a": ra, "b": rb}
        if ma is not None:
            row["a"] = {k: v for k, v in ma.items() if v is not None}
        if mb is not None:
            row["b"] = {k: v for k, v in mb.items() if v is not None}
        if ma is not None and mb is not None:
            row["delta"] = {k: round(mb[k] - ma[k], 4) for k in ma
                            if isinstance(ma.get(k), (int, float)) and isinstance(mb.get(k), (int, float))
                            and not isinstance(ma.get(k), bool) and k != "frame" and mb[k] != ma[k]}
        rows.append(row)
    return rows


def _per_min(count: Any, minutes: float | None) -> float | None:
    if not isinstance(count, (int, float)) or not minutes:
        return None
    return round(count / minutes, 3)


def rank(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order = {c: i for i, c in enumerate(CHANGES)}
    return sorted(rows, key=lambda r: (order[r["change"]], -r["score"], r["section"], r["key"]))
