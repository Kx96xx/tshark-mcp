"""DNS queries paired with their responses, from ``-T fields`` output.

``dns.time`` and ``dns.response_to`` exist only on a response that arrived, so
a query that was never answered is invisible to them. Here every query is kept
and matched to a response by transport, client and server address and port,
DNS id and question name. On top of the pairing the module reports what DNS
debugging usually needs: unanswered queries, rcodes, retransmissions of the
same query, retries of the same name with a new id, latency percentiles per
server, truncated (TC) answers and whether the client fell back to TCP.

A capture taken on several interfaces (or of a GTP-U tunnel both tunnelled and
decapsulated) holds the same packet more than once. Copies carry the same addresses,
ports, DNS id and flags and arrive within a few milliseconds; they are
counted once (``duplicate_copies``) rather than as retransmissions.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .fields import compact, iso, parse_time, split_fields_line, to_int

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.protocols",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport",
    "dns.id", "dns.flags.response", "dns.flags.rcode", "dns.flags.truncated",
    "dns.qry.name", "dns.qry.type", "dns.count.answers",
    "dns.a", "dns.aaaa", "dns.cname",
]
AGGREGATOR = "|"

# mDNS and LLMNR reuse the DNS dissector; they are multicast name lookups, not resolver traffic.
# An ICMP error quotes the packet it is about, so the quoted DNS query is read apart (icmp_errors).
BASE_FILTER = "dns && !mdns && !llmnr"

RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN",
    7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE", 16: "BADVERS",
}
QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
    35: "NAPTR", 39: "DNAME", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 52: "TLSA",
    64: "SVCB", 65: "HTTPS", 99: "SPF", 252: "AXFR", 255: "ANY", 257: "CAA",
}

COPY_WINDOW = 0.05     # seconds: the same packet seen again this soon is a capture copy
RETRY_WINDOW = 10.0    # seconds: a new query for the same name this soon after a failed one is a retry
PARALLEL_WINDOW = 0.2  # seconds: queries this close together went out in parallel (to several resolvers), not as a retry
SLOW_MS = 1000.0       # an answer slower than this is called slow
END_GRACE = 2.0        # seconds: a query this close to the end of the capture may simply have been cut off
ISSUE_SHARE = 0.05     # unanswered or failed share that is worth an issue


def display_filter() -> str:
    """DNS over UDP and TCP, plus the ICMP errors that quote a DNS packet."""
    return BASE_FILTER


def _truthy(value: str) -> bool:
    return value in ("1", "True", "true")


def _last(values: list[str]) -> str:
    return values[-1] if values else ""


def _nth(values: list[str], n: int) -> str:
    return values[n] if 0 <= n < len(values) else ""


def qtype_name(code: int | None) -> str | None:
    if code is None:
        return None
    return QTYPES.get(code, f"TYPE{code}")


def rcode_name(code: int | None) -> str | None:
    if code is None:
        return None
    return RCODES.get(code, f"RCODE{code}")


def matches_name(qname: str, wanted: str) -> bool:
    """Case-insensitive match of the name itself or any name under it."""
    q = qname.lower().rstrip(".")
    w = wanted.lower().rstrip(".")
    return q == w or q.endswith("." + w)


def parse(stdout: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(DNS messages in capture order, ICMP errors about DNS packets)."""
    messages: list[dict[str, Any]] = []
    icmp: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(FIELDS):
            continue
        raw = {k: (v.split(AGGREGATOR) if v else []) for k, v in zip(FIELDS, cols)}
        layers = [p for p in _nth(raw["frame.protocols"], 0).split(":") if p]
        ts = parse_time(_nth(raw["frame.time_epoch"], 0))
        frame = to_int(_nth(raw["frame.number"], 0))
        if "icmp" in layers or "icmpv6" in layers:
            # The outer addresses are the router or server that sent the error; the quoted
            # packet's addresses are the query's. tshark lists the outer ones first.
            src = _nth(raw["ip.src"], 0) or _nth(raw["ipv6.src"], 0)
            q_dst = _last(raw["ip.dst"]) if raw["ip.dst"] else _last(raw["ipv6.dst"])
            icmp.append({"frame": frame, "time": ts, "from": src, "server": q_dst,
                         "name": _nth(raw["dns.qry.name"], 0)})
            continue
        # Inside a GTP-U tunnel the user's packet is the innermost IP layer, so the last
        # occurrence of each field is the one that belongs to the DNS message.
        dns_at = layers.index("dns") if "dns" in layers else len(layers)
        ip_layers = [p for p in layers[:dns_at] if p in ("ip", "ipv6")]
        v6 = bool(ip_layers) and ip_layers[-1] == "ipv6"
        src = _last(raw["ipv6.src"]) if v6 else _last(raw["ip.src"])
        dst = _last(raw["ipv6.dst"]) if v6 else _last(raw["ip.dst"])
        transport = "tcp" if dns_at > 0 and layers[dns_at - 1] == "tcp" else "udp"
        if transport == "tcp":
            sport, dport = _last(raw["tcp.srcport"]), _last(raw["tcp.dstport"])
        else:
            sport, dport = _last(raw["udp.srcport"]), _last(raw["udp.dstport"])
        ids = raw["dns.id"]
        # Several DNS messages can share one TCP segment; the answer fields cannot be split
        # between them, so they are kept only when the frame holds a single message.
        single = len(ids) <= 1
        for i, dns_id in enumerate(ids or [""]):
            response = _truthy(_nth(raw["dns.flags.response"], i))
            qtype = to_int(_nth(raw["dns.qry.type"], i))
            msg = {
                "frame": frame, "time": ts, "src": src, "dst": dst, "sport": sport, "dport": dport,
                "transport": transport, "id": dns_id, "response": response,
                "name": _nth(raw["dns.qry.name"], i), "qtype": qtype,
            }
            if response:
                msg["rcode"] = to_int(_nth(raw["dns.flags.rcode"], i), 0)
                msg["tc"] = _truthy(_nth(raw["dns.flags.truncated"], i))
                msg["answers"] = to_int(_nth(raw["dns.count.answers"], i), 0)
                if single:
                    msg["addresses"] = raw["dns.a"] + raw["dns.aaaa"]
                    msg["cnames"] = raw["dns.cname"]
            messages.append(msg)
    return messages, icmp


def _drop_copies(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Keep one of each packet captured more than once: same addresses, ports, DNS id, direction and
    name within COPY_WINDOW. The IP ID is not part of the key: a decapsulating tap can rewrite it
    (seen as 0 on the decapsulated copy), and no resolver or client resends within COPY_WINDOW."""
    seen: dict[tuple, float] = {}
    kept, copies = [], 0
    for m in messages:
        key = (m["transport"], m["src"], m["dst"], m["sport"], m["dport"], m["id"], m["response"], m["name"])
        prev = seen.get(key)
        if prev is not None and m["time"] is not None and abs(m["time"] - prev) <= COPY_WINDOW:
            copies += 1
            continue
        if m["time"] is not None:
            seen[key] = m["time"]
        kept.append(m)
    return kept, copies


def _percentile(sorted_values: list[float], pct: float) -> float | None:
    if not sorted_values:
        return None
    rank = max(1, -(-len(sorted_values) * pct // 100))  # nearest rank
    return round(sorted_values[int(rank) - 1], 3)


def pair(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Transactions (one per distinct query) and the number of responses that matched no query."""
    txs: list[dict[str, Any]] = []
    open_by_key: dict[tuple, dict[str, Any]] = {}
    orphans = 0
    for m in messages:
        name_key = m["name"].lower()
        if not m["response"]:
            key = (m["transport"], m["src"], m["sport"], m["dst"], m["dport"], m["id"], name_key)
            tx = open_by_key.get(key)
            if tx is not None and tx.get("response_time") is None:
                tx["retransmissions"] += 1
                tx["last_query_time"] = m["time"]
                continue
            tx = {
                "frame": m["frame"], "time": m["time"], "last_query_time": m["time"], "client": m["src"],
                "client_port": m["sport"], "server": m["dst"], "server_port": m["dport"], "transport": m["transport"],
                "id": m["id"], "name": m["name"], "qtype": m["qtype"], "retransmissions": 0,
            }
            open_by_key[key] = tx
            txs.append(tx)
            continue
        key = (m["transport"], m["dst"], m["dport"], m["src"], m["sport"], m["id"], name_key)
        tx = open_by_key.get(key)
        if tx is None:
            orphans += 1
            continue
        if tx.get("response_time") is not None:
            tx["duplicate_responses"] = tx.get("duplicate_responses", 0) + 1
            continue
        tx.update({
            "response_frame": m["frame"], "response_time": m["time"], "rcode": m["rcode"], "tc": m["tc"],
            "answers": m["answers"], "addresses": m.get("addresses", []), "cnames": m.get("cnames", []),
        })
    return txs, orphans


def _mark_retries_and_fallback(txs: list[dict[str, Any]]) -> None:
    """A retry is a new query (new id or port, or another server) for the same name and type from the
    same client, sent within RETRY_WINDOW of one that came back with an error, or at least
    PARALLEL_WINDOW after one still waiting for its answer (queries sent together to several
    resolvers are not retries). A UDP answer with TC set
    followed by the same question over TCP is a TCP fallback."""
    by_question: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for tx in txs:
        by_question[(tx["client"], tx["name"].lower(), tx["qtype"])].append(tx)
    for chain in by_question.values():
        for prev, nxt in zip(chain, chain[1:]):
            if prev["time"] is None or nxt["time"] is None or nxt["time"] - prev["time"] > RETRY_WINDOW:
                continue
            answered_before = prev.get("response_time") is not None and prev["response_time"] <= nxt["time"]
            if prev.get("tc") and prev["transport"] == "udp" and nxt["transport"] == "tcp":
                prev["tcp_fallback_frame"] = nxt["frame"]
                nxt["fallback_from_udp"] = True
                continue
            if answered_before:
                if prev.get("rcode") not in (None, 0):
                    nxt["retry_of"] = prev["frame"]  # asked again after an error answer
            elif nxt["time"] - prev["time"] >= PARALLEL_WINDOW:
                nxt["retry_of"] = prev["frame"]  # asked again after waiting for an answer that had not come


def summarise(messages: list[dict[str, Any]], icmp: list[dict[str, Any]], name: str | None = None,
              slow_ms: float = SLOW_MS) -> dict[str, Any]:
    """Transactions, per-name and per-server summaries, and issues in plain words."""
    kept, copies = _drop_copies(messages)
    txs, orphans = pair(kept)
    _mark_retries_and_fallback(txs)
    if name:
        txs = [t for t in txs if matches_name(t["name"], name)]
        icmp = [e for e in icmp if e.get("name") and matches_name(e["name"], name)]
    last_seen = max((m["time"] for m in kept if m["time"] is not None), default=None)

    rows = []
    for tx in txs:
        answered = tx.get("response_time") is not None
        rtt = round((tx["response_time"] - tx["time"]) * 1000, 3) if answered and tx["time"] is not None else None
        row = {
            "frame": tx["frame"], "time": iso(tx["time"]), "client": f"{tx['client']}:{tx['client_port']}",
            "server": f"{tx['server']}:{tx['server_port']}", "transport": tx["transport"], "id": tx["id"],
            "name": tx["name"], "type": qtype_name(tx["qtype"]),
            "response_frame": tx.get("response_frame"),
            "rcode": tx.get("rcode"), "rcode_name": rcode_name(tx.get("rcode")),
            "answers": tx.get("answers") if answered else None,
            "addresses": tx.get("addresses")[:8] if answered and tx.get("addresses") else None,
            "cnames": tx.get("cnames")[:4] if answered and tx.get("cnames") else None,
            "rtt_ms": rtt,
            "retransmissions": tx["retransmissions"] or None,
            "retry_of": tx.get("retry_of"),
            "truncated_tc": True if tx.get("tc") else None,
            "tcp_fallback_frame": tx.get("tcp_fallback_frame"),
            "fallback_from_udp": tx.get("fallback_from_udp"),
            "duplicate_responses": tx.get("duplicate_responses"),
        }
        if not answered:
            row["unanswered"] = True
            if last_seen is not None and tx["time"] is not None and last_seen - tx["time"] < END_GRACE:
                row["near_capture_end"] = True
        rows.append(compact(row))

    servers = _per_server(txs, icmp)
    names = _per_name(txs, slow_ms)
    summary = {
        "queries": len(txs),
        "answered": sum(1 for t in txs if t.get("response_time") is not None),
        "unanswered": sum(1 for t in txs if t.get("response_time") is None),
        "rcodes": dict(Counter(rcode_name(t["rcode"]) for t in txs if t.get("rcode") is not None)),
        "retransmissions": sum(t["retransmissions"] for t in txs),
        "retries": sum(1 for t in txs if t.get("retry_of")),
        "truncated_tc": sum(1 for t in txs if t.get("tc")),
        "tcp_fallbacks": sum(1 for t in txs if t.get("tcp_fallback_frame")),
        "tcp_queries": sum(1 for t in txs if t["transport"] == "tcp"),
        "orphan_responses": orphans if not name else None,
        "duplicate_copies": copies,
        "icmp_errors": len(icmp),
    }
    rtts = sorted((t["response_time"] - t["time"]) * 1000 for t in txs
                  if t.get("response_time") is not None and t["time"] is not None)
    if rtts:
        summary["rtt_ms"] = {"p50": _percentile(rtts, 50), "p90": _percentile(rtts, 90), "p99": _percentile(rtts, 99),
                             "max": round(rtts[-1], 3)}
    issues = _issues(summary, servers, names, txs, slow_ms)
    return {"transactions": rows, "servers": servers, "names": names, "summary": compact(summary), "issues": issues}


def _per_server(txs: list[dict[str, Any]], icmp: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for tx in txs:
        groups[tx["server"]].append(tx)
    icmp_by_server = Counter(e["server"] for e in icmp if e.get("server"))
    out = []
    for server, group in groups.items():
        rtts = sorted((t["response_time"] - t["time"]) * 1000 for t in group
                      if t.get("response_time") is not None and t["time"] is not None)
        answered = sum(1 for t in group if t.get("response_time") is not None)
        row = {
            "server": server, "queries": len(group), "answered": answered, "unanswered": len(group) - answered,
            "unanswered_share": round((len(group) - answered) / len(group), 3) if group else None,
            "rcodes": dict(Counter(rcode_name(t["rcode"]) for t in group if t.get("rcode") is not None)),
            "retransmissions": sum(t["retransmissions"] for t in group) or None,
            "transports": dict(Counter(t["transport"] for t in group)),
            "clients": len({t["client"] for t in group}),
            "icmp_errors": icmp_by_server.get(server) or None,
        }
        if rtts:
            row["rtt_ms"] = {"min": round(rtts[0], 3), "p50": _percentile(rtts, 50), "p90": _percentile(rtts, 90),
                             "p99": _percentile(rtts, 99), "max": round(rtts[-1], 3)}
        out.append(compact(row))
    out.sort(key=lambda r: (-r.get("unanswered", 0), -r["queries"]))
    return out


def _per_name(txs: list[dict[str, Any]], slow_ms: float) -> list[dict[str, Any]]:
    """Names that failed, went unanswered, were retried or were slow, worst first (at most 50)."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for tx in txs:
        groups[tx["name"].lower()].append(tx)
    out = []
    for qname, group in groups.items():
        unanswered = sum(1 for t in group if t.get("response_time") is None)
        failed = sum(1 for t in group if t.get("rcode") not in (None, 0))
        retries = sum(1 for t in group if t.get("retry_of"))
        slow = sum(1 for t in group if t.get("response_time") is not None and t["time"] is not None
                   and (t["response_time"] - t["time"]) * 1000 > slow_ms)
        if not (unanswered or failed or retries or slow):
            continue
        out.append(compact({
            "name": qname, "queries": len(group), "unanswered": unanswered or None, "failed": failed or None,
            "rcodes": dict(Counter(rcode_name(t["rcode"]) for t in group if t.get("rcode") is not None)),
            "retries": retries or None, "slow": slow or None,
            "types": sorted({qtype_name(t["qtype"]) or "?" for t in group}),
            "servers": sorted({t["server"] for t in group})[:8],
        }))
    out.sort(key=lambda r: (-(r.get("unanswered", 0) + r.get("failed", 0)), -r.get("retries", 0), -r["queries"]))
    return out[:50]


def _issues(summary: dict[str, Any], servers: list[dict[str, Any]], names: list[dict[str, Any]],
            txs: list[dict[str, Any]], slow_ms: float) -> list[str]:
    issues: list[str] = []
    for s in servers:
        q, un = s["queries"], s.get("unanswered", 0)
        if un and (un / q >= ISSUE_SHARE or un >= 3):
            if un == q:
                issues.append(f"{s['server']} answered none of {q} queries")
            else:
                issues.append(f"{s['server']} left {un} of {q} queries unanswered")
        if s.get("icmp_errors"):
            issues.append(f"{s['icmp_errors']} ICMP errors came back for queries to {s['server']} (port unreachable or filtered)")
        p90 = (s.get("rtt_ms") or {}).get("p90")
        if p90 is not None and p90 > slow_ms:
            issues.append(f"{s['server']} is slow: 90% of answers within {p90} ms")
    failed = Counter(rcode_name(t["rcode"]) for t in txs if t.get("rcode") not in (None, 0))
    for rc, n in failed.most_common():
        sample = sorted({t["name"] for t in txs if rcode_name(t.get("rcode")) == rc})[:3]
        issues.append(f"{n} answers were {rc} (e.g. {', '.join(sample)})")
    if summary["retries"]:
        issues.append(f"{summary['retries']} queries were retries of a name that had not been answered yet or had failed")
    if summary["retransmissions"]:
        issues.append(f"{summary['retransmissions']} queries were sent again unchanged (same id and port) before an answer")
    tc_no_fallback = sum(1 for t in txs if t.get("tc") and t["transport"] == "udp" and not t.get("tcp_fallback_frame"))
    if tc_no_fallback:
        issues.append(f"{tc_no_fallback} UDP answers had the TC bit set and the client did not retry over TCP in the capture")
    if summary.get("tcp_fallbacks"):
        issues.append(f"{summary['tcp_fallbacks']} truncated UDP answers were followed by the same query over TCP")
    if summary["duplicate_copies"]:
        issues.append(f"{summary['duplicate_copies']} packets were extra copies of the same packet (capture on several "
                      "interfaces or legs); they were counted once")
    return issues


def is_problem(row: dict[str, Any]) -> bool:
    """A transaction row worth reading first: unanswered, failed, retried, resent or truncated."""
    return bool(row.get("unanswered") or row.get("rcode") or row.get("retry_of") or row.get("retransmissions")
                or row.get("truncated_tc"))
