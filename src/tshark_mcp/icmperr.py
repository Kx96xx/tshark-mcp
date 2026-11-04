"""icmp_errors: every ICMP and ICMPv6 error in the capture, about which flow, from whom.

Each error is read with the packet it quotes (``packets`` keeps the quoted IP and
transport layers apart from the carrier), named by kind, and grouped per sender,
kind and quoted flow (source, destination, protocol): the destination ports seen
are listed. Copies of the same error (a mirror, a second interface) are dropped with
the key ``capture_quality`` uses. On top of the rows:

* ``by_sender``: errors per sender, the kinds it sent, its hop distance from the
  capture point (from the TTL) and whether it is the endpoint the packets were
  addressed to or a router on the path;
* ``echo``: echo requests paired with replies per source and destination, with lost
  requests and round trip times;
* ``issues``: fragmentation needed with the MTU, routing loops (TTL exceeded from two
  routers alternating for one flow), traceroutes, administrative rejects, missing
  routes and closed UDP ports.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Any

from .copies import CopyTracker, copy_key, has_ip_id
from .fields import compact, iso, split_fields_line
from .packets import AGGREGATOR, record

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.protocols",
    "ip.src", "ip.dst", "ip.id", "ip.len", "ip.ttl",
    "ipv6.src", "ipv6.dst", "ipv6.plen", "ipv6.hlim",
    "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "udp.srcport", "udp.dstport",
    "icmp.type", "icmp.code", "icmp.mtu", "icmp.checksum", "icmp.ident", "icmp.seq",
    "icmpv6.type", "icmpv6.code", "icmpv6.mtu", "icmpv6.checksum", "icmpv6.echo.identifier",
    "icmpv6.echo.sequence_number",
]

# Errors (RFC 792, RFC 1812, RFC 4443) and echo, which the echo summary pairs.
ERROR_FILTER = "icmp.type in {3, 4, 5, 11, 12} || icmpv6.type in {1, 2, 3, 4}"
ECHO_FILTER = "icmp.type in {0, 8} || icmpv6.type in {128, 129}"

_V4 = {
    (3, 0): ("net_unreachable", "net unreachable"), (3, 1): ("host_unreachable", "host unreachable"),
    (3, 2): ("protocol_unreachable", "protocol unreachable"), (3, 3): ("port_unreachable", "port unreachable"),
    (3, 4): ("frag_needed", "fragmentation needed and DF set"), (3, 5): ("source_route_failed", "source route failed"),
    (3, 6): ("net_unreachable", "destination network unknown"), (3, 7): ("host_unreachable", "destination host unknown"),
    (3, 8): ("host_unreachable", "source host isolated"),
    (3, 9): ("admin_prohibited", "network administratively prohibited"),
    (3, 10): ("admin_prohibited", "host administratively prohibited"),
    (3, 11): ("net_unreachable", "network unreachable for TOS"), (3, 12): ("host_unreachable", "host unreachable for TOS"),
    (3, 13): ("admin_prohibited", "communication administratively prohibited"),
    (3, 14): ("admin_prohibited", "host precedence violation"), (3, 15): ("admin_prohibited", "precedence cutoff in effect"),
    (11, 0): ("ttl_exceeded", "TTL exceeded in transit"), (11, 1): ("reassembly_timeout", "fragment reassembly time exceeded"),
}
_V4_TYPES = {4: ("source_quench", "source quench"), 5: ("redirect", "redirect"), 12: ("parameter_problem", "parameter problem")}
_V6 = {
    (1, 0): ("no_route", "no route to destination"), (1, 1): ("admin_prohibited", "administratively prohibited"),
    (1, 2): ("no_route", "beyond scope of source address"), (1, 3): ("address_unreachable", "address unreachable"),
    (1, 4): ("port_unreachable", "port unreachable"), (1, 5): ("admin_prohibited", "source address failed policy"),
    (1, 6): ("admin_prohibited", "reject route to destination"),
    (3, 0): ("ttl_exceeded", "hop limit exceeded in transit"), (3, 1): ("reassembly_timeout", "fragment reassembly time exceeded"),
}
_V6_TYPES = {2: ("packet_too_big", "packet too big"), 4: ("parameter_problem", "parameter problem")}
KINDS = ("net_unreachable", "host_unreachable", "protocol_unreachable", "port_unreachable", "frag_needed",
         "source_route_failed", "admin_prohibited", "ttl_exceeded", "reassembly_timeout", "source_quench", "redirect",
         "parameter_problem", "no_route", "address_unreachable", "packet_too_big", "other")
COPY_WINDOW_S = 1.0
MAX_PORTS = 10
MAX_ISSUES = 20


def display_filter() -> str:
    return f"{ERROR_FILTER} || {ECHO_FILTER}"


def kind_of(family: str, typ: int | None, code: int | None) -> tuple[str, str]:
    if family == "icmpv6":
        hit = _V6.get((typ, code)) or _V6_TYPES.get(typ)
    else:
        hit = _V4.get((typ, code)) or _V4_TYPES.get(typ)
    return hit or ("other", f"{family} type {typ} code {code}")


def parse(stdout: str) -> list[dict[str, Any]]:
    """Generic records plus the echo identifier and sequence number."""
    out = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(FIELDS):
            continue
        raw = {k: (v.split(AGGREGATOR) if v else []) for k, v in zip(FIELDS, cols)}
        rec = record(raw)
        icmp = rec.get("icmp")
        if icmp:
            key = icmp["family"]
            ident = raw.get("icmpv6.echo.identifier" if key == "icmpv6" else "icmp.ident") or [""]
            seq = raw.get("icmpv6.echo.sequence_number" if key == "icmpv6" else "icmp.seq") or [""]
            icmp["ident"], icmp["seq"] = ident[0], seq[0]
        out.append(rec)
    return out


def _initial_ttl(ttl: int) -> int:
    return next(v for v in (32, 64, 128, 255) if ttl <= v)


def _addr(ip: str | None, port: str | None = None) -> str:
    if not port:
        return ip or "?"
    return f"[{ip}]:{port}" if ip and ":" in ip else f"{ip}:{port}"


def analyse(recs: list[dict[str, Any]]) -> dict[str, Any]:
    tracker = CopyTracker(id_window=COPY_WINDOW_S)
    groups: dict[tuple, dict[str, Any]] = {}
    senders: dict[str, dict[str, Any]] = {}
    flow_senders: dict[tuple, list[str]] = defaultdict(list)
    echoes: dict[tuple, dict[str, Any]] = {}
    pending: dict[tuple, tuple[float | None, int | None]] = {}
    copies = 0
    errors = 0
    for rec in recs:
        if not rec.get("src"):
            continue
        has_id = has_ip_id(rec)
        key = copy_key(rec, has_id)
        if key is not None and tracker.check(key, has_id, rec["time"])[0]:
            copies += 1
            continue
        if rec.get("icmp_error"):
            errors += 1
            _error(rec, groups, senders, flow_senders)
        elif rec.get("icmp"):
            _echo(rec, echoes, pending)
    rows = []
    for g in groups.values():
        mtus = g.pop("mtus")
        ports = g.pop("ports")
        g["mtu"] = mtus.most_common(1)[0][0] if mtus else None
        g["mtus"] = sorted(mtus) if len(mtus) > 1 else None
        g["quoted"]["ports"] = sorted(ports, key=lambda p: (len(p), p))[:MAX_PORTS] or None
        g["quoted"]["port_count"] = len(ports) if len(ports) > MAX_PORTS else None
        g["quoted"] = compact(g["quoted"])
        g["first"], g["last"] = iso(g.pop("_first")), iso(g.pop("_last"))
        rows.append(compact(g))
    rows.sort(key=lambda r: (-r["count"], r["first_frame"]))
    by_sender = []
    quoted_dsts = {r["quoted"].get("dst") for r in rows}
    for s in senders.values():
        ttl = s.pop("ttls").most_common(1)
        s["kinds"] = dict(s["kinds"].most_common())
        if ttl:
            s["ttl"] = ttl[0][0]
            s["hops_away"] = _initial_ttl(ttl[0][0]) - ttl[0][0]
        s["role"] = "endpoint" if s["sender"] in quoted_dsts else "on_path"
        by_sender.append(compact(s))
    by_sender.sort(key=lambda s: -s["errors"])
    echo = _echo_rows(echoes, pending)
    issues = _issues(rows, flow_senders, echo)
    summary = {
        "errors": errors, "error_rows": len(rows), "copies_dropped": copies,
        "by_kind": dict(Counter(r["kind"] for r in rows for _ in range(r["count"])).most_common()),
        "senders": len(by_sender), "echo_requests": sum(e["requests"] for e in echo),
        "echo_lost": sum(e["lost"] for e in echo),
    }
    return {"rows": rows, "by_sender": by_sender, "echo": echo, "issues": issues, "summary": summary}


def _error(rec: dict[str, Any], groups: dict, senders: dict, flow_senders: dict) -> None:
    icmp = rec["icmp_error"]
    kind, name = kind_of(icmp["family"], icmp["type"], icmp["code"])
    q = rec.get("quoted") or {}
    flow = (q.get("src"), q.get("dst"), q.get("proto"))
    gkey = (rec["src"], kind, name, *flow)
    g = groups.get(gkey)
    if g is None:
        g = groups[gkey] = {
            "sender": rec["src"], "kind": kind, "error": name, "family": icmp["family"], "type": icmp["type"],
            "code": icmp["code"], "count": 0, "first_frame": rec["frame"], "last_frame": rec["frame"],
            "_first": rec["time"], "_last": rec["time"], "mtus": Counter(), "ports": set(),
            "quoted": {"src": q.get("src"), "dst": q.get("dst"), "proto": q.get("proto")},
            "quoted_ip_id": q.get("id") or None,
        }
    g["count"] += 1
    g["last_frame"], g["_last"] = rec["frame"], rec["time"]
    if icmp.get("mtu"):
        g["mtus"][icmp["mtu"]] += 1
    if q.get("dport"):
        g["ports"].add(str(q["dport"]))
    s = senders.get(rec["src"])
    if s is None:
        s = senders[rec["src"]] = {"sender": rec["src"], "errors": 0, "kinds": Counter(), "ttls": Counter(),
                                   "first_frame": rec["frame"]}
    s["errors"] += 1
    s["kinds"][kind] += 1
    if rec.get("ttl") is not None:
        s["ttls"][rec["ttl"]] += 1
    if kind == "ttl_exceeded":
        flow_senders[flow].append(rec["src"])


def _echo(rec: dict[str, Any], echoes: dict, pending: dict) -> None:
    icmp = rec["icmp"]
    fam, typ = icmp["family"], icmp["type"]
    request = (fam == "icmp" and typ == 8) or (fam == "icmpv6" and typ == 128)
    reply = (fam == "icmp" and typ == 0) or (fam == "icmpv6" and typ == 129)
    if not (request or reply):
        return
    if request:
        src, dst = rec["src"], rec["dst"]
    else:
        src, dst = rec["dst"], rec["src"]
    e = echoes.get((src, dst))
    if e is None:
        e = echoes[(src, dst)] = {"source": src, "destination": dst, "requests": 0, "replies": 0, "rtts": [],
                                  "first_frame": rec["frame"], "lost_frames": []}
    pkey = (src, dst, icmp.get("ident"), icmp.get("seq"))
    if request:
        e["requests"] += 1
        if pkey not in pending:
            pending[pkey] = (rec["time"], rec["frame"])
    elif pkey in pending:
        sent, _frame = pending.pop(pkey)
        e["replies"] += 1
        if sent is not None and rec["time"] is not None and rec["time"] >= sent:
            e["rtts"].append((rec["time"] - sent) * 1000)


def _echo_rows(echoes: dict, pending: dict) -> list[dict[str, Any]]:
    lost: dict[tuple, list[int]] = defaultdict(list)
    for (src, dst, _i, _s), (_t, frame) in pending.items():
        lost[(src, dst)].append(frame)
    rows = []
    for key, e in echoes.items():
        rtts = sorted(e.pop("rtts"))
        e.pop("lost_frames")
        frames = sorted(f for f in lost.get(key, []) if f is not None)
        e["lost"] = len(lost.get(key, []))
        e["lost_frames"] = frames[:5] or None
        if rtts:
            e["rtt_ms"] = {"min": round(rtts[0], 3), "p50": round(statistics.median(rtts), 3), "max": round(rtts[-1], 3)}
        rows.append(compact(e))
    rows.sort(key=lambda e: (-e["lost"], -e["requests"]))
    return rows


def _alternating(seq: list[str]) -> bool:
    changes = sum(1 for a, b in zip(seq, seq[1:]) if a != b)
    return len(set(seq)) == 2 and len(seq) >= 4 and changes >= len(seq) - 2


def _issues(rows: list[dict[str, Any]], flow_senders: dict, echo: list[dict[str, Any]]) -> list[str]:
    issues: list[str] = []
    for r in rows:
        q = r.get("quoted") or {}
        proto = (q.get("proto") or "").upper()
        ports = q.get("ports") or []
        dst = q.get("dst") or "?"
        where = f"{dst} {proto} port{'s' if len(ports) > 1 else ''} {', '.join(ports)}" if ports else dst
        n, sender = r["count"], r["sender"]
        times = f"{n} time{'s' if n != 1 else ''}"
        if r["kind"] in ("frag_needed", "packet_too_big"):
            mtu = f" (next-hop MTU {r['mtu']})" if r.get("mtu") else ""
            issues.append(f"{sender} says {r['error']}{mtu} {times} for packets from {q.get('src')} to {dst}: "
                          f"the path MTU is smaller than the packets sent; if the sender keeps sending full-size "
                          f"packets this ICMP is not reaching it (frame {r['first_frame']})")
        elif r["kind"] == "admin_prohibited":
            issues.append(f"{sender} rejects traffic from {q.get('src')} to {where} as {r['error']} ({times}, "
                          f"frame {r['first_frame']}): a firewall or ACL rejects it")
        elif r["kind"] == "port_unreachable":
            issues.append(f"{sender} reports port unreachable {times} for {where} (frame {r['first_frame']}): "
                          "nothing listens there")
        elif r["kind"] in ("net_unreachable", "host_unreachable", "no_route", "address_unreachable"):
            issues.append(f"{sender} reports {r['error']} {times} for {q.get('src')} to {dst} (frame {r['first_frame']}): "
                          "no route, or the next hop does not answer ARP or neighbour discovery")
        elif r["kind"] == "redirect":
            issues.append(f"{sender} sent {n} redirect{'s' if n != 1 else ''} about traffic to {dst}: hosts send through "
                          "a gateway that is not the best next hop")
        if len(issues) >= MAX_ISSUES:
            break
    for (src, dst, proto), seq in flow_senders.items():
        if _alternating(seq):
            a, b = sorted(set(seq))
            issues.append(f"TTL exceeded from {a} and {b} alternating for {(proto or '').upper()} {src} to {dst} "
                          f"({len(seq)} errors): a routing loop between them")
        elif len(set(seq)) >= 3:
            issues.append(f"TTL exceeded from {len(set(seq))} different routers for {src} to {dst}: a traceroute "
                          "(each hop answers in turn), not a fault")
    for e in echo:
        if e["lost"] and e["requests"]:
            issues.append(f"{e['lost']} of {e['requests']} echo requests from {e['source']} to {e['destination']} got "
                          "no reply")
    return issues[:MAX_ISSUES]
