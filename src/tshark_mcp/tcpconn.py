"""tcp_connections: can this host reach that port, and if not, why not?

Every TCP connection attempt in the capture gets one row with an ``outcome``:

* ``connected``: SYN, SYN-ACK and the client's ACK (or data) were seen;
* ``refused``: the server side answered the SYN with a reset (nothing listens on
  the port, or a firewall rejects with a reset);
* ``prohibited``: an ICMP administratively-prohibited error quotes the SYN (a
  firewall rejects it);
* ``unreachable``: another ICMP destination-unreachable or time-exceeded error
  quotes the SYN (no route, host or port unreachable, TTL exceeded);
* ``filtered``: the SYN got no answer at all (a firewall drops it, or the host is
  down); ``near_capture_end`` when the capture stopped before a retry was due;
* ``reset_during_handshake``: a SYN-ACK came back, then a reset before the
  handshake finished;
* ``handshake_incomplete``: a SYN-ACK came back and the client never acknowledged it;
* ``one_sided``: only one direction of the connection is in the capture (a one-way
  tap, asymmetric routing, or a capture filter on one address): the SYN sender went on
  sending ACKs or data without a SYN-ACK in the file, or the server sent data after its
  SYN-ACK without the client's ACK in the file. The peer must have answered, so this is
  not a failure; ``missing_direction`` names the direction that is absent;
* ``seen_midway``: the capture started after the handshake.

A new SYN with another initial sequence number on the same addresses and ports
is a new attempt (port reuse); a SYN with the same one is a retry. Copies of the
same packet (mirror, SPAN, several interfaces) are dropped first with the key
``capture_quality`` uses, so a mirrored SYN is not a retry.

``destinations`` groups the attempts per server address and port: success rate,
refusals, drops, connect time, connection churn per client, and ``issues`` such
as one client being dropped while others connect.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Any, Callable

from .copies import CopyTracker, copy_key, has_ip_id
from .fields import compact, iso
from .packets import zeroed_tcp_header
from .tunnels import ICMP_NAMES, ICMPV6_NAMES

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.protocols",
    "ip.src", "ip.dst", "ip.id", "ip.len", "ip.ttl",
    "ipv6.src", "ipv6.dst", "ipv6.plen", "ipv6.hlim",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.flags", "tcp.checksum",
    "icmp.type", "icmp.code", "icmp.checksum", "icmp.seq", "icmpv6.type", "icmpv6.code", "icmpv6.checksum",
]

# ICMP errors that can answer a SYN: destination unreachable and time exceeded (RFC 792),
# ICMPv6 destination unreachable and time exceeded (RFC 4443).
ICMP_ERRORS = "icmp.type == 3 || icmp.type == 11 || icmpv6.type == 1 || icmpv6.type == 3"
# Administratively prohibited: RFC 1812 codes 9, 10 and 13; ICMPv6 code 1.
PROHIBITED = {("icmp", 3, 9), ("icmp", 3, 10), ("icmp", 3, 13), ("icmpv6", 1, 1)}

OUTCOMES = ("connected", "refused", "filtered", "prohibited", "unreachable", "reset_during_handshake",
            "handshake_incomplete", "one_sided", "seen_midway")
NOT_ATTEMPTS = ("seen_midway", "one_sided")  # neither proves nor disproves that a connection attempt worked
FAILED = ("refused", "filtered", "prohibited", "unreachable", "reset_during_handshake", "handshake_incomplete")
COPY_WINDOW_S = 1.0
NEAR_END_S = 3.0  # a SYN this close to the end of the capture may still have been answered or retried
CHURN_MIN = 50  # connections from one client to one destination before churn is worth a sentence
CHURN_SHORT_S = 5.0
SLOW_CONNECT_MS = 1000.0
MAX_ICMP_PER_CONN = 5


def display_filter() -> str:
    return f"tcp || {ICMP_ERRORS}"


def side_text(ip: str, port: str) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


class _Conn:
    def __init__(self, rec: dict[str, Any], key: tuple) -> None:
        self.key = key
        self.stream = rec["tcp"].get("stream")
        self.first = self.last = rec["time"]
        self.first_frame = self.last_frame = rec["frame"]
        self.client: tuple | None = None
        self.isn: int | None = None
        self.syn_times: list[float] = []
        self.syn_frames: list[int] = []
        self.synack_time: float | None = None
        self.synack_frame: int | None = None
        self.established = False
        self.packets: Counter[tuple] = Counter()
        self.bytes: Counter[tuple] = Counter()
        self.closes: list[tuple[str, tuple, int, bool]] = []  # (fin|rst, side, frame, before the handshake ended)
        self.icmp: Counter[tuple] = Counter()
        self.icmp_frames: dict[tuple, int] = {}
        self.copies = 0
        self.seen: set[str] = set()
        # Packets after the SYN / SYN-ACK that only make sense once the other side answered:
        # the SYN sender's ACKs or data, the SYN-ACK sender's data.
        self.acks_after_syn: Counter[tuple] = Counter()
        self.data_after_synack: Counter[tuple] = Counter()

    def other(self, side: tuple) -> tuple:
        a, b = self.key
        return b if side == a else a


def analyse(recs: list[dict[str, Any]], capture_end: Callable[[], float | None]
            ) -> tuple[list[dict[str, Any]], dict[str, Any], dict[int, tuple[float | None, float | None]]]:
    """(one row per connection attempt, summary counters, first frame to (start, end) time)."""
    tracker = CopyTracker(id_window=COPY_WINDOW_S)
    current: dict[tuple, _Conn] = {}
    conns: list[_Conn] = []
    by_key: dict[tuple, list[_Conn]] = defaultdict(list)
    copies = 0
    icmp_records = []
    for rec in recs:
        if rec.get("icmp_error"):
            icmp_records.append(rec)
            continue
        tcp = rec.get("tcp")
        if not tcp or not rec.get("src"):
            continue
        me, peer = (rec["src"], tcp["sport"]), (rec["dst"], tcp["dport"])
        key = tuple(sorted([me, peer]))
        conn = current.get(key)
        has_id = has_ip_id(rec)
        if zeroed_tcp_header(rec) or tracker.check(copy_key(rec, has_id), has_id, rec["time"])[0]:
            if conn is not None:
                conn.copies += 1
            copies += 1
            continue
        fresh_syn = tcp["syn"] and not tcp["ack"] and (conn is None or conn.isn != tcp["seq"])
        if conn is None or fresh_syn:
            conn = current[key] = _Conn(rec, key)
            conns.append(conn)
            by_key[key].append(conn)
        _account(conn, rec, me, peer)
    icmp_copies, icmp_unmatched = _attach_icmp(icmp_records, by_key)
    end: list[float | None] = []

    def end_time() -> float | None:
        if not end:
            end.append(capture_end())
        return end[0]

    rows = [_row(c, end_time) for c in conns]
    order = {name: i for i, name in enumerate(FAILED)}
    rows.sort(key=lambda r: (order.get(r["outcome"], len(FAILED)), r.get("first_frame") or 0))
    summary = {
        "connections": len(rows),
        "by_outcome": dict(Counter(r["outcome"] for r in rows).most_common()),
        "copies_dropped": copies,
        "icmp_copies_dropped": icmp_copies,
        "icmp_errors_without_connection": icmp_unmatched,
    }
    times = {c.first_frame: (c.first, c.last) for c in conns}
    return rows, summary, times


def _account(conn: _Conn, rec: dict[str, Any], me: tuple, peer: tuple) -> None:
    tcp = rec["tcp"]
    t = rec["time"]
    if t is not None:
        conn.first = t if conn.first is None else min(conn.first, t)
        conn.last = t if conn.last is None else max(conn.last, t)
    conn.last_frame = rec["frame"]
    conn.packets[me] += 1
    conn.bytes[me] += tcp["len"]
    if conn.stream is None:
        conn.stream = tcp.get("stream")
    if tcp["syn"] and not tcp["ack"]:
        conn.seen.add("syn")
        if conn.client is None:
            conn.client = me
        conn.isn = tcp["seq"]
        if conn.synack_time is None and t is not None:
            conn.syn_times.append(t)
            conn.syn_frames.append(rec["frame"])
    elif tcp["syn"] and tcp["ack"]:
        conn.seen.add("syn_ack")
        if conn.client is None:
            conn.client = peer
        if conn.synack_time is None:
            conn.synack_time, conn.synack_frame = t, rec["frame"]
    elif conn.synack_time is not None and me == conn.client and (tcp["ack"] or tcp["len"]) and not tcp["rst"]:
        conn.established = True
    if not tcp["syn"] and not tcp["rst"]:
        if tcp["ack"] and "syn" in conn.seen and me == conn.client:
            conn.acks_after_syn[me] += 1
        if tcp["len"] and conn.synack_time is not None and me != conn.client:
            conn.data_after_synack[me] += 1
    if tcp["len"]:
        conn.seen.add("data")
    if tcp["fin"] and not tcp["rst"]:
        conn.seen.add("fin")
        conn.closes.append(("fin", me, rec["frame"], not conn.established))
    if tcp["rst"]:
        conn.seen.add("rst")
        conn.closes.append(("rst", me, rec["frame"], not conn.established))


def _attach_icmp(icmp_records: list[dict[str, Any]], by_key: dict[tuple, list[_Conn]]) -> tuple[int, int]:
    """Hang each ICMP error on the connection whose packet it quotes; (copies dropped, unmatched)."""
    tracker = CopyTracker(id_window=COPY_WINDOW_S)
    copies = unmatched = 0
    for rec in icmp_records:
        q = rec.get("quoted") or {}
        if q.get("proto") != "tcp":
            continue
        key = tuple(sorted([(q.get("src"), q.get("sport")), (q.get("dst"), q.get("dport"))]))
        candidates = by_key.get(key)
        if not candidates:
            unmatched += 1
            continue
        has_id = has_ip_id(rec)
        ckey = copy_key(rec, has_id)
        if ckey is not None and tracker.check(ckey, has_id, rec["time"])[0]:
            copies += 1
            continue
        t = rec["time"]
        # The latest attempt on these addresses and ports that started before the error.
        conn = candidates[0]
        for c in candidates:
            if t is None or c.first is None or c.first <= t:
                conn = c
        icmp = rec["icmp_error"]
        k = (rec["src"], icmp["family"], icmp["type"], icmp["code"])
        conn.icmp[k] += 1
        conn.icmp_frames.setdefault(k, rec["frame"])
    return copies, unmatched


def icmp_name(family: str, typ: int | None, code: int | None) -> str:
    names = ICMPV6_NAMES if family == "icmpv6" else ICMP_NAMES
    return names.get((typ, code), f"{family} type {typ} code {code}")


def _client_server(conn: _Conn) -> tuple[tuple, tuple]:
    if conn.client is not None:
        return conn.client, conn.other(conn.client)
    # No SYN or SYN-ACK in the capture: the side with the higher port is most likely the client.
    a, b = conn.key
    client = max((a, b), key=lambda s: int(s[1]) if str(s[1]).isdigit() else 0)
    return client, conn.other(client)


def _missing_direction(conn: _Conn, client: tuple, server: tuple) -> str | None:
    """The direction absent from the capture when the packets that are there prove the handshake worked."""
    if conn.synack_time is None:
        # The SYN sender acknowledges and sends data although no SYN-ACK is in the file, and nothing came back.
        if conn.acks_after_syn.get(client) and not conn.packets.get(server):
            return "server_to_client"
        return None
    if not conn.established and conn.data_after_synack.get(server) and not any(k == "rst" for k, *_ in conn.closes):
        # The server sends data after its SYN-ACK, which it only does once the client's ACK arrived.
        return "client_to_server"
    return None


def _outcome(conn: _Conn, server: tuple) -> str:
    if not conn.syn_times and conn.synack_time is None and "syn" not in conn.seen:
        return "seen_midway"
    if _missing_direction(conn, conn.other(server), server):
        return "one_sided"
    if conn.synack_time is not None:
        if conn.established:
            return "connected"
        if any(kind == "rst" for kind, *_ in conn.closes):
            return "reset_during_handshake"
        return "handshake_incomplete"
    if any(kind == "rst" and side == server for kind, side, *_ in conn.closes):
        return "refused"
    if conn.icmp:
        if any((fam, typ, code) in PROHIBITED for _src, fam, typ, code in conn.icmp):
            return "prohibited"
        return "unreachable"
    return "filtered"


def _ms(a: float | None, b: float | None) -> float | None:
    return round((b - a) * 1000, 3) if a is not None and b is not None and b >= a else None


def _row(conn: _Conn, end_time: Callable[[], float | None]) -> dict[str, Any]:
    client, server = _client_server(conn)
    outcome = _outcome(conn, server)
    row: dict[str, Any] = {
        "stream": conn.stream, "client": side_text(*client), "server": side_text(*server), "outcome": outcome,
    }
    if outcome == "one_sided":
        row["missing_direction"] = _missing_direction(conn, client, server)
    if outcome in ("filtered", "handshake_incomplete"):
        last_try = conn.syn_times[-1] if conn.syn_times else conn.synack_time
        end = end_time()
        if last_try is not None and end is not None and end - last_try < NEAR_END_S:
            row["near_capture_end"] = True
    if conn.syn_times:
        row["syns"] = len(conn.syn_times)
        row["syn_retries"] = len(conn.syn_times) - 1 or None
        row["connect_ms"] = _ms(conn.syn_times[0], conn.synack_time)
        if len(conn.syn_times) > 1:
            row["syn_retry_gaps_s"] = [round(b - a, 3) for a, b in zip(conn.syn_times, conn.syn_times[1:])][:8]
    row["bytes_client_to_server"] = conn.bytes[client]
    row["bytes_server_to_client"] = conn.bytes[server]
    row["packets"] = sum(conn.packets.values())
    row["duration_s"] = round(conn.last - conn.first, 6) if conn.first is not None and conn.last is not None else None
    row["closed_by"] = _closed_by(conn, client)
    row["completeness"] = [s for s in ("syn", "syn_ack", "data", "fin", "rst") if s in conn.seen]
    if conn.icmp:
        row["icmp"] = [compact({"from": src, "error": icmp_name(fam, typ, code), "count": n,
                                "frame": conn.icmp_frames.get((src, fam, typ, code))})
                       for (src, fam, typ, code), n in conn.icmp.most_common(MAX_ICMP_PER_CONN)]
    reset = next((frame for kind, _side, frame, _early in conn.closes if kind == "rst"), None)
    row["reset_frame"] = reset
    row["first"] = iso(conn.first)
    row["first_frame"] = conn.first_frame
    row["last_frame"] = conn.last_frame
    row["copies_dropped"] = conn.copies or None
    return compact(row)


def _closed_by(conn: _Conn, client: tuple) -> str:
    if not conn.closes:
        return "open_at_capture_end"
    kind, side, _frame, _early = conn.closes[0]
    return f"{'client' if side == client else 'server'}_{kind}"


# ------------------------------------------------------------------ destinations
def _p50(values: list[float]) -> float | None:
    return round(statistics.median(values), 3) if values else None


def destinations(rows: list[dict[str, Any]], times: dict[int, tuple[float | None, float | None]]) -> list[dict[str, Any]]:
    """Per server address and port: attempts, outcomes, connect time, churn and ``issues``.

    ``times`` maps a row's first frame to its (start, end) epoch times, for churn and concurrency."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        groups[r["server"]].append(r)
    out = []
    for server, rs in groups.items():
        outcomes = Counter(r["outcome"] for r in rs)
        attempts = [r for r in rs if r["outcome"] not in NOT_ATTEMPTS]
        connect = [r["connect_ms"] for r in rs if r.get("connect_ms") is not None]
        durations = [r["duration_s"] for r in rs if r["outcome"] == "connected" and r.get("duration_s") is not None]
        clients = Counter(r["client"].rsplit(":", 1)[0] for r in rs)
        dest: dict[str, Any] = {
            "server": server, "connections": len(rs), "attempts": len(attempts),
            "connected": outcomes.get("connected", 0),
            **{k: outcomes.get(k) or None for k in OUTCOMES if k != "connected"},
            "success_rate": round(outcomes.get("connected", 0) / len(attempts), 4) if attempts else None,
            "syn_retries": sum(r.get("syn_retries") or 0 for r in rs) or None,
            "connect_ms_p50": _p50(connect), "connect_ms_max": max(connect) if connect else None,
            "duration_s_p50": _p50(durations),
            "clients": len(clients),
            "max_concurrent": _max_concurrent([times.get(r.get("first_frame") or 0, (None, None)) for r in rs]),
            "first_frame": min(r.get("first_frame") or 0 for r in rs),
        }
        dest["issues"] = _dest_issues(server, rs, dest, times)
        out.append(compact(dest))
    out.sort(key=lambda d: (-(d["attempts"] - d["connected"]), -d["connections"], d["first_frame"]))
    return out


def _max_concurrent(spans: list[tuple[float | None, float | None]]) -> int:
    events = []
    for start, end in spans:
        if start is None:
            continue
        events.append((start, 1))
        events.append((end if end is not None else start, -1))
    events.sort(key=lambda e: (e[0], -e[1]))
    best = cur = 0
    for _t, step in events:
        cur += step
        best = max(best, cur)
    return best


def _frames(rs: list[dict[str, Any]], n: int = 3) -> str:
    frames = sorted(r.get("first_frame") or 0 for r in rs)[:n]
    return ", ".join(str(f) for f in frames)


def _dest_issues(server: str, rs: list[dict[str, Any]], dest: dict[str, Any],
                 times: dict[int, tuple[float | None, float | None]]) -> list[str]:
    issues: list[str] = []
    dropped = [r for r in rs if r["outcome"] == "filtered" and not r.get("near_capture_end")]
    connected = [r for r in rs if r["outcome"] == "connected"]
    if dropped:
        by_client: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in dropped:
            by_client[r["client"].rsplit(":", 1)[0]].append(r)
        ok_clients = {r["client"].rsplit(":", 1)[0] for r in connected}
        singled_out = {c: v for c, v in by_client.items() if c not in ok_clients and ok_clients}
        for client, v in singled_out.items():
            syns = sum(r.get("syns") or 1 for r in v)
            issues.append(f"{server} answers nothing to {syns} SYN{'s' if syns != 1 else ''} from {client} "
                          f"(frames {_frames(v)}) while {len(ok_clients)} other client{'s' if len(ok_clients) != 1 else ''} "
                          "connect: a host firewall or security group drops that source")
        rest = [r for c, v in by_client.items() if c not in singled_out for r in v]
        if rest:
            syns = sum(r.get("syns") or 1 for r in rest)
            tail = ("" if not connected else f"; {len(connected)} other attempt{'s' if len(connected) != 1 else ''} "
                    "connected, so the drops are intermittent")
            issues.append(f"{len(rest)} connection attempt{'s' if len(rest) != 1 else ''} to {server} "
                          f"({syns} SYN{'s' if syns != 1 else ''}, frames {_frames(rest)}) got no answer at all: a "
                          f"firewall drops them, or the host is down{tail}")
    refused = [r for r in rs if r["outcome"] == "refused"]
    if refused:
        issues.append(f"{server} refused {len(refused)} connection attempt{'s' if len(refused) != 1 else ''} with a "
                      f"reset (frames {_frames(refused)}): nothing listens on that port, or a firewall rejects with a reset")
    for kind in ("prohibited", "unreachable"):
        hit = [r for r in rs if r["outcome"] == kind]
        if not hit:
            continue
        senders: Counter[tuple[str, str]] = Counter()
        for r in hit:
            for e in r.get("icmp") or []:
                senders[(e["from"], e["error"])] += 1
        for (sender, error), n in senders.most_common(3):
            what = "a firewall rejects them" if kind == "prohibited" else "the path or the host is unreachable"
            issues.append(f"{sender} answered {n} SYN{'s' if n != 1 else ''} to {server} with ICMP {error} "
                          f"(frames {_frames(hit)}): {what}")
    rst_hs = [r for r in rs if r["outcome"] == "reset_during_handshake"]
    if rst_hs:
        issues.append(f"{len(rst_hs)} connection{'s' if len(rst_hs) != 1 else ''} to {server} reset after the SYN-ACK, "
                      f"before the handshake finished (frames {_frames(rst_hs)})")
    incomplete = [r for r in rs if r["outcome"] == "handshake_incomplete" and not r.get("near_capture_end")]
    if incomplete:
        issues.append(f"{len(incomplete)} SYN-ACK{'s' if len(incomplete) != 1 else ''} from {server} never acknowledged "
                      f"by the client (frames {_frames(incomplete)}): the SYN-ACK is lost on the way back, or "
                      "asymmetric routing sends it past the capture point")
    one_sided = [r for r in rs if r["outcome"] == "one_sided"]
    if one_sided:
        n = len(one_sided)
        issues.append(f"{n} connection{'s' if n != 1 else ''} to {server} {'are' if n != 1 else 'is'} in the capture in one "
                      f"direction only (frame{'s' if n != 1 else ''} {_frames(one_sided)}): the other side must have answered, so this is not "
                      "a connection failure; the capture point sees one direction (a one-way tap or asymmetric routing)")
    retried = [r for r in rs if r.get("syn_retries") and r["outcome"] == "connected"]
    if retried:
        worst = max(r["syn_retries"] for r in retried)
        issues.append(f"{len(retried)} connection{'s' if len(retried) != 1 else ''} to {server} needed SYN retries "
                      f"(up to {worst}) before the server answered: loss on the path or a full accept queue")
    p50 = dest.get("connect_ms_p50")
    if p50 is not None and p50 >= SLOW_CONNECT_MS:
        issues.append(f"connecting to {server} takes {p50} ms at the median")
    per_client: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rs:
        per_client[r["client"].rsplit(":", 1)[0]].append(r)
    for client, v in per_client.items():
        if len(v) < CHURN_MIN:
            continue
        starts = sorted(t for t in (times.get(r.get("first_frame") or 0, (None, None))[0] for r in v) if t is not None)
        if len(starts) < 2:
            continue
        span = max(starts[-1] - starts[0], 1.0)
        durations = [r["duration_s"] for r in v if r.get("duration_s") is not None]
        median = _p50(durations)
        if median is not None and median <= CHURN_SHORT_S:
            rate = round(len(v) / span * 60, 1)
            issues.append(f"{client} opened {len(v)} connections to {server} in {round(span, 1)} s ({rate} per minute), "
                          f"each lasting {median} s at the median: a new connection per request (no keep-alive or "
                          "connection pooling)")
    return issues
