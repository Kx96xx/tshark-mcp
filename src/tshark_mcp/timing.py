"""Where the time goes in a TCP request/response flow, from ``-T fields`` output.

Every TCP connection is cut into exchanges: a run of data from the client (the
request) followed by a run of data from the server (the response). For each
exchange the time is split the way the Wireshark TRANSUM method does it:

* network round trip: the SYN to SYN-ACK delay is the round trip from the
  capture point to the server, the SYN-ACK to ACK delay the one to the client;
  without a handshake in the capture the quickest ACK of each side stands in
* server time: last request byte to first response byte, less the round trip
  between the capture point and the server (so it is right wherever the
  capture was taken)
* transfer time: first to last response byte, with the stalls inside it
  (gaps over 200 ms and over three round trips) attributed to a retransmission,
  to the client advertising a zero window, or to the server pausing

The verdict per flow is the largest share: server-bound, network-bound
(round trips, retransmission stalls and transfer), receiver-bound (zero
window), or fast when every exchange finished within 100 ms. An answer that
comes more than 10 s after its request is a long poll, push or keep-alive
(``long_wait``) and is left out of the split; a flow made only of those is
idle-or-push. Requests that never got a response and connections that never
opened are reported too.

A segment below the highest sequence already seen is a retransmission when that
sequence was seen before; otherwise it was overtaken on the way (out of order)
when its IPv4 ID is lower than the newest segment's, and without an IP ID when
it came within one round trip of the newest data, as tshark decides. tshark
itself ignores the IP ID and calls many reordered segments retransmissions.

Copies of the same packet (captured on two interfaces, or tunnelled and
decapsulated) are counted once: same direction, sequence number, length,
flags and IPv4 ID within 50 ms (within 1 ms when there is no IP ID), and a
tap's copy with an all-zero TCP header is dropped.
HTTP/1.x method, URI and status are attached when tshark dissects them.
Pipelined or multiplexed protocols (HTTP/2, gRPC) still split into exchanges
by direction, which then group several requests each.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .fields import compact, iso, parse_time, split_fields_line, to_int

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.protocols",
    "ip.src", "ip.dst", "ip.id", "ipv6.src", "ipv6.dst",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.len",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset", "tcp.window_size_value",
    "http.request.method", "http.request.uri", "http.host", "http.response.code",
]
AGGREGATOR = "|"
BASE_FILTER = "tcp && !icmp && !icmpv6"

COPY_WINDOW = 0.05       # IPv4 copies: same IP ID within this
COPY_WINDOW_NO_ID = 0.001  # IPv6 (or IP ID 0): no ID to compare, so only a near-simultaneous twin is a copy
STALL_MIN = 0.2          # seconds: a gap shorter than this is never a stall
STALL_RTTS = 3           # ... and it must also be longer than this many round trips
FAST_MS = 100.0          # a flow whose exchanges all finished within this is fast
MAX_EXCHANGES_SHOWN = 3
IDLE_S = 10.0            # a wait longer than this is a long poll, a push or a keep-alive, not a slow server


def display_filter() -> str:
    return BASE_FILTER


def _truthy(value: str) -> bool:
    return value in ("1", "True", "true")


def _nth(values: list[str], n: int) -> str:
    return values[n] if 0 <= n < len(values) else ""


def _last(values: list[str]) -> str:
    return values[-1] if values else ""


def _ms(seconds: float | None) -> float | None:
    return None if seconds is None else round(seconds * 1000, 3)


def parse(stdout: str) -> list[dict[str, Any]]:
    packets = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(FIELDS):
            continue
        raw = {k: (v.split(AGGREGATOR) if v else []) for k, v in zip(FIELDS, cols)}
        layers = [p for p in _nth(raw["frame.protocols"], 0).split(":") if p]
        ip_layers = [p for p in layers if p in ("ip", "ipv6")]
        v6 = bool(ip_layers) and ip_layers[-1] == "ipv6"
        t = parse_time(_nth(raw["frame.time_epoch"], 0))
        if t is None:
            continue
        packets.append({
            "frame": to_int(_nth(raw["frame.number"], 0)), "time": t,
            "src": _last(raw["ipv6.src"]) if v6 else _last(raw["ip.src"]),
            "dst": _last(raw["ipv6.dst"]) if v6 else _last(raw["ip.dst"]),
            "ip_id": None if v6 else to_int(_last(raw["ip.id"])),
            "stream": _last(raw["tcp.stream"]), "sport": _last(raw["tcp.srcport"]), "dport": _last(raw["tcp.dstport"]),
            "seq": to_int(_last(raw["tcp.seq_raw"])), "ack_no": to_int(_last(raw["tcp.ack_raw"])),
            "len": to_int(_last(raw["tcp.len"]), 0) or 0,
            "syn": _truthy(_last(raw["tcp.flags.syn"])), "ack": _truthy(_last(raw["tcp.flags.ack"])),
            "fin": _truthy(_last(raw["tcp.flags.fin"])), "rst": _truthy(_last(raw["tcp.flags.reset"])),
            "window": to_int(_last(raw["tcp.window_size_value"])),
            "method": _nth(raw["http.request.method"], 0), "uri": _nth(raw["http.request.uri"], 0),
            "host": _nth(raw["http.host"], 0), "status": to_int(_nth(raw["http.response.code"], 0)),
        })
    return packets


def _drop_copies(packets: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    seen: dict[tuple, float] = {}
    kept: list[dict[str, Any]] = []
    copies: dict[str, int] = defaultdict(int)
    for p in packets:
        if not (p["syn"] or p["ack"] or p["rst"]):
            copies[p["stream"]] += 1  # every segment after the SYN carries ACK: this is a tap's zeroed copy
            continue
        # A retransmission repeats the sequence number too but leaves with a new IP ID; a copy of the
        # same packet keeps it. Without an IP ID only a twin within a millisecond counts as a copy.
        key = (p["src"], p["sport"], p["dst"], p["dport"], p["seq"], p["len"], p["syn"], p["fin"], p["rst"], p["ack_no"],
               p["ip_id"])
        prev = seen.get(key)
        seen[key] = p["time"]
        window = COPY_WINDOW if p["ip_id"] else COPY_WINDOW_NO_ID
        if prev is not None and p["time"] - prev <= window:
            copies[p["stream"]] += 1
            continue
        kept.append(p)
    return kept, copies


def _client_of(pkts: list[dict[str, Any]]) -> tuple[str, str]:
    for p in pkts:
        if p["syn"] and not p["ack"]:
            return p["src"], p["sport"]
    for p in pkts:
        if p["syn"] and p["ack"]:
            return p["dst"], p["dport"]
    first = pkts[0]
    a, b = (first["src"], first["sport"]), (first["dst"], first["dport"])
    # Without a handshake the side on the higher (ephemeral) port is taken as the client.
    return a if (to_int(a[1], 0) or 0) >= (to_int(b[1], 0) or 0) else b


def _rtt_from_acks(pkts: list[dict[str, Any]], sender: tuple[str, str]) -> float | None:
    """Quickest ACK from the other side covering a data segment of ``sender`` (no handshake in the capture)."""
    sent: dict[int, float] = {}
    best = None
    for p in pkts:
        side = (p["src"], p["sport"])
        if side == sender and p["len"] and p["seq"] is not None:
            sent.setdefault((p["seq"] + p["len"]) & 0xFFFFFFFF, p["time"])
        elif side != sender and p["ack"] and p["ack_no"] in sent:
            gap = p["time"] - sent.pop(p["ack_no"])
            if gap >= 0 and (best is None or gap < best):
                best = gap
    return best


def _connections(packets: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Packets grouped per TCP connection by address and port pair rather than by tcp.stream.

    tshark starts a new tcp.stream when a tap's zeroed copy (sequence 0) sits between a SYN and its
    SYN-ACK, which splits one connection in two. A new SYN with another initial sequence number on a
    pair that already closed or carried data is a new connection (port reuse)."""
    groups: dict[str, list[dict[str, Any]]] = {}
    current: dict[frozenset, dict[str, Any]] = {}
    for p in packets:
        pair = frozenset({(p["src"], p["sport"]), (p["dst"], p["dport"])})
        conn = current.get(pair)
        new_syn = p["syn"] and not p["ack"]
        if conn is None or (new_syn and conn["syn_seq"] is not None and p["seq"] != conn["syn_seq"]
                            and (conn["closed"] or conn["data"])):
            conn = current[pair] = {"id": p["stream"], "syn_seq": None, "closed": False, "data": False}
            while conn["id"] in groups:
                conn["id"] = f"{conn['id']}+"
            groups[conn["id"]] = []
        if new_syn and conn["syn_seq"] is None:
            conn["syn_seq"] = p["seq"]
        conn["closed"] = conn["closed"] or p["fin"] or p["rst"]
        conn["data"] = conn["data"] or bool(p["len"])
        groups[conn["id"]].append(p)
    return groups


def analyse_stream(pkts: list[dict[str, Any]]) -> dict[str, Any]:
    client = _client_of(pkts)
    syns = [p for p in pkts if p["syn"] and not p["ack"]]
    synacks = [p for p in pkts if p["syn"] and p["ack"]]
    syn = syns[0] if syns else None
    synack = synacks[0] if synacks else None
    hs_ack = None
    if synack is not None:
        hs_ack = next((p for p in pkts if p["time"] >= synack["time"] and (p["src"], p["sport"]) == client
                       and p["ack"] and not p["syn"]), None)
    server_rtt = client_rtt = connect = None
    rtt_source = None
    syn_retx = synack_retx = 0
    if syn is not None and synack is not None:
        # With retransmitted SYNs or SYN-ACKs the round trip is taken from the last SYN before the
        # client's ACK (as tshark's tcp.analysis.initial_rtt does), split at the first SYN-ACK after it.
        until = hs_ack["time"] if hs_ack is not None else float("inf")
        last_syn = ([x for x in syns if x["time"] <= until] or syns[:1])[-1]
        after = [a for a in synacks if last_syn["time"] <= a["time"] <= until]
        if after:
            server_rtt = after[0]["time"] - last_syn["time"]
            if hs_ack is not None:
                client_rtt = hs_ack["time"] - after[0]["time"]
        else:  # the SYN-ACK answering the last SYN was not captured: use the quickest SYN to SYN-ACK pair
            gaps = [next((a["time"] for a in synacks if a["time"] >= x["time"]), None) for x in syns]
            server_rtt = min((g - x["time"] for g, x in zip(gaps, syns) if g is not None), default=None)
            if hs_ack is not None and server_rtt is not None:
                client_rtt = max(0.0, hs_ack["time"] - last_syn["time"] - server_rtt)
        if hs_ack is not None:
            connect = hs_ack["time"] - syn["time"]
        syn_retx = len([x for x in syns if x["time"] <= until]) - 1
        synack_retx = len([a for a in synacks if a["time"] <= until]) - 1
        rtt_source = "handshake"
    server = next(((p["dst"], p["dport"]) if (p["src"], p["sport"]) == client else (p["src"], p["sport"]) for p in pkts))
    if server_rtt is None:
        server_rtt = _rtt_from_acks(pkts, client)
        client_rtt = _rtt_from_acks(pkts, server)
        rtt_source = "acks" if server_rtt is not None or client_rtt is not None else None
    rtt = (server_rtt or 0) + (client_rtt or 0) if (server_rtt is not None or client_rtt is not None) else None

    exchanges: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    high = {"client": None, "server": None}
    high_time = {"client": 0.0, "server": 0.0}
    high_id: dict[str, int | None] = {"client": None, "server": None}
    sent: dict[str, set[int]] = {"client": set(), "server": set()}
    reorder_window = max(rtt or 0.0, 0.003)
    zero_windows: list[float] = []
    resets = Counter()
    closed: dict[str, str] = {}
    pushes = 0
    for p in pkts:
        side = "client" if (p["src"], p["sport"]) == client else "server"
        if p["rst"]:
            resets[side] += 1
            closed.setdefault(side, "reset")
        elif p["fin"]:
            closed.setdefault(side, "fin")
        if p["window"] == 0 and not p["syn"] and not p["rst"] and p["ack"]:
            zero_windows.append(p["time"])
            if side == "client" and cur is not None:
                cur["client_zero_window"].append(p["time"])
        if not p["len"] or p["seq"] is None:
            continue
        end = (p["seq"] + p["len"]) & 0xFFFFFFFF
        # Below the highest sequence already seen: a resend of a segment seen before, or of one lost
        # before the capture point, is a retransmission; a segment that fills a gap within one round
        # trip of the newest data is out of order (tshark's own rule).
        # With IPv4 IDs the order the sender sent in is known: a lower ID than the newest segment's
        # means the segment was sent first and overtaken on the way, whatever the timing.
        retx = ooo = False
        if high[side] is not None and p["len"] > 1 and _seq_le(end, high[side]):
            sent_earlier = (p["ip_id"] and high_id[side] and ((high_id[side] - p["ip_id"]) & 0xFFFF) < 0x8000)
            if p["seq"] in sent[side]:
                retx = True
            elif p["ip_id"] and high_id[side]:
                ooo, retx = bool(sent_earlier), not sent_earlier
            elif p["time"] - high_time[side] >= reorder_window:
                retx = True
            else:
                ooo = True
        sent[side].add(p["seq"])
        if high[side] is None or not _seq_le(end, high[side]):
            high[side], high_time[side], high_id[side] = end, p["time"], p["ip_id"]
        if side == "client":
            idle = cur is not None and cur["response_first"] is None and p["time"] - cur["request_last"] > IDLE_S
            if cur is None or cur["response_first"] is not None or idle:
                cur = {"request_first": p["time"], "request_last": p["time"], "request_bytes": 0, "request_frame": p["frame"],
                       "response_first": None, "response_last": None, "response_bytes": 0, "response_frame": None,
                       "server_segments": [], "client_zero_window": [], "retransmissions": 0,
                       "out_of_order": 0}
                exchanges.append(cur)
            cur["request_last"] = p["time"]
            cur["request_bytes"] += p["len"]
            if retx:
                cur["retransmissions"] += 1
            cur["out_of_order"] += ooo
            if p["method"] and "method" not in cur:
                cur["method"], cur["uri"], cur["host"] = p["method"], p["uri"], p["host"]
        else:
            if cur is None or cur.get("pushed"):
                continue  # server data before any request (a banner, a capture started mid-response) or a push
            if cur["response_last"] is not None and p["time"] - cur["response_last"] > IDLE_S:
                # Data long after the response ended, with no new request: the server pushing on an
                # idle connection (a notification, a keep-alive, an HTTP/2 PING), not part of the answer.
                cur["pushed"] = True
                pushes += 1
                continue
            if cur["response_first"] is None:
                cur["response_first"], cur["response_frame"] = p["time"], p["frame"]
            cur["response_last"] = p["time"]
            cur["response_bytes"] += p["len"]
            cur["server_segments"].append((p["time"], retx))
            if retx:
                cur["retransmissions"] += 1
            cur["out_of_order"] += ooo
            if p["status"] and "status" not in cur:
                cur["status"] = p["status"]

    rows = [_exchange_row(x, server_rtt, rtt) for x in exchanges]
    return {"client": client, "server": server, "syn": syn, "synack": synack, "server_rtt": server_rtt,
            "connect": connect, "syn_retransmissions": syn_retx, "synack_retransmissions": synack_retx,
            "client_rtt": client_rtt, "rtt": rtt, "rtt_source": rtt_source, "exchanges": rows,
            "zero_windows": len(zero_windows), "resets": dict(resets), "closed": closed, "server_pushes": pushes,
            "first": pkts[0]["time"], "last": pkts[-1]["time"], "frame": pkts[0]["frame"]}


def _seq_le(a: int, b: int) -> bool:
    """a <= b in 32-bit sequence space."""
    return ((b - a) & 0xFFFFFFFF) < 0x80000000


def _exchange_row(x: dict[str, Any], server_rtt: float | None, rtt: float | None) -> dict[str, Any]:
    row: dict[str, Any] = {"frame": x["request_frame"], "time": iso(x["request_first"]),
                           "request_bytes": x["request_bytes"], "request_ms": _ms(x["request_last"] - x["request_first"])}
    for k in ("method", "uri", "host", "status"):
        if x.get(k):
            row[k] = x[k]
    if x["response_first"] is None:
        row.update({"no_response": True, "retransmissions": x["retransmissions"] or None,
                    "out_of_order": x["out_of_order"] or None})
        return compact(row)
    think = x["response_first"] - x["request_last"]
    server = max(0.0, think - (server_rtt or 0.0))
    long_wait = think > IDLE_S
    transfer = x["response_last"] - x["response_first"]
    stall_min = max(STALL_MIN, STALL_RTTS * (rtt or 0.0))
    stalls = {"retransmission": 0.0, "zero_window": 0.0, "server_pause": 0.0}
    stall_list = []
    segs = x["server_segments"]
    for (t0, _), (t1, retx) in zip(segs, segs[1:]):
        gap = t1 - t0
        if gap <= stall_min:
            continue
        if retx:
            cause = "retransmission"
        elif any(t0 <= z <= t1 for z in x["client_zero_window"]):
            cause = "zero_window"
        else:
            cause = "server_pause"
        stalls[cause] += gap
        stall_list.append({"at": iso(t0), "gap_ms": _ms(gap), "cause": cause})
    row.update({
        "response_frame": x["response_frame"], "response_bytes": x["response_bytes"],
        "think_ms": _ms(think), "server_ms": _ms(server), "transfer_ms": _ms(transfer),
        "total_ms": _ms(x["response_last"] - x["request_first"]),
        "retransmissions": x["retransmissions"] or None, "out_of_order": x["out_of_order"] or None,
    })
    if stall_list:
        row["stalls"] = stall_list[:5]
    row = compact(row)
    if long_wait:
        # The answer came more than IDLE_S after the request: a long poll, a server push or a keep-alive
        # reply. Counting it as server time would call every push channel a slow server.
        row["long_wait"] = True
        return row
    row["_split"] = {"rtt": rtt or 0.0, "server": server, "transfer": max(0.0, transfer - sum(stalls.values())),
                     **stalls}
    return row


def _verdict(split: dict[str, float], exchanges: list[dict[str, Any]]) -> tuple[str, str]:
    answered = [x for x in exchanges if not x.get("no_response") and not x.get("long_wait")]
    if exchanges and not answered:
        if any(x.get("long_wait") for x in exchanges):
            return "idle-or-push", (f"every answer came more than {IDLE_S:g} s after its request: a long poll, "
                                    "push channel or keep-alive, not a slow server")
        return "no-response", "requests got no response in the capture"
    if answered and all((x.get("total_ms") or 0) <= FAST_MS for x in answered):
        return "fast", f"every exchange finished within {FAST_MS:g} ms"
    network = split["network_rtt"] + split["transfer"] + split["retransmission_stalls"]
    parts = {"server-bound": split["server"] + split["server_pauses"], "network-bound": network,
             "receiver-bound": split["zero_window_stalls"]}
    verdict = max(parts, key=lambda k: parts[k])
    total = sum(parts.values()) or 1.0
    share = round(100 * parts[verdict] / total)
    why = {
        "server-bound": f"{share}% of the time is the server working before it answers or pausing mid-response",
        "network-bound": f"{share}% of the time is round trips, transfer and retransmission stalls",
        "receiver-bound": f"{share}% of the time the client advertised a zero window",
    }[verdict]
    return verdict, why


def summarise(packets: list[dict[str, Any]]) -> dict[str, Any]:
    kept, copies = _drop_copies(packets)
    streams = _connections(kept)
    flows = []
    unopened = []
    for sid, pkts in streams.items():
        info = analyse_stream(pkts)
        has_data = any(p["len"] for p in pkts)
        if info["syn"] is not None and info["synack"] is None and not has_data:
            refused = any(p["rst"] for p in pkts if (p["src"], p["sport"]) == info["server"])
            unopened.append(compact({
                "stream": to_int(sid.rstrip("+")), "frame": info["frame"], "time": iso(info["first"]),
                "client": f"{info['client'][0]}:{info['client'][1]}", "server": f"{info['server'][0]}:{info['server'][1]}",
                "outcome": "refused" if refused else "no_answer",
                "syn_attempts": sum(1 for p in pkts if p["syn"] and not p["ack"]),
            }))
            continue
        if not info["exchanges"]:
            continue
        split = {"network_rtt": 0.0, "server": 0.0, "transfer": 0.0, "retransmission_stalls": 0.0,
                 "zero_window_stalls": 0.0, "server_pauses": 0.0}
        for x in info["exchanges"]:
            s = x.pop("_split", None)
            if not s:
                continue
            split["network_rtt"] += s["rtt"]
            split["server"] += s["server"]
            split["transfer"] += s["transfer"]
            split["retransmission_stalls"] += s["retransmission"]
            split["zero_window_stalls"] += s["zero_window"]
            split["server_pauses"] += s["server_pause"]
        verdict, why = _verdict(split, info["exchanges"])
        answered = [x for x in info["exchanges"] if not x.get("no_response")]
        timed = [x for x in answered if not x.get("long_wait")]
        slowest = sorted(info["exchanges"], key=lambda x: (bool(x.get("long_wait")), -(x.get("total_ms") or 0)))[:MAX_EXCHANGES_SHOWN]
        flows.append(compact({
            "stream": to_int(sid.rstrip("+")), "tcp_streams": _streams_of(pkts),
            "client": f"{info['client'][0]}:{info['client'][1]}",
            "server": f"{info['server'][0]}:{info['server'][1]}", "frame": info["frame"], "first": iso(info["first"]),
            "duration_ms": _ms(info["last"] - info["first"]),
            "rtt_ms": _ms(info["rtt"]), "rtt_capture_to_server_ms": _ms(info["server_rtt"]),
            "rtt_capture_to_client_ms": _ms(info["client_rtt"]), "rtt_source": info["rtt_source"],
            "connect_ms": _ms(info["connect"]) if info["syn_retransmissions"] or info["synack_retransmissions"] else None,
            "syn_retransmissions": info["syn_retransmissions"] or None,
            "synack_retransmissions": info["synack_retransmissions"] or None,
            "capture_near": _vantage(info["server_rtt"], info["client_rtt"]),
            "exchanges": len(info["exchanges"]), "unanswered_requests": len(info["exchanges"]) - len(answered) or None,
            "long_waits": sum(1 for x in info["exchanges"] if x.get("long_wait")) or None,
            "server_pushes": info["server_pushes"] or None,
            "max_server_ms": max((x.get("server_ms") or 0 for x in timed), default=None) if timed else None,
            "time_split_ms": {k: _ms(v) for k, v in split.items() if v},
            "verdict": verdict, "why": why,
            "retransmissions": sum(x.get("retransmissions") or 0 for x in info["exchanges"]) or None,
            "out_of_order": sum(x.get("out_of_order") or 0 for x in info["exchanges"]) or None,
            "zero_windows": info["zero_windows"] or None, "resets": info["resets"] or None, "closed": info["closed"] or None,
            "duplicate_copies": sum(copies.get(x, 0) for x in {p["stream"] for p in pkts}) or None,
            "slowest_exchanges": slowest,
            "_server_ms": [x["server_ms"] for x in timed if x.get("server_ms") is not None],
            "_worst": max((x.get("total_ms") or 0 for x in timed), default=0),
        }))
    flows.sort(key=lambda f: (f["verdict"] in ("fast", "idle-or-push"), -f["_worst"]))
    servers = _per_server(flows)
    for f in flows:
        f.pop("_worst", None)
        f.pop("_server_ms", None)
    summary = {
        "flows": len(flows), "verdicts": dict(Counter(f["verdict"] for f in flows)),
        "connections_not_opened": len(unopened) or None, "duplicate_copies": sum(copies.values()) or None,
    }
    return {"flows": flows, "servers": servers, "not_opened": unopened[:50], "summary": compact(summary),
            "issues": _issues(flows, unopened)}


def _streams_of(pkts: list[dict[str, Any]]) -> list[int] | None:
    """tshark's tcp.stream numbers when one connection spans several (otherwise None)."""
    ids = sorted({to_int(p["stream"]) for p in pkts if to_int(p["stream"]) is not None})
    return ids if len(ids) > 1 else None


def _vantage(server_rtt: float | None, client_rtt: float | None) -> str | None:
    if server_rtt is None or client_rtt is None:
        return None
    if server_rtt < client_rtt / 4:
        return "server"
    if client_rtt < server_rtt / 4:
        return "client"
    return "middle"


def _pct(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    rank = max(1, -(-len(values) * pct // 100))
    return values[int(rank) - 1]


def _per_server(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in flows:
        groups[f["server"]].append(f)
    out = []
    for server, group in groups.items():
        server_ms = [v for f in group for v in f.get("_server_ms", [])]
        rtts = [f["rtt_ms"] for f in group if f.get("rtt_ms") is not None]
        out.append(compact({
            "server": server, "flows": len(group), "exchanges": sum(f["exchanges"] for f in group),
            "verdicts": dict(Counter(f["verdict"] for f in group)),
            "rtt_ms_median": _pct(rtts, 50), "server_ms_p50": _pct(server_ms, 50), "server_ms_p90": _pct(server_ms, 90),
            "server_ms_max": max(server_ms) if server_ms else None,
        }))
    out.sort(key=lambda r: -(r.get("server_ms_max") or 0))
    return out[:50]


def _issues(flows: list[dict[str, Any]], unopened: list[dict[str, Any]]) -> list[str]:
    issues = []
    by_verdict: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in flows:
        by_verdict[f["verdict"]].append(f)
    for verdict in ("server-bound", "network-bound", "receiver-bound", "no-response"):
        group = by_verdict.get(verdict)
        if not group:
            continue
        servers = Counter(f["server"] for f in group).most_common(3)
        issues.append(f"{len(group)} flows are {verdict} (" + ", ".join(f"{s} x{n}" for s, n in servers) + ")")
    lossy_down = [f for f in flows if f.get("synack_retransmissions")]
    if lossy_down:
        issues.append(f"{len(lossy_down)} connections needed the SYN-ACK more than once before the client acknowledged "
                      f"it (up to {max(f['synack_retransmissions'] for f in lossy_down) + 1} times, up to "
                      f"{max(f.get('connect_ms') or 0 for f in lossy_down):g} ms to connect): packets toward the client are lost or held up")
    lossy_up = [f for f in flows if f.get("syn_retransmissions") and not f.get("synack_retransmissions")]
    if lossy_up:
        issues.append(f"{len(lossy_up)} connections sent the SYN more than once before an answer: the SYN or its "
                      "answer was lost on the way, or the server was slow to accept")
    stalls = Counter(s["cause"] for f in flows for x in f.get("slowest_exchanges", []) for s in x.get("stalls", []))
    for cause, n in stalls.most_common():
        issues.append(f"{n} stalls inside responses caused by {cause.replace('_', ' ')}")
    if unopened:
        c = Counter(u["outcome"] for u in unopened)
        issues.append(", ".join(f"{n} connections {o.replace('_', ' ')}" for o, n in c.items()) + " at the SYN")
    return issues
