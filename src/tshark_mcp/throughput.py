"""throughput_timeline: bytes, goodput and the events that explain them, per interval.

One ``-T fields`` pass reads every frame's time, length, addresses and the TCP numbers;
everything else is computed here. Goodput is the new data a receiver acknowledged (from
``tcp.ack_raw``), so copies of a packet and retransmissions never count twice. Copies (the
same IP ID, sequence number and length within a second, from a capture on two taps) are
dropped first, as in tcp_health. Per interval the counters that explain a slowdown sit next
to the bytes: retransmitted bytes, zero windows, window-full events, duplicate ACKs, new
connections and SYNs never answered, plus the DNS queries, TLS ClientHellos and ICMP errors
whose bursts give the general-protocol view of message_rates.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .fields import iso, parse_time, to_int

FIELDS = [
    "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "ip.id",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.len", "tcp.seq_raw", "tcp.ack_raw",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.window_size",
    "tcp.analysis.zero_window", "tcp.analysis.window_full", "tcp.analysis.duplicate_ack",
    "tcp.analysis.bytes_in_flight", "udp.srcport", "udp.dstport",
    "dns.flags.response", "tls.handshake.type", "icmp.type", "icmpv6.type", "frame.number",
]
PERS = ("total", "conversation", "host", "stream")
COUNTERS = ("syns", "syns_unanswered", "dns_queries", "tls_client_hellos", "icmp_errors")
MAX_INTERVALS = 10_000
COPY_WINDOW_S = 1.0
LOSS_SHARE = 0.02          # retransmitted share of a stream's data bytes: loss-limited
RWND_SHARE = 0.20          # share of active intervals with a zero window or a full window: receiver-limited
IDLE_SHARE = 0.50          # share of the stream's life without a packet: application-idle
BURST_FACTOR = 3.0         # an interval at three times the usual rate of a counter
BURST_MIN = 10
_ICMP_ERRORS = {3, 4, 5, 11, 12}
_ICMP6_ERRORS = {1, 2, 3, 4}
SEQ_MOD = 2 ** 32


def _flag(value: str) -> bool:
    return bool(value) and value not in ("0", "False", "false")


def _ahead(a: int, b: int) -> int:
    """How far sequence number ``a`` is past ``b`` (negative when behind), modulo 2**32."""
    d = (a - b) % SEQ_MOD
    return d - SEQ_MOD if d >= SEQ_MOD // 2 else d


@dataclass
class _Dir:
    top_seq: int | None = None      # highest seq + len sent
    top_ack: int | None = None      # highest ack this side's peer sent (bytes acknowledged)
    data: int = 0
    retrans: int = 0


@dataclass
class _Stream:
    index: int
    key: str
    client: str
    server: str
    first: float
    last: float
    syn_time: float | None = None
    answered: bool = False
    dirs: dict[str, _Dir] = field(default_factory=lambda: defaultdict(_Dir))
    bins: dict[int, dict[str, float]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(float)))
    max_in_flight: int = 0
    max_window: int = 0
    first_frame: int | None = None


AUTO_INTERVALS = (1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0, 21_600.0, 86_400.0)


def auto_interval(span: float) -> float:
    """The smallest round interval that covers ``span`` seconds in at most MAX_INTERVALS intervals."""
    for step in AUTO_INTERVALS:
        if span / step + 1 <= MAX_INTERVALS:
            return step
    return AUTO_INTERVALS[-1]


def _bin() -> dict[str, float]:
    return defaultdict(float)


def parse(stdout: str) -> list[dict[str, Any]]:
    rows = []
    for line in stdout.splitlines():
        cols = line.split("\t")
        if len(cols) < len(FIELDS):
            cols += [""] * (len(FIELDS) - len(cols))
        r = dict(zip(FIELDS, cols))
        t = parse_time(r["frame.time_epoch"])
        if t is None:
            continue
        r["_t"] = t
        r["_frame"] = to_int(r["frame.number"])
        rows.append(r)
    return rows


def analyse(packets: list[dict[str, Any]], interval: float, per: str, top: int) -> dict[str, Any]:
    """Intervals, per-key series, per-stream verdicts and issues (see the module docstring)."""
    if not packets:
        return {"intervals": [], "series": [], "streams": [], "issues": [], "summary": {"packets": 0}}
    t0 = min(p["_t"] for p in packets)
    t_end = max(p["_t"] for p in packets)
    n_bins = int(math.floor((t_end - t0) / interval)) + 1
    total: dict[int, dict[str, float]] = defaultdict(_bin)
    keyed: dict[str, dict[int, dict[str, float]]] = defaultdict(lambda: defaultdict(_bin))
    key_bytes: dict[str, float] = defaultdict(float)
    streams: dict[str, _Stream] = {}
    seen_copies: dict[tuple, float] = {}
    copies = 0
    for p in packets:
        t = p["_t"]
        b = int((t - t0) / interval)
        src = p["ip.src"].split(",")[0] or p["ipv6.src"].split(",")[0]
        dst = p["ip.dst"].split(",")[0] or p["ipv6.dst"].split(",")[0]
        stream_id = to_int(p["tcp.stream"].split(",")[0])
        tlen = to_int(p["tcp.len"].split(",")[0]) or 0
        seq = to_int(p["tcp.seq_raw"].split(",")[0])
        ip_id = p["ip.id"].split(",")[0]
        if stream_id is not None and seq is not None and ip_id and ip_id not in ("0x0000", "0"):
            ck = (src, dst, ip_id, seq, tlen, p["tcp.ack_raw"])
            prev = seen_copies.get(ck)
            if prev is not None and t - prev <= COPY_WINDOW_S:
                copies += 1
                continue
            seen_copies[ck] = t
        size = to_int(p["frame.len"]) or 0
        row = total[b]
        row["packets"] += 1
        row["bytes"] += size
        sport = p["tcp.srcport"] or p["udp.srcport"]
        dport = p["tcp.dstport"] or p["udp.dstport"]
        a_end, b_end = f"{src}:{sport}" if sport else src, f"{dst}:{dport}" if dport else dst
        if per == "conversation":
            pair = sorted([src, dst])
            keys = [(f"{pair[0]} <-> {pair[1]}", "a_to_b" if src == pair[0] else "b_to_a")]
        elif per == "host":
            keys = [(src, "sent"), (dst, "received")]
        elif per == "stream":
            pair = sorted([a_end, b_end])
            keys = [(f"{pair[0]} <-> {pair[1]}", "a_to_b" if a_end == pair[0] else "b_to_a")] if sport else []
        else:
            keys = []
        for key, direction in keys:
            kb = keyed[key][b]
            kb["packets"] += 1
            kb[f"bytes_{direction}"] += size
            key_bytes[key] += size
        # Counters every interval carries.
        syn, ack = _flag(p["tcp.flags.syn"]), _flag(p["tcp.flags.ack"])
        if p["dns.flags.response"] and not _flag(p["dns.flags.response"].split(",")[0]):
            row["dns_queries"] += 1
        if "1" in p["tls.handshake.type"].split(","):
            row["tls_client_hellos"] += 1
        icmp_t = to_int(p["icmp.type"].split(",")[0])
        icmp6_t = to_int(p["icmpv6.type"].split(",")[0])
        if (icmp_t in _ICMP_ERRORS) or (icmp6_t in _ICMP6_ERRORS):
            row["icmp_errors"] += 1
            continue  # the quoted TCP header inside is not this host's traffic
        if stream_id is None:
            continue
        skey = str(stream_id)
        st = streams.get(skey)
        if st is None:
            if syn:
                client_first = not ack
            else:  # joined midway: the higher port is most likely the client's
                client_first = (to_int(sport) or 0) > (to_int(dport) or 0)
            client, server = (a_end, b_end) if client_first else (b_end, a_end)
            st = streams[skey] = _Stream(index=stream_id, key=f"{client} -> {server}", client=client, server=server,
                                         first=t, last=t, first_frame=p.get("_frame"))
        st.last = t
        if syn and not ack:
            if st.syn_time is None:
                st.syn_time = t
                row["syns"] += 1
        elif syn and ack:
            st.answered = True
        d = st.dirs[a_end]
        sb = st.bins[b]
        sb["bytes"] += size
        sb["packets"] += 1
        win = to_int(p["tcp.window_size"].split(",")[0])
        if win is not None:
            st.max_window = max(st.max_window, win)
        fl = to_int(p["tcp.analysis.bytes_in_flight"].split(",")[0])
        if fl is not None:
            st.max_in_flight = max(st.max_in_flight, fl)
        if tlen > 0 and seq is not None:
            end = (seq + tlen) % SEQ_MOD
            d.data += tlen
            if d.top_seq is not None and _ahead(end, d.top_seq) <= 0:
                d.retrans += tlen
                row["retransmitted_bytes"] += tlen
                sb["retransmitted_bytes"] += tlen
                for key, _direction in keys:
                    keyed[key][b]["retransmitted_bytes"] += tlen
            else:
                d.top_seq = end
        ack_raw = to_int(p["tcp.ack_raw"].split(",")[0])
        if ack and ack_raw is not None and not syn:
            peer = st.dirs[b_end]  # this ACK acknowledges what the peer sent
            if peer.top_ack is None:
                peer.top_ack = ack_raw
            else:
                gained = _ahead(ack_raw, peer.top_ack)
                if 0 < gained < SEQ_MOD // 4:
                    peer.top_ack = ack_raw
                    row["acked_bytes"] += gained
                    sb["acked_bytes"] += gained
                    for key, _direction in keys:
                        keyed[key][b]["acked_bytes"] += gained
        for name, fld in (("zero_windows", "tcp.analysis.zero_window"), ("window_full", "tcp.analysis.window_full"),
                          ("duplicate_acks", "tcp.analysis.duplicate_ack")):
            if p[fld]:
                row[name] += 1
                sb[name] += 1
    for st in streams.values():
        if st.syn_time is not None and not st.answered:
            total[int((st.syn_time - t0) / interval)]["syns_unanswered"] += 1

    def out_row(i: int, r: dict[str, float]) -> dict[str, Any]:
        o: dict[str, Any] = {"index": i, "start": iso(t0 + i * interval), "offset_s": round(i * interval, 6)}
        for k, v in r.items():
            if v:
                o[k] = int(v)
        o["bps"] = round(r.get("bytes", 0) * 8 / interval, 1)
        if r.get("acked_bytes"):
            o["goodput_bps"] = round(r["acked_bytes"] * 8 / interval, 1)
        return o

    intervals = [out_row(i, total.get(i, {})) for i in range(n_bins)]
    top_keys = sorted(key_bytes, key=lambda k: -key_bytes[k])[:top]
    series = []
    for key in top_keys:
        bins = keyed[key]
        rows = [out_row(i, bins[i]) for i in sorted(bins)]
        peak = max((r["bps"] for r in rows), default=0)
        series.append({"key": key, "bytes": int(key_bytes[key]), "peak_bps": peak,
                       "mean_bps": round(key_bytes[key] * 8 / (n_bins * interval), 1), "intervals": rows})
    stream_rows = [_stream_row(st, t0, interval) for st in streams.values()]
    stream_rows = [r for r in stream_rows if r["bytes"] > 0]
    stream_rows.sort(key=lambda r: -r["bytes"])
    issues = _issues(intervals, stream_rows, interval)
    summary = {
        "packets": int(sum(r.get("packets", 0) for r in total.values())),
        "bytes": int(sum(r.get("bytes", 0) for r in total.values())),
        "first": iso(t0), "last": iso(t_end), "span_s": round(t_end - t0, 6), "interval_s": interval,
        "intervals": n_bins, "idle_intervals": sum(1 for r in intervals if not r.get("packets")),
        "peak_bps": max((r["bps"] for r in intervals), default=0),
        "mean_bps": round(sum(r.get("bytes", 0) for r in total.values()) * 8 / (n_bins * interval), 1),
        "peak_goodput_bps": max((r.get("goodput_bps", 0) for r in intervals), default=0),
        "retransmitted_bytes": int(sum(r.get("retransmitted_bytes", 0) for r in total.values())),
        "tcp_streams": len(streams), "copies_dropped": copies,
    }
    for c in COUNTERS:
        summary[c] = int(sum(r.get(c, 0) for r in total.values()))
    return {"intervals": intervals, "series": series, "streams": stream_rows[:top], "issues": issues, "summary": summary}


def _stream_row(st: _Stream, t0: float, interval: float) -> dict[str, Any]:
    first_b, last_b = int((st.first - t0) / interval), int((st.last - t0) / interval)
    life = last_b - first_b + 1
    active = [b for b in range(first_b, last_b + 1) if st.bins.get(b, {}).get("packets")]
    data = sum(d.data for d in st.dirs.values())
    retrans = sum(d.retrans for d in st.dirs.values())
    rwnd = [b for b in active if st.bins[b].get("zero_windows") or st.bins[b].get("window_full")]
    bps = [st.bins[b].get("acked_bytes", 0) * 8 / interval for b in active]
    total_bytes = sum(st.bins[b].get("bytes", 0) for b in active)
    row = {
        "stream": st.index, "flow": st.key, "client": st.client, "server": st.server,
        "first": iso(st.first), "last": iso(st.last), "duration_s": round(st.last - st.first, 6), "bytes": int(total_bytes),
        "data_bytes": data, "retransmitted_bytes": retrans,
        "retransmitted_share": round(retrans / data, 4) if data else 0.0,
        "peak_bps": round(max(bps), 1) if bps else 0.0,
        "mean_bps": round(sum(st.bins[b].get("acked_bytes", 0) for b in active) * 8 / (life * interval), 1),
        "max_bytes_in_flight": st.max_in_flight or None, "max_window": st.max_window or None,
        "rwnd_limited_share": round(len(rwnd) / len(active), 4) if active else 0.0,
        "idle_share": round(1 - len(active) / life, 4) if life else 0.0, "first_frame": st.first_frame,
    }
    if data and retrans / data > LOSS_SHARE:
        verdict = "loss-limited"
    elif row["rwnd_limited_share"] >= RWND_SHARE:
        verdict = "receiver-limited"
    elif row["idle_share"] >= IDLE_SHARE:
        verdict = "application-idle"
    elif st.max_in_flight and st.max_window and st.max_in_flight * 4 < st.max_window and life > 2:
        verdict = "sender-limited"
    else:
        verdict = "fine"
    row["verdict"] = verdict
    return {k: v for k, v in row.items() if v is not None}


def _mbit(bps: float) -> str:
    return f"{round(bps / 1e6, 2)} Mbit/s" if bps >= 1e5 else f"{round(bps / 1e3, 1)} kbit/s"


def _issues(intervals: list[dict[str, Any]], streams: list[dict[str, Any]], interval: float) -> list[str]:
    out: list[str] = []
    # Goodput collapse: an interval below a quarter of the median of the active intervals before it.
    good = [(r, r.get("goodput_bps", 0)) for r in intervals]
    history: list[float] = []
    for r, g in good:
        if len(history) >= 2:
            usual = statistics.median(history)
            sent = r.get("bytes", 0)
            if usual > 0 and g < usual / 4 and sent:
                share = r.get("retransmitted_bytes", 0) / max(1, sent)
                if r.get("retransmitted_bytes"):
                    why = f"while retransmissions rose to {round(100 * share, 1)}% of the bytes: loss on the path"
                elif r.get("zero_windows") or r.get("window_full"):
                    why = "while the receiver window was zero or full: the receiver did not read"
                else:
                    why = "with no loss and no window limit: the sender or the application slowed down"
                out.append(f"goodput fell from {_mbit(usual)} to {_mbit(g)} at {r['start']} {why}")
                break
        if g > 0:
            history.append(g)
    for s in streams:
        if s["verdict"] == "loss-limited":
            out.append(f"{s['flow']}: {round(100 * s['retransmitted_share'], 1)}% of the data retransmitted: loss-limited, "
                       "see tcp_health for where it was lost")
        elif s["verdict"] == "receiver-limited":
            out.append(f"{s['flow']}: receiver window zero or full in {round(100 * s['rwnd_limited_share'])}% of its active "
                       f"intervals: the application on {s['client'].rsplit(':', 1)[0]} is not reading fast enough")
        elif s["verdict"] == "application-idle":
            out.append(f"{s['flow']}: idle for {round(100 * s['idle_share'])}% of its life: the application paused, "
                       "not the network")
    idle = [r for r in intervals if not r.get("packets")]
    if idle and len(idle) * 4 >= len(intervals):
        out.append(f"{len(idle)} of {len(intervals)} intervals of {interval}s carry no packet")
    for c in COUNTERS:
        if c == "syns_unanswered":
            continue
        values = [r.get(c, 0) for r in intervals]
        active = [v for v in values if v]
        if not active:
            continue
        usual = statistics.median(active) if len(active) > 2 else 0
        peak = max(values)
        if peak >= BURST_MIN and (usual == 0 or peak >= BURST_FACTOR * usual) and len(active) < len(values):
            at = intervals[values.index(peak)]["start"]
            out.append(f"burst of {peak} {c.replace('_', ' ')} in the {interval}s from {at} "
                       f"(usual {usual} per interval)")
    unanswered = sum(r.get("syns_unanswered", 0) for r in intervals)
    if unanswered:
        out.append(f"{unanswered} SYN(s) never answered; tcp_connections says by which destination")
    return out
