"""tcp_health: per TCP stream, what went wrong and where.

Copies of the same packet (see ``copies``) are dropped before anything is
counted, so a mirror or a capture on several interfaces does not turn into
retransmissions. Each stream then gets:

* the handshake: SYN retries, SYN to SYN-ACK and SYN-ACK to ACK times (the two
  halves of the round trip as seen from the capture point), MSS, window scale
  and SACK on each side;
* per direction: data segments, retransmissions split by where the segment was
  lost (``tcpflow``), duplicate ACKs, zero windows, keep-alives;
* resets with their likely origin: a reset whose TTL (hop limit) or source MAC
  differs from the other packets of the same side was most likely injected by
  a middlebox (firewall, load balancer, IPS), not sent by the endpoint;
* MTU problems: an MSS whose segments do not fit ``mtu``, DF packets above it,
  ICMP fragmentation-needed / packet-too-big about the stream, and the black
  hole pattern (full-size segments retransmitted and never acknowledged while
  smaller ones get through).
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .copies import CopyTracker, copy_key, nonzero
from .fields import compact, iso
from .packets import zeroed_tcp_header
from .tcpflow import FlowTracker, ahead
from .tunnels import ICMP_NAMES, ICMPV6_NAMES

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.protocols",
    "eth.src", "eth.dst", "sll.src.eth",
    "ip.src", "ip.dst", "ip.id", "ip.len", "ip.ttl", "ip.flags.df",
    "ipv6.src", "ipv6.dst", "ipv6.plen", "ipv6.hlim",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.flags", "tcp.checksum",
    "tcp.window_size_value", "tcp.window_size", "tcp.options.mss_val", "tcp.options.wscale.shift",
    "tcp.options.sack_perm", "tcp.options.timestamp.tsval",
    "icmp.type", "icmp.code", "icmp.mtu", "icmpv6.type", "icmpv6.code", "icmpv6.mtu",
]

ICMP_ERRORS = "(icmp.type == 3) || (icmp.type == 11) || (icmpv6.type == 1) || (icmpv6.type == 2) || (icmpv6.type == 3)"
COPY_WINDOW_S = 1.0
RETRANSMISSION_ALERT = 0.02
MIN_SEGMENTS_FOR_RATIO = 20
IDLE_RESET_S = 60.0
MAX_RESETS = 5


def display_filter(stream: int | None) -> str:
    base = f"tcp.stream == {stream}" if stream is not None else "tcp"
    return f"({base}) || ({ICMP_ERRORS})"


def _side(ip: str, port: str) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


class _Dir:
    """What tcpflow does not track: ACK behaviour, windows, TTL and MAC baseline, sizes."""

    def __init__(self) -> None:
        self.packets = 0
        self.dup_acks = 0
        self.zero_windows = 0
        self.fins = 0
        self.rsts = 0
        self.last_ack: tuple | None = None
        self.ttls: Counter[int] = Counter()
        self.macs: Counter[str] = Counter()
        self.mss: int | None = None
        self.wscale: int | None = None
        self.sack = False
        self.full_retrans = 0
        self.full_sent = 0
        self.first_full_seq: int | None = None
        self.first_data_seq: int | None = None
        self.df_above = 0
        self.large_ends: list[int] = []  # sequence end of each data packet above the MTU (bounded)
        self.max_ip = 0
        self.last_time: float | None = None


class _Stream:
    def __init__(self, rec: dict[str, Any]) -> None:
        tcp = rec["tcp"]
        self.index = tcp.get("stream")
        self.a = (rec["src"], tcp["sport"])
        self.b = (rec["dst"], tcp["dport"])
        self.first = self.last = rec["time"]
        self.first_frame = rec["frame"]
        self.packets = 0
        self.copies = 0
        self.dirs: dict[tuple, _Dir] = {}
        self.syn_time: float | None = None
        self.syn_from: tuple | None = None
        self.syns = 0
        self.synack_time: float | None = None
        self.synacks = 0
        self.ack_time: float | None = None
        self.resets: list[dict[str, Any]] = []
        self.icmp: Counter[tuple] = Counter()
        self.last_normal: float | None = None

    def d(self, side: tuple) -> _Dir:
        x = self.dirs.get(side)
        if x is None:
            x = self.dirs[side] = _Dir()
        return x


def analyse(recs: list[dict[str, Any]], mtu: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    tracker = CopyTracker(id_window=COPY_WINDOW_S)
    flows = FlowTracker()
    streams: dict[tuple, _Stream] = {}
    copies = 0
    icmp_records = []
    for rec in recs:
        if rec.get("icmp_error"):
            icmp_records.append(rec)
            continue
        tcp = rec.get("tcp")
        if not tcp or not rec.get("src"):
            continue
        key = tuple(sorted([(rec["src"], tcp["sport"]), (rec["dst"], tcp["dport"])]))
        st = streams.get(key)
        if st is None:
            st = streams[key] = _Stream(rec)
        if zeroed_tcp_header(rec) or tracker.check(copy_key(rec, nonzero(*rec.get("ids", ()))), nonzero(*rec.get("ids", ())),
                                                   rec["time"])[0]:
            st.copies += 1
            copies += 1
            continue
        _account(st, rec, flows, mtu)
    for rec in icmp_records:
        q = rec.get("quoted") or {}
        if q.get("proto") != "tcp":
            continue
        key = tuple(sorted([(q.get("src"), q.get("sport")), (q.get("dst"), q.get("dport"))]))
        st = streams.get(key)
        if st is not None:
            icmp = rec["icmp_error"]
            st.icmp[(rec["src"], icmp["family"], icmp["type"], icmp["code"], icmp["mtu"])] += 1
    rows = [_row(st, flows, mtu) for st in streams.values()]
    rows.sort(key=lambda r: (-len(r.get("issues", [])), -r["packets"], r.get("stream") or 0))
    summary = {
        "streams": len(rows),
        "streams_with_issues": sum(1 for r in rows if r.get("issues")),
        "copies_dropped": copies,
        "retransmissions": sum(r[k].get("retransmissions", 0) for r in rows for k in ("client_to_server", "server_to_client")
                               if r.get(k)),
        "resets": sum(len(r.get("resets", [])) for r in rows),
    }
    return rows, summary


def _account(st: _Stream, rec: dict[str, Any], flows: FlowTracker, mtu: int) -> None:
    tcp = rec["tcp"]
    me = (rec["src"], tcp["sport"])
    d = st.d(me)
    st.packets += 1
    d.packets += 1
    t = rec["time"]
    if t is not None:
        st.first = t if st.first is None else min(st.first, t)
        st.last = t if st.last is None else max(st.last, t)
    if st.index is None:
        st.index = tcp.get("stream")
    if tcp["syn"] and not tcp["ack"]:
        st.syns += 1
        if st.syn_from is None:
            st.syn_from = me
        if st.synack_time is None and me == st.syn_from:
            st.syn_time = t  # the last SYN before the answer, so a retried SYN does not inflate the RTT
        _options(d, tcp)
    elif tcp["syn"] and tcp["ack"]:
        st.synacks += 1
        if st.synack_time is None:
            st.synack_time = t
        _options(d, tcp)
    elif st.synack_time is not None and st.ack_time is None and me == st.syn_from and tcp["ack"]:
        st.ack_time = t
    ip_len = rec.get("ip_len") or 0
    d.max_ip = max(d.max_ip, ip_len)
    if rec.get("df") and ip_len > mtu:
        d.df_above += 1
        if tcp["len"] > 0 and tcp["seq"] is not None and len(d.large_ends) < 1000:
            d.large_ends.append((tcp["seq"] + tcp["len"]) % 2**32)
    if tcp["rst"]:
        d.rsts += 1
        if len(st.resets) < MAX_RESETS:
            idle = (t - st.last_normal) if st.last_normal is not None and t is not None else None
            st.resets.append({"side": me, "frame": rec["frame"], "time": t, "ttl": rec.get("ttl"), "mac": rec.get("mac_src"),
                              "idle": idle, "with_ack": tcp["ack"]})
        flows.feed(rec)
        return
    if rec.get("ttl") is not None:
        d.ttls[rec["ttl"]] += 1
    if rec.get("mac_src"):
        d.macs[rec["mac_src"]] += 1
    d.last_time = t
    st.last_normal = t
    if tcp["fin"]:
        d.fins += 1
    if tcp["window"] == 0 and not (tcp["syn"] or tcp["fin"]):
        d.zero_windows += 1
    if tcp["len"] == 0 and not (tcp["syn"] or tcp["fin"]) and tcp["ack"]:
        ack_key = (tcp["ack_no"], tcp["window"])
        if d.last_ack == ack_key:
            d.dup_acks += 1
        d.last_ack = ack_key
    elif tcp["len"] > 0:
        d.last_ack = None
    if tcp["len"] > 0 and d.first_data_seq is None and tcp["seq"] is not None:
        d.first_data_seq = tcp["seq"]
    kind = flows.feed(rec)
    fd = flows.dirs.get((rec["src"], tcp["sport"], rec["dst"], tcp["dport"]))
    if tcp["len"] > 0 and fd is not None and fd.max_len >= 1000 and tcp["len"] >= 0.95 * fd.max_len:
        d.full_sent += 1
        if kind in ("lost_before_capture", "retransmitted_after_capture"):
            d.full_retrans += 1
        if d.first_full_seq is None and tcp["seq"] is not None:
            d.first_full_seq = tcp["seq"]


def _options(d: _Dir, tcp: dict[str, Any]) -> None:
    if tcp.get("mss") is not None:
        d.mss = tcp["mss"]
    if tcp.get("wscale") is not None:
        d.wscale = tcp["wscale"]
    d.sack = d.sack or bool(tcp.get("sack_perm"))


def _ms(a: float | None, b: float | None) -> float | None:
    return round((b - a) * 1000, 3) if a is not None and b is not None and b >= a else None


def _row(st: _Stream, flows: FlowTracker, mtu: int) -> dict[str, Any]:
    if st.syn_from is not None:
        client = st.syn_from
    else:  # no SYN in the capture: the side with the higher port is most likely the client
        client = max((st.a, st.b), key=lambda s: int(s[1]) if str(s[1]).isdigit() else 0)
    server = st.b if client == st.a else st.a
    c, s = st.d(client), st.d(server)
    fc = flows.dirs.get((client[0], client[1], server[0], server[1]))
    fs = flows.dirs.get((server[0], server[1], client[0], client[1]))
    row: dict[str, Any] = {
        "stream": st.index, "client": _side(*client), "server": _side(*server),
        "first": iso(st.first), "last": iso(st.last),
        "duration_s": round(st.last - st.first, 6) if st.first is not None and st.last is not None else None,
        "packets": st.packets, "copies_dropped": st.copies or None,
    }
    hs: dict[str, Any] = {}
    if st.syns or st.synacks:
        hs = {
            "syn": st.syns, "syn_retransmissions": (fc.syn_retrans if fc else 0) or None, "syn_ack": st.synacks,
            "server_side_rtt_ms": _ms(st.syn_time, st.synack_time), "client_side_rtt_ms": _ms(st.synack_time, st.ack_time),
            "client_mss": c.mss, "server_mss": s.mss, "client_wscale": c.wscale, "server_wscale": s.wscale,
            "sack": (c.sack and s.sack) if st.synacks else None,
        }
        if hs["server_side_rtt_ms"] is not None and hs["client_side_rtt_ms"] is not None:
            hs["rtt_ms"] = round(hs["server_side_rtt_ms"] + hs["client_side_rtt_ms"], 3)
        hs = compact(hs)
    row["handshake"] = hs or None
    row["client_to_server"] = _direction(c, fc)
    row["server_to_client"] = _direction(s, fs)
    resets = [_reset(r, st, client) for r in st.resets]
    row["resets"] = resets or None
    icmp = [compact({"from": src, "error": _icmp_name(fam, typ, code), "mtu": m, "count": n})
            for (src, fam, typ, code, m), n in st.icmp.most_common()]
    row["icmp"] = icmp or None
    row["df_above_mtu"] = (c.df_above + s.df_above) or None
    delivered = _delivered(c.large_ends, fc) + _delivered(s.large_ends, fs)
    row["df_above_mtu_acknowledged"] = delivered or None
    row["loss"] = _where(fc, fs)
    row["issues"] = _issues(row, st, c, s, fc, fs, client, server, mtu)
    return compact(row)


def _delivered(ends: list[int], f: Any) -> int:
    if not f or f.acked is None:
        return 0
    return sum(1 for e in ends if e == f.acked or ahead(f.acked, e))


def _direction(d: _Dir, f: Any) -> dict[str, Any] | None:
    if not d.packets and f is None:
        return None
    out = {
        "packets": d.packets,
        "data_segments": f.data_segments if f else 0,
        "bytes": f.bytes if f else 0,
        "max_segment": (f.max_len or None) if f else None,
        "retransmissions": (f.lost_before + f.after) if f else 0,
        "lost_before_capture": (f.lost_before or None) if f else None,
        "retransmitted_after_capture": (f.after or None) if f else None,
        "missed_by_capture": (f.missed or None) if f else None,
        "out_of_order": (f.out_of_order or None) if f else None,
        "unresolved_gaps": ((f.unresolved() + f.untracked) or None) if f else None,
        "keepalives": (f.keepalives or None) if f else None,
        "duplicate_acks": d.dup_acks or None,
        "zero_windows": d.zero_windows or None,
        "fin": d.fins or None,
        "rst": d.rsts or None,
    }
    if f and f.data_segments:
        out["retransmission_ratio"] = round(out["retransmissions"] / f.data_segments, 4)
    return compact(out)


def _icmp_name(family: str, typ: int | None, code: int | None) -> str:
    names = ICMPV6_NAMES if family == "icmpv6" else ICMP_NAMES
    return names.get((typ, code), f"{family} type {typ} code {code}")


def _initial_ttl(ttl: int) -> int:
    return next(v for v in (32, 64, 128, 255) if ttl <= v)


def _reset(r: dict[str, Any], st: _Stream, client: tuple) -> dict[str, Any]:
    d = st.dirs.get(r["side"])
    usual_ttl = d.ttls.most_common(1)[0][0] if d and d.ttls else None
    usual_mac = d.macs.most_common(1)[0][0] if d and d.macs else None
    why = []
    likely = "unknown"
    if usual_ttl is None and usual_mac is None:
        why.append("no other packet from that side to compare with")
    else:
        ttl_diff = (r["ttl"] - usual_ttl) if r["ttl"] is not None and usual_ttl is not None else None
        mac_diff = bool(r["mac"] and usual_mac and r["mac"] != usual_mac)
        if ttl_diff:
            hops_r, hops_u = _initial_ttl(r["ttl"]) - r["ttl"], _initial_ttl(usual_ttl) - usual_ttl
            why.append(f"TTL {r['ttl']} (about {hops_r} hops away) where that side's packets carry {usual_ttl} "
                       f"(about {hops_u} hops away)")
        if mac_diff:
            why.append(f"source MAC {r['mac']} where that side's packets come from {usual_mac}")
        if ttl_diff or mac_diff:
            likely = "middlebox"
        else:
            likely = "endpoint"
            why.append("same TTL and source MAC as that side's other packets")
    out = {
        "from": "client" if r["side"] == client else "server", "frame": r["frame"], "time": iso(r["time"]),
        "ttl": r["ttl"], "usual_ttl": usual_ttl, "mac": r["mac"] if r["mac"] != usual_mac else None,
        "usual_mac": usual_mac if r["mac"] != usual_mac else None,
        "idle_before_s": round(r["idle"], 3) if r["idle"] is not None else None,
        "likely_from": likely, "why": "; ".join(why),
    }
    return compact(out)


def _where(fc: Any, fs: Any) -> str | None:
    before = sum(f.lost_before for f in (fc, fs) if f)
    after = sum(f.after for f in (fc, fs) if f)
    missed = sum(f.missed for f in (fc, fs) if f)
    parts = []
    if before:
        parts.append(f"{before} lost on the network before the capture point")
    if after:
        parts.append(f"{after} retransmitted after the capture saw the original (lost beyond the capture point, "
                     "or the ACK was)")
    if missed:
        parts.append(f"{missed} missing only from the capture (the receiver acknowledged them)")
    if not parts:
        return "no loss seen" if (fc and fc.data_segments) or (fs and fs.data_segments) else None
    return "; ".join(parts)


def _issues(row: dict[str, Any], st: _Stream, c: _Dir, s: _Dir, fc: Any, fs: Any, client: tuple, server: tuple,
            mtu: int) -> list[str]:
    issues: list[str] = []
    v6 = ":" in client[0]
    header = 60 if v6 else 40
    hs = row.get("handshake") or {}
    if st.syns and not st.synacks:
        issues.append(f"{st.syns} SYN{'s' if st.syns != 1 else ''} and no SYN-ACK: the server did not answer "
                      "(down, filtered, or the answer took another path)")
    elif hs.get("syn_retransmissions"):
        n = hs["syn_retransmissions"]
        issues.append(f"{n} SYN retransmission{'s' if n != 1 else ''} before the connection was answered")
    for name, d, peer in (("client", c, s), ("server", s, c)):
        if d.mss is not None and d.mss + header > mtu:
            issues.append(f"the {name} announced MSS {d.mss}: the {('server' if name == 'client' else 'client')} may send "
                          f"packets of {d.mss + header} bytes, above the {mtu}-byte path MTU; an MSS of at most "
                          f"{mtu - header} fits")
    for label, f, d, peer_f in (("client to server", fc, c, fs), ("server to client", fs, s, fc)):
        if not f:
            continue
        retrans = f.lost_before + f.after
        if f.data_segments >= MIN_SEGMENTS_FOR_RATIO and retrans / f.data_segments >= RETRANSMISSION_ALERT:
            issues.append(f"{label}: {round(100 * retrans / f.data_segments, 1)}% of data segments retransmitted "
                          f"({retrans} of {f.data_segments}; {f.lost_before} lost before the capture point, "
                          f"{f.after} after it)")
        elif retrans and f.data_segments < MIN_SEGMENTS_FOR_RATIO:
            issues.append(f"{label}: {retrans} retransmission{'s' if retrans != 1 else ''}")
        if f.missed:
            issues.append(f"{label}: {f.missed} gap{'s' if f.missed != 1 else ''} ({f.missed_bytes} bytes) acknowledged "
                          "by the receiver but absent from the capture: the capture missed them, the network did not")
        if d.zero_windows:
            sender = "client" if label.startswith("client") else "server"
            issues.append(f"the {sender} advertised a zero window {d.zero_windows} time{'s' if d.zero_windows != 1 else ''} "
                          "(its application did not read fast enough): the stall is at the receiver, not the network")
        if d.full_retrans >= 2 and d.first_full_seq is not None:
            acked = f.acked
            stuck = acked is None or not ahead(acked, d.first_full_seq)
            small_passed = (acked is not None and d.first_data_seq is not None and d.first_data_seq != d.first_full_seq
                            and ahead(acked, d.first_data_seq))
            if stuck and small_passed:
                issues.append(f"{label}: full-size segments ({f.max_len} bytes) were retransmitted {d.full_retrans} times "
                              "and never acknowledged while smaller packets got through: a path MTU black hole (an "
                              "ICMP fragmentation-needed or packet-too-big dropped on the way); clamp the MSS or let "
                              "that ICMP through")
    above, acked = row.get("df_above_mtu") or 0, row.get("df_above_mtu_acknowledged") or 0
    if above and acked < above:
        issues.append(f"{above - acked} packets with DF set are larger than the {mtu}-byte path MTU and were not "
                      "acknowledged")
    # Oversized packets that were acknowledged were split by the network card after the capture
    # point (TSO/GRO): reported in df_above_mtu_acknowledged, not an issue.
    for e in row.get("icmp") or []:
        if e.get("mtu"):
            issues.append(f"{e['from']} sent {e['count']} ICMP {e['error']} about this stream, next-hop MTU {e['mtu']}")
        else:
            issues.append(f"{e['from']} sent {e['count']} ICMP {e['error']} about this stream"
                          + (" (a routing loop or a TTL too low for the path)" if "TTL exceeded" in e["error"] else ""))
    for r in row.get("resets") or []:
        idle = (f" after {r['idle_before_s']} s without traffic (an idle timer?)"
                if r.get("idle_before_s", 0) >= IDLE_RESET_S else "")
        if r["likely_from"] == "middlebox":
            issues.append(f"reset towards the {'server' if r['from'] == 'client' else 'client'} at frame {r['frame']} "
                          f"claims to come from the {r['from']} but most likely came from a middlebox ({r['why']}){idle}")
        else:
            issues.append(f"the {r['from']} reset the connection at frame {r['frame']}{idle}")
    sides = {r["from"] for r in row.get("resets") or [] if r["likely_from"] == "middlebox"}
    if len(sides) == 2:
        issues.append("resets towards both ends that neither end sent: typical of a firewall or IPS tearing the "
                      "connection down")
    if (fc is None or not fc.packets) or (fs is None or not fs.packets):
        if not (st.syns and not st.synacks):
            issues.append("only one direction of this stream is in the capture: losses cannot be checked against ACKs")
    return issues
