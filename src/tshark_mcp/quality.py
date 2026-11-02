"""capture_quality: can loss and timing conclusions be drawn from this capture?

One ``-T fields`` pass over the capture (with tshark's IP, TCP and UDP checksum
validation switched on) feeds these checks:

* duplicate copies of the same packet (SPAN of ingress and egress, several
  interfaces, a tunnel seen before and after decapsulation), with the likely cause;
* TCP bytes the receiver acknowledged but the capture never saw (dropped by the
  capture, not the network), and gaps that a retransmission later filled (lost
  before the capture point);
* frames cut short by the snapshot length, and packets larger than the link MTU
  (segmentation offload on the capturing host);
* bad checksums, and whether they look like checksum offload (one sender, and the
  peer acknowledged the data anyway) or real corruption;
* TCP streams seen in one direction only, and one-way UDP flows;
* timestamps going backwards, identical stamps, coarse resolution, long silences.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from . import packets
from .copies import CopyTracker, copy_key, has_ip_id
from .fields import iso
from .tcpflow import FlowTracker, ahead

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "frame.interface_id", "frame.protocols",
    "eth.src", "eth.dst", "sll.src.eth", "sll.pkttype", "vlan.id",
    "ip.src", "ip.dst", "ip.id", "ip.len", "ip.ttl", "ip.checksum.status",
    "ipv6.src", "ipv6.dst", "ipv6.plen", "ipv6.hlim",
    "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.flags", "tcp.checksum",
    "tcp.checksum.status", "tcp.options.timestamp.tsval", "udp.srcport", "udp.dstport", "udp.length", "udp.checksum", "udp.checksum.status",
    "icmp.type", "icmp.code", "icmp.checksum", "icmp.seq", "icmpv6.type", "icmpv6.code", "icmpv6.checksum",
    "icmpv6.echo.sequence_number",
]

# Validation of these checksums is off by default in tshark; the runner allows exactly these.
CHECKSUM_PREFERENCES = ("ip.check_checksum:TRUE", "tcp.check_checksum:TRUE", "udp.check_checksum:TRUE")

COPY_WINDOW_S = 1.0  # copies with a non-zero IP ID within this distance; IDs wrap on long captures
LINK_MTU = 1500
ENCAPSULATIONS = ("vlan", "mpls", "gre", "erspan", "vxlan", "geneve", "gtp", "sll", "ipip")
EXAMPLES = 5
GAP_REPORT_S = 1.0
ONE_SIDED_MIN = 3  # packets before a one-direction TCP stream counts against the capture
ZEROED_CAUSE = "rebuilt copy with a zeroed TCP header (a capture tool writing decapsulated packets)"


def tshark_args() -> list[str]:
    args: list[str] = []
    for pref in CHECKSUM_PREFERENCES:
        args += ["-o", pref]
    return args


def _copy_key(rec: dict[str, Any]) -> tuple | None:
    """What a copy shares with the original. Without an IP ID (zero, or IPv6) two different
    packets of the same size can follow each other closely, so the transport checksum is
    added: it differs with the payload and is the same in a copy. Only the innermost IP ID counts."""
    return copy_key(rec, has_ip_id(rec))


def _copy_cause(first: dict[str, Any], rec: dict[str, Any]) -> str:
    if first["iface"] != rec["iface"]:
        return "captured on two interfaces"
    if first["vlan"] != rec["vlan"]:
        return "seen on two VLANs (SPAN of both ingress and egress)"
    if first["tunnelled"] != rec.get("tunnelled", False):
        return "seen tunnelled and decapsulated"
    if first["sll_type"] != rec["sll_type"]:
        return "seen leaving one interface and arriving on another (Linux any capture)"
    if first["link"] != rec["link"] or first["protocols"] != rec["protocols"]:
        return "seen with two different link-layer headers (capture on several interfaces, e.g. Linux any)"
    if first["ttl"] is not None and rec.get("ttl") is not None and first["ttl"] != rec["ttl"]:
        return "seen before and after a router hop (TTL differs)"
    if first["macs"] != (rec["mac_src"], rec["mac_dst"]):
        return "seen on both sides of a switch or router (MAC addresses differ)"
    return "identical headers (SPAN or mirror of both directions of a port, or a Linux any capture)"


def _copy_info(rec: dict[str, Any]) -> dict[str, Any]:
    return {"frame": rec["frame"], "iface": rec["iface"], "vlan": rec["vlan"], "tunnelled": rec.get("tunnelled", False),
            "link": rec["link"], "protocols": rec["protocols"], "ttl": rec.get("ttl"),
            "macs": (rec["mac_src"], rec["mac_dst"]), "sll_type": rec["sll_type"]}


def analyse(recs: list[dict[str, Any]]) -> dict[str, Any]:
    tracker = CopyTracker(id_window=COPY_WINDOW_S)
    flows = FlowTracker()
    ip_packets = copies = 0
    causes: Counter[str] = Counter()
    copy_examples: list[dict[str, Any]] = []
    truncated, trunc_caps, trunc_protos = 0, Counter(), Counter()
    oversized, max_ip = 0, 0
    bad: Counter[str] = Counter()
    checked: Counter[str] = Counter()
    bad_by_sender: dict[str, Counter[str]] = defaultdict(Counter)
    sent_by: Counter[str] = Counter()
    bad_tcp: list[tuple[tuple[str, str, str, str], int]] = []
    encaps: Counter[str] = Counter()
    links: Counter[str] = Counter()
    ifaces: set[str] = set()
    ts = _Timestamps()
    tcp_pairs: dict[tuple, dict[str, Any]] = {}
    udp_pairs: dict[tuple, Counter[str]] = {}

    for rec in recs:
        ts.feed(rec)
        links[rec["link"] or "unknown"] += 1
        if rec["iface"]:
            ifaces.add(rec["iface"])
        _encapsulations(rec, encaps)
        if rec["cap_len"] and rec["len"] and rec["cap_len"] < rec["len"]:
            truncated += 1
            trunc_caps[rec["cap_len"]] += 1
            last = rec["protocols"].rsplit(":", 1)[-1] if rec["protocols"] else "unknown"
            trunc_protos[last] += 1
        if not rec.get("src"):
            continue
        ip_packets += 1
        if packets.zeroed_tcp_header(rec):
            copies += 1
            causes[ZEROED_CAUSE] += 1
            if len(copy_examples) < EXAMPLES:
                copy_examples.append({"frame": rec["frame"], "cause": ZEROED_CAUSE})
            continue
        key = _copy_key(rec)
        if key is not None:
            is_copy, first = tracker.check(key, has_ip_id(rec), rec["time"], _copy_info(rec))
            if is_copy:
                copies += 1
                cause = _copy_cause(first, rec)
                causes[cause] += 1
                if len(copy_examples) < EXAMPLES:
                    copy_examples.append({"frame": rec["frame"], "copy_of": first["frame"], "cause": cause})
                continue
        outer_len = rec.get("outer_len") or rec.get("ip_len")
        if outer_len and outer_len > LINK_MTU:
            oversized += 1
            max_ip = max(max_ip, outer_len)
        sent_by[rec["src"]] += 1
        for layer, status, sender in rec.get("outer_checksums", []):
            if status in ("0", "1"):
                checked[layer] += 1
            if status == "0":
                bad[layer] += 1
                bad_by_sender[sender or rec["src"]][layer] += 1
        tcp = rec.get("tcp")
        if tcp:
            flows.feed(rec)
            pair = _pair(rec["src"], tcp["sport"], rec["dst"], tcp["dport"])
            p = tcp_pairs.setdefault(pair, {"dirs": Counter(), "syn_only": True, "first": rec["frame"]})
            p["dirs"][(rec["src"], tcp["sport"])] += 1
            if not (tcp["syn"] and not tcp["ack"]):
                p["syn_only"] = False
            if tcp["checksum"] == "0" and tcp["len"] > 0 and tcp["seq"] is not None and len(bad_tcp) < 10000:
                bad_tcp.append(((rec["src"], tcp["sport"], rec["dst"], tcp["dport"]), (tcp["seq"] + tcp["len"]) % 2**32))
        elif rec.get("udp"):
            udp = rec["udp"]
            pair = _pair(rec["src"], udp["sport"], rec["dst"], udp["dport"])
            udp_pairs.setdefault(pair, Counter())[(rec["src"], udp["sport"])] += 1

    out: dict[str, Any] = {
        "frames": len(recs), "ip_packets": ip_packets,
        "first": iso(ts.first), "last": iso(ts.last),
        "duration_s": round(ts.last - ts.first, 6) if ts.first is not None and ts.last is not None else None,
        "link_types": dict(links.most_common()),
        "interfaces": len(ifaces) or None,
        "encapsulations": dict(encaps.most_common()) or None,
    }
    out["duplicates"] = {
        "copies": copies,
        "share": round(copies / ip_packets, 4) if ip_packets else 0.0,
        "causes": dict(causes.most_common()) or None,
        "examples": copy_examples or None,
    }
    out["tcp_capture_gaps"] = _gaps(flows)
    out["truncated_frames"] = {
        "frames": truncated, "share": round(truncated / len(recs), 4) if recs else 0.0,
        "snaplen": trunc_caps.most_common(1)[0][0] if trunc_caps else None,
        "protocols": dict(trunc_protos.most_common(5)) or None,
    }
    out["oversized_packets"] = {"packets": oversized, "max_ip_len": max_ip or None, "link_mtu": LINK_MTU}
    out["checksums"] = _checksums(checked, bad, bad_by_sender, sent_by, bad_tcp, flows)
    out["one_sided"] = _one_sided(tcp_pairs, udp_pairs)
    out["timestamps"] = ts.summary()
    out["verdict"] = _verdict(out)
    return _drop_none(out)


def _drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_none(v) for v in value]
    return value


def _pair(a: str, ap: str, b: str, bp: str) -> tuple:
    return tuple(sorted([(a, ap), (b, bp)]))


def _encapsulations(rec: dict[str, Any], encaps: Counter[str]) -> None:
    layers = rec["protocols"].split(":") if rec["protocols"] else []
    seen = set()
    for p in layers:
        if p in ENCAPSULATIONS:
            seen.add(p)
    ips = [p for p in layers if p in ("ip", "ipv6")]
    if len(ips) > 1 and not seen & {"gre", "vxlan", "geneve", "gtp", "erspan"}:
        seen.add("ipip")
    for p in seen:
        encaps[p] += 1


def _gaps(flows: FlowTracker) -> dict[str, Any]:
    missed = missed_bytes = lost_before = after = ooo = unresolved = data = 0
    streams_missed = 0
    for d in flows.dirs.values():
        missed += d.missed
        missed_bytes += d.missed_bytes
        lost_before += d.lost_before
        after += d.after
        ooo += d.out_of_order
        unresolved += d.unresolved() + d.untracked
        data += d.data_segments
        if d.missed:
            streams_missed += 1
    return {
        "tcp_data_segments": data,
        "missed_by_capture": missed, "missed_bytes": missed_bytes, "directions_with_missed": streams_missed,
        "lost_before_capture": lost_before, "retransmitted_after_capture": after, "out_of_order": ooo,
        "unresolved_gaps": unresolved,
    }


def _checksums(checked: Counter[str], bad: Counter[str], by_sender: dict[str, Counter[str]], sent_by: Counter[str],
               bad_tcp: list, flows: FlowTracker) -> dict[str, Any]:
    total_bad = sum(bad.values())
    out: dict[str, Any] = {"validated": dict(checked), "bad": dict(bad)}
    if not total_bad:
        return out
    senders = sorted(by_sender.items(), key=lambda kv: -sum(kv[1].values()))
    out["bad_by_sender"] = [{"sender": s, "bad": sum(c.values()), "packets_sent": sent_by.get(s, 0), "layers": dict(c)}
                            for s, c in senders[:EXAMPLES]]
    acked = 0
    for key, end in bad_tcp:
        r = flows.dirs.get(key)
        if r is not None and r.acked is not None and (r.acked == end or ahead(r.acked, end)):
            acked += 1
    out["bad_tcp_segments_acknowledged"] = acked
    out["bad_tcp_data_segments"] = len(bad_tcp)
    top_sender, top = senders[0]
    top_bad = sum(top.values())
    concentrated = top_bad >= 0.9 * total_bad and top_bad >= 0.5 * max(1, sent_by.get(top_sender, 0))
    mostly_acked = bool(bad_tcp) and acked >= 0.5 * len(bad_tcp)
    if concentrated or mostly_acked:
        out["likely_offload"] = True
        why = []
        if concentrated:
            why.append(f"{top_bad} of {total_bad} come from {top_sender}, which is most likely the capturing host")
        if mostly_acked:
            why.append(f"{acked} of {len(bad_tcp)} TCP data segments with a bad checksum were acknowledged by the receiver, "
                       "so they arrived intact")
        out["explanation"] = ("checksum offload: the network card fills the checksum after the capture point; "
                              + "; ".join(why) + ". Not a network fault")
    else:
        out["likely_offload"] = False
        out["explanation"] = ("bad checksums from several senders and not acknowledged: possible corruption on the path "
                              "(or a capture point that rewrites packets)")
    return out


def _one_sided(tcp_pairs: dict[tuple, dict[str, Any]], udp_pairs: dict[tuple, Counter[str]]) -> dict[str, Any]:
    one, short, syn_only, examples = 0, 0, 0, []
    for pair, p in tcp_pairs.items():
        if len(p["dirs"]) != 1:
            continue
        (src, sport), n = next(iter(p["dirs"].items()))
        other = pair[1] if pair[0] == (src, sport) else pair[0]
        if p["syn_only"]:
            syn_only += 1
            kind = "SYN only, never answered"
        elif n >= ONE_SIDED_MIN:
            one += 1
            kind = "one direction only"
        else:
            short += 1
            continue
        if len(examples) < EXAMPLES:
            examples.append({"from": f"{src}:{sport}", "to": f"{other[0]}:{other[1]}", "packets": n, "kind": kind,
                             "first_frame": p["first"]})
    udp_one = sum(1 for c in udp_pairs.values() if len(c) == 1 and sum(c.values()) >= 5)
    return {"tcp_streams": len(tcp_pairs), "tcp_one_direction": one, "tcp_one_direction_short": short,
            "tcp_syn_unanswered": syn_only, "udp_flows": len(udp_pairs), "udp_one_way_flows": udp_one,
            "examples": examples or None}


class _Timestamps:
    def __init__(self) -> None:
        self.first: float | None = None
        self.last: float | None = None
        self.prev: int | None = None
        self.prev_frame: int | None = None
        self.backwards = 0
        self.max_back = 0.0
        self.first_back: int | None = None
        self.identical = 0
        self.frames = 0
        self.fractions: set[int] = set()
        self.ns_any = self.us_any = self.ms_any = False
        self.gap = 0.0
        self.gap_after: int | None = None
        self.before_2000 = 0

    def feed(self, rec: dict[str, Any]) -> None:
        t = rec["time"]
        if t is None:
            return
        self.frames += 1
        if self.first is None or t < self.first:
            self.first = t
        if self.last is None or t > self.last:
            self.last = t
        if t < 946684800:
            self.before_2000 += 1
        ns = packets.ns_fraction(rec["time_text"])
        if ns is not None:
            if ns % 1000:
                self.ns_any = True
            elif ns % 1_000_000:
                self.us_any = True
            elif ns:
                self.ms_any = True
        stamp = packets.epoch_ns(rec["time_text"])  # integer nanoseconds: a float loses sub-microsecond steps
        if stamp is None:
            return
        if self.prev is not None:
            delta = stamp - self.prev
            if delta < 0:
                self.backwards += 1
                self.max_back = max(self.max_back, -delta / 1e9)
                if self.first_back is None:
                    self.first_back = rec["frame"]
            elif delta == 0:
                self.identical += 1
            elif delta / 1e9 > self.gap:
                self.gap, self.gap_after = delta / 1e9, self.prev_frame
        self.prev, self.prev_frame = stamp, rec["frame"]

    def resolution(self) -> str | None:
        if not self.frames:
            return None
        if self.ns_any:
            return "nanosecond"
        if self.us_any:
            return "microsecond"
        if self.ms_any:
            return "millisecond"
        return "second" if self.frames > 1 else None

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "backwards_jumps": self.backwards,
            "max_backwards_s": round(self.max_back, 6) if self.backwards else None,
            "first_backwards_frame": self.first_back,
            "identical_to_previous": self.identical,
            "identical_share": round(self.identical / max(1, self.frames - 1), 4) if self.frames > 1 else 0.0,
            "resolution": self.resolution(),
            "largest_gap_s": round(self.gap, 6) if self.gap >= GAP_REPORT_S else None,
            "largest_gap_after_frame": self.gap_after if self.gap >= GAP_REPORT_S else None,
            "before_year_2000": self.before_2000 or None,
        }
        return {k: v for k, v in out.items() if v is not None}


def _n(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


def _verdict(out: dict[str, Any]) -> dict[str, Any]:
    severity = 0  # 0 trustworthy, 1 use with care, 2 not trustworthy
    reasons: list[str] = []
    notes: list[str] = []
    dup = out["duplicates"]
    if dup["copies"]:
        cause = next(iter(dup["causes"] or {}), "copies")
        pct = round(dup["share"] * 100, 1)
        text = (f"{dup['copies']} duplicate copies ({pct}% of IP packets; {cause}): raw tshark retransmission and "
                "duplicate-ACK flags count these copies; tcp_health, gtp_tunnel_health and message_rates count them once")
        if dup["share"] >= 0.01:
            severity = max(severity, 1)
            reasons.append(text)
        else:
            notes.append(text)
    gaps = out["tcp_capture_gaps"]
    if gaps["missed_by_capture"]:
        share = gaps["missed_by_capture"] / max(1, gaps["tcp_data_segments"])
        severity = max(severity, 2 if share >= 0.001 else 1)
        reasons.append(f"the capture missed {_n(gaps['missed_by_capture'], 'TCP gap')} ({gaps['missed_bytes']} bytes) that the "
                       "receiver acknowledged: the capture dropped them (or the file was filtered or sliced), the "
                       "network delivered them; a packet absent from this file is not proof of loss")
    if gaps["lost_before_capture"] or gaps["retransmitted_after_capture"]:
        notes.append(f"real TCP loss: {_n(gaps['lost_before_capture'], 'segment')} lost before the capture point (gap later "
                     f"filled by a retransmission), {_n(gaps['retransmitted_after_capture'], 'retransmission')} of segments "
                     "the capture had already seen (lost after it, or their ACK was)")
    tr = out["truncated_frames"]
    if tr["frames"]:
        severity = max(severity, 1)
        reasons.append(f"{tr['frames']} frames cut to a snapshot length of {tr['snaplen']} bytes: payload reassembly and "
                       "message decoding are incomplete; header-based counts still hold")
    ov = out["oversized_packets"]
    if ov["packets"]:
        severity = max(severity, 1)
        reasons.append(f"{ov['packets']} packets larger than {LINK_MTU} bytes (up to {ov['max_ip_len']}): segmentation "
                       "offload (TSO/GRO) on the capturing host or jumbo frames; segment counts and sizes are those "
                       "before the network card split them")
    one = out["one_sided"]
    if one["tcp_one_direction"]:
        share = one["tcp_one_direction"] / max(1, one["tcp_streams"])
        severity = max(severity, 2 if share >= 0.5 and one["tcp_one_direction"] >= 2 else 1)
        reasons.append(f"{one['tcp_one_direction']} of {one['tcp_streams']} TCP streams were seen in one direction only "
                       f"({ONE_SIDED_MIN} packets or more; asymmetric routing or a one-way tap): their losses cannot be "
                       "checked against ACKs")
    if one["tcp_one_direction_short"]:
        notes.append(f"{one['tcp_one_direction_short']} TCP streams have fewer than {ONE_SIDED_MIN} packets, all in one "
                     "direction (a long-lived connection caught briefly, or one direction missing)")
    if one["tcp_syn_unanswered"]:
        notes.append(f"{one['tcp_syn_unanswered']} TCP connection attempts got no SYN-ACK in the capture")
    if one["udp_one_way_flows"]:
        notes.append(f"{one['udp_one_way_flows']} UDP flows of 5 or more packets have no reverse traffic (normal for some "
                     "protocols; for request/response protocols the other direction is missing)")
    ck = out["checksums"]
    if ck.get("bad") and sum(ck["bad"].values()):
        if ck.get("likely_offload"):
            notes.append("bad checksums are " + ck["explanation"])
        else:
            severity = max(severity, 1)
            reasons.append(ck["explanation"])
    t = out["timestamps"]
    if t.get("backwards_jumps"):
        severity = max(severity, 1)
        reasons.append(f"timestamps go backwards {t['backwards_jumps']} times (up to {t['max_backwards_s']} s; merged "
                       "captures or interfaces with different clocks): RTTs and ordering across them are unreliable")
    if t.get("resolution") in ("millisecond", "second"):
        severity = max(severity, 1)
        reasons.append(f"timestamps have {t['resolution']} resolution: sub-{t['resolution']} RTTs and reordering "
                       "decisions are approximate")
    if t.get("identical_share", 0) >= 0.2 and t.get("resolution") not in ("millisecond", "second"):
        notes.append(f"{round(t['identical_share'] * 100, 1)}% of frames carry the same timestamp as the previous "
                     "frame (batched timestamping)")
    if t.get("before_year_2000"):
        severity = max(severity, 1)
        reasons.append(f"{t['before_year_2000']} frames are stamped before 2000: the capturing clock was not set")
    if t.get("largest_gap_s"):
        notes.append(f"longest silence {t['largest_gap_s']} s after frame {t['largest_gap_after_frame']}")
    label = ("trustworthy", "use with care", "not trustworthy")[severity]
    summary = {
        0: "no duplicate copies, capture drops, truncation or clock problems found: loss seen in this file is real loss",
        1: "loss conclusions hold only with the caveats listed",
        2: "the capture itself is incomplete: do not read missing packets as network loss",
    }[severity]
    return {"loss_conclusions": label, "summary": summary, "reasons": reasons, "notes": notes}
