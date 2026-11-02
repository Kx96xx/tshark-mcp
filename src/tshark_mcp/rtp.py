"""RTP streams (RFC 3550) and their RTCP reports, linked to SIP calls through SDP.

Statistics are computed here from per-packet ``-T fields`` output rather than from
``tshark -z rtp,streams`` so every number can be explained and tested:

* streams are keyed like Wireshark's: SSRC plus source and destination address and port;
* sequence numbers are extended across the 16-bit wrap; ``lost`` = expected (highest
  minus lowest extended sequence + 1) minus distinct packets received, ``duplicates``
  are repeats, ``sequence_errors`` counts packets whose number is not the previous
  packet's + 1 (gaps, reordering and repeats), as Wireshark's "wrong sequence" does;
* interarrival jitter is RFC 3550 section 6.4.1 (J += (|D| - J) / 16) in milliseconds,
  over the stream's voice payload type, using the clock rate from the SDP rtpmap or the
  static payload-type table; with an unknown clock rate it is not reported;
* ``mos_estimate`` is a simplified ITU-T G.107 E-model from network metrics only; see
  :func:`mos_estimate`. It is an estimate, never a measured or perceptual score.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from . import sdp as sdp_mod
from .fields import compact, iso, parse_time, split_fields_line, to_int

FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "udp.srcport", "udp.dstport",
    "rtp.ssrc", "rtp.seq", "rtp.timestamp", "rtp.p_type", "rtp.marker", "rtp.setup-frame",
    "rtpevent.event_id", "rtpevent.end_of_event", "rtpevent.duration", "rtpevent.volume",
    "rtcp.pt", "rtcp.senderssrc", "rtcp.timestamp.ntp.msw", "rtcp.timestamp.ntp.lsw", "rtcp.sender.packetcount",
    "rtcp.ssrc.identifier", "rtcp.ssrc.fraction", "rtcp.ssrc.cum_nr", "rtcp.ssrc.jitter", "rtcp.ssrc.lsr",
    "rtcp.ssrc.dlsr",
    "rtcp.xr.voipmetrics.rfactor", "rtcp.xr.voipmetrics.moslq", "rtcp.xr.voipmetrics.moscq",
    "rtcp.xr.voipmetrics.rtdelay",
]
AGGREGATOR = ","
DISPLAY_FILTER = "rtp || rtcp"
# Heuristic RTP/RTCP decoding for captures without the SDP that would set the streams up.
HEURISTIC_ARGS = ("--enable-heuristic", "rtp_udp", "--enable-heuristic", "rtcp_udp")

# Thresholds behind the per-stream `issues`.
LOSS_ISSUE_PCT = 1.0
JITTER_ISSUE_MS = 30.0
DELTA_ISSUE_MS = 200.0

MOS_METHOD = (
    "Estimate, not a measurement: simplified ITU-T G.107 E-model on the narrowband scale. "
    "R = 93.2 - Id - Ie,eff; Id = 0.024 d + 0.11 (d - 177.3) when d > 177.3 ms (Cole and Rosenbluth); "
    "d = one-way network delay (half the RTCP round trip when one was measured, else 0) + 2 x mean jitter "
    "(jitter buffer) + packet time + 10 ms codec/processing; Ie,eff = Ie + (95 - Ie) x loss% / (loss% + Bpl) "
    "with random loss (BurstR = 1) and the codec's Ie/Bpl from ITU-T G.113 where listed; "
    "MOS = 1 + 0.035 R + 7e-6 R (R - 60) (100 - R). Wideband codecs are scored on the narrowband scale."
)

# Codec impairment (Ie) and packet-loss robustness (Bpl), ITU-T G.113 Appendix I where listed.
CODEC_IMPAIRMENT: dict[str, tuple[float, float, str]] = {
    "PCMU": (0.0, 25.1, "G.113: G.711 with packet loss concealment"),
    "PCMA": (0.0, 25.1, "G.113: G.711 with packet loss concealment"),
    "G729": (11.0, 19.0, "G.113: G.729A with VAD"),
    "G723": (15.0, 16.1, "G.113: G.723.1 6.3 kbit/s with VAD"),
    "GSM": (20.0, 10.0, "G.113 Ie for GSM-FR; Bpl assumed 10"),
    "GSM-EFR": (5.0, 10.0, "G.113 Ie for GSM-EFR; Bpl assumed 10"),
    "AMR": (5.0, 10.0, "G.113 Ie for AMR 12.2 kbit/s; Bpl assumed 10"),
}
DEFAULT_IMPAIRMENT = (0.0, 25.1, "assumed: no G.113 value for this codec, scored like G.711 with PLC")
WIDEBAND = frozenset({"AMR-WB", "G722", "G7221", "EVS", "OPUS", "SILK", "SPEEX"})


def _last(value: str) -> str:
    """The innermost value of an aggregated field (RTP inside GTP-U lists outer, inner)."""
    return value.split(AGGREGATOR)[-1].strip() if value else ""


def _all(value: str) -> list[str]:
    return [v.strip() for v in value.split(AGGREGATOR)] if value else []


def _bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true")


def parse(stdout: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(RTP packets, RTCP packets) from ``-T fields`` output of :data:`FIELDS`."""
    rtp: list[dict[str, Any]] = []
    rtcp: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(FIELDS):
            continue
        r = dict(zip(FIELDS, cols))
        src = _last(r["ip.src"]) or _last(r["ipv6.src"])
        dst = _last(r["ip.dst"]) or _last(r["ipv6.dst"])
        base = {
            "frame": to_int(r["frame.number"]),
            "time": parse_time(r["frame.time_epoch"]),
            "src": src, "sport": to_int(_last(r["udp.srcport"])),
            "dst": dst, "dport": to_int(_last(r["udp.dstport"])),
        }
        if r["rtp.ssrc"]:
            pkt = dict(base)
            pkt.update({
                "ssrc": to_int(_last(r["rtp.ssrc"])), "seq": to_int(_last(r["rtp.seq"])),
                "ts": to_int(_last(r["rtp.timestamp"])), "pt": to_int(_last(r["rtp.p_type"])),
                "marker": _bool(_last(r["rtp.marker"])), "setup_frame": to_int(_last(r["rtp.setup-frame"])),
            })
            if r["rtpevent.event_id"]:
                pkt["event"] = {
                    "id": to_int(_last(r["rtpevent.event_id"])),
                    "end": _bool(_last(r["rtpevent.end_of_event"])),
                    "duration": to_int(_last(r["rtpevent.duration"])),
                    "volume": to_int(_last(r["rtpevent.volume"])),
                }
            if pkt["ssrc"] is not None and pkt["seq"] is not None:
                rtp.append(pkt)
        if r["rtcp.pt"]:
            pkt = dict(base)
            ids = _all(r["rtcp.ssrc.identifier"])
            cols_b = [_all(r[k]) for k in ("rtcp.ssrc.fraction", "rtcp.ssrc.cum_nr", "rtcp.ssrc.jitter",
                                            "rtcp.ssrc.lsr", "rtcp.ssrc.dlsr")]
            blocks = []
            if all(len(c) == len(ids) for c in cols_b):
                for i, about in enumerate(ids):
                    blocks.append({
                        "about": to_int(about), "fraction": to_int(cols_b[0][i]), "cum_lost": to_int(cols_b[1][i]),
                        "jitter": to_int(cols_b[2][i]), "lsr": to_int(cols_b[3][i]), "dlsr": to_int(cols_b[4][i]),
                    })
            ntp_mid = None
            msw, lsw = to_int(_all(r["rtcp.timestamp.ntp.msw"])[0] if r["rtcp.timestamp.ntp.msw"] else None), \
                to_int(_all(r["rtcp.timestamp.ntp.lsw"])[0] if r["rtcp.timestamp.ntp.lsw"] else None)
            if msw is not None and lsw is not None:
                ntp_mid = ((msw & 0xFFFF) << 16) | ((lsw >> 16) & 0xFFFF)
            xr = None
            if r["rtcp.xr.voipmetrics.rfactor"] or r["rtcp.xr.voipmetrics.moslq"]:
                xr = compact({
                    "r_factor": to_int(_all(r["rtcp.xr.voipmetrics.rfactor"])[0]) if r["rtcp.xr.voipmetrics.rfactor"] else None,
                    "mos_lq": _float(r["rtcp.xr.voipmetrics.moslq"]),
                    "mos_cq": _float(r["rtcp.xr.voipmetrics.moscq"]),
                    "round_trip_ms": to_int(_all(r["rtcp.xr.voipmetrics.rtdelay"])[0]) if r["rtcp.xr.voipmetrics.rtdelay"] else None,
                })
            sender = _all(r["rtcp.senderssrc"])
            pkt.update({
                "types": [to_int(v) for v in _all(r["rtcp.pt"])],
                "sender_ssrc": to_int(sender[0]) if sender else None,
                "ntp_mid": ntp_mid,
                "sender_packets": to_int(_all(r["rtcp.sender.packetcount"])[0]) if r["rtcp.sender.packetcount"] else None,
                "blocks": blocks, "xr": xr,
            })
            rtcp.append(pkt)
    return rtp, rtcp


def _float(value: str) -> float | None:
    vals = _all(value)
    if not vals:
        return None
    try:
        return round(float(vals[0]), 2)
    except ValueError:
        return None


def ep(addr: str, port: int | None) -> str:
    if ":" in addr:
        return f"[{addr}]:{port}"
    return f"{addr}:{port}"


# ----------------------------------------------------------------- linking to SDP
def _pick(refs: list[dict[str, Any]], start: float | None) -> dict[str, Any]:
    """The SDP that advertised an endpoint most recently before the stream started
    (ports are reused across calls), else the earliest one."""
    before = [r for r in refs if r["entry"]["time"] is not None and start is not None and r["entry"]["time"] <= start + 1.0]
    return before[-1] if before else refs[0]


def link(stream: dict[str, Any], endpoints: dict[tuple[str, int], list[dict[str, Any]]],
         by_frame: dict[int, dict[str, Any]]) -> tuple[dict[str, Any] | None, str | None]:
    """The SDP media section a stream belongs to and how it was found: the destination
    is an address/port the receiver advertised (``sdp_destination``), the source is one
    the sender advertised (``sdp_source``, symmetric RTP), or tshark set the stream up
    from that SDP frame (``setup_frame``)."""
    refs = [r for r in endpoints.get((stream["dst"], stream["dport"]), []) if not r["rtcp"]]
    if refs:
        return _pick(refs, stream["first_time"]), "sdp_destination"
    refs = [r for r in endpoints.get((stream["src"], stream["sport"]), []) if not r["rtcp"]]
    if refs:
        return _pick(refs, stream["first_time"]), "sdp_source"
    frame = stream.get("setup_frame")
    if frame is not None and frame in by_frame:
        entry = by_frame[frame]
        return {"entry": entry, "media": entry["sdp"]["media"][0], "index": 0, "rtcp": False}, "setup_frame"
    return None, None


def _codec_for(pt: int | None, call_sdps: list[dict[str, Any]], preferred: dict[str, Any] | None) -> dict[str, Any] | None:
    if pt is None:
        return None
    media_list = ([preferred] if preferred else []) + [m for e in call_sdps for m in e["sdp"]["media"]]
    for media in media_list:
        for c in media.get("codecs", []):
            if c.get("pt") == pt and c.get("name"):
                return {**c, "source": "sdp"}
    if pt in sdp_mod.STATIC_PT:
        name, rate = sdp_mod.STATIC_PT[pt]
        return {"pt": pt, "name": name, "rate": rate, "source": "static payload type"}
    return None


# ----------------------------------------------------------------- statistics
def _ext_seq(seq: int, highest: int | None) -> int:
    if highest is None:
        return seq
    delta = (seq - (highest & 0xFFFF)) & 0xFFFF
    return highest + delta if delta < 0x8000 else highest - (0x10000 - delta)


def sequence_stats(packets: list[dict[str, Any]]) -> dict[str, Any]:
    highest: int | None = None
    lowest: int | None = None
    seen: set[int] = set()
    dups = errors = late = 0
    prev: int | None = None
    for p in packets:
        ext = _ext_seq(p["seq"], highest)
        if prev is not None and ext != prev + 1:
            errors += 1
        if ext in seen:
            dups += 1
        elif highest is not None and ext < highest:
            late += 1
        seen.add(ext)
        highest = ext if highest is None else max(highest, ext)
        lowest = ext if lowest is None else min(lowest, ext)
        prev = ext
    expected = (highest - lowest + 1) if highest is not None and lowest is not None else 0
    lost = max(0, expected - len(seen))
    return {"expected": expected, "lost": lost, "duplicates": dups, "sequence_errors": errors, "out_of_order": late}


def timing_stats(packets: list[dict[str, Any]], rate: int | None, voice_pt: int | None = None) -> dict[str, Any]:
    """Interarrival deltas over every packet of the stream (as Wireshark reports them),
    and RFC 3550 jitter over the packets of ``voice_pt`` when the clock rate is known:
    RFC 4733 event packets repeat one timestamp for the whole digit, so they are left
    out of the jitter (this is why a stream carrying DTMF can differ slightly from
    Wireshark's mean jitter)."""
    deltas = []
    prev = None
    for p in packets:
        if prev is not None and p["time"] is not None and prev["time"] is not None:
            deltas.append((p["time"] - prev["time"]) * 1000.0)
        prev = p
    jit = 0.0
    jitters = []
    prev = None
    if rate:
        for p in packets:
            if voice_pt is not None and p["pt"] != voice_pt:
                continue
            if prev is not None and p["time"] is not None and prev["time"] is not None:
                arrival = (p["time"] - prev["time"]) * 1000.0
                ts_delta = ((p["ts"] - prev["ts"] + 0x80000000) & 0xFFFFFFFF) - 0x80000000
                jit += (abs(arrival - ts_delta * 1000.0 / rate) - jit) / 16.0
                jitters.append(jit)
            prev = p
    out: dict[str, Any] = {}
    if deltas:
        out["max_delta_ms"] = round(max(deltas), 3)
        out["mean_delta_ms"] = round(sum(deltas) / len(deltas), 3)
    if jitters:
        out["max_jitter_ms"] = round(max(jitters), 3)
        out["mean_jitter_ms"] = round(sum(jitters) / len(jitters), 3)
    return out


def mos_estimate(codec_name: str | None, loss_pct: float, mean_jitter_ms: float | None, rtt_ms: float | None,
                 ptime_ms: float | None) -> dict[str, Any]:
    """Simplified E-model (see :data:`MOS_METHOD`). Returns the score, the R factor and
    every input and assumption used, so it can be read as the estimate it is."""
    key = (codec_name or "").upper()
    ie, bpl, source = CODEC_IMPAIRMENT.get(key, DEFAULT_IMPAIRMENT)
    jitter = mean_jitter_ms or 0.0
    ptime = ptime_ms or 20.0
    one_way = rtt_ms / 2.0 if rtt_ms is not None and rtt_ms > 0 else 0.0
    d = one_way + 2.0 * jitter + ptime + 10.0
    i_d = 0.024 * d + (0.11 * (d - 177.3) if d > 177.3 else 0.0)
    loss = max(0.0, min(100.0, loss_pct))
    ie_eff = ie + (95.0 - ie) * loss / (loss + bpl) if loss > 0 else ie
    r = 93.2 - i_d - ie_eff
    if r <= 0:
        mos = 1.0
    elif r >= 100:
        mos = 4.5
    else:
        mos = 1 + 0.035 * r + 7e-6 * r * (r - 60) * (100 - r)
    inputs: dict[str, Any] = {
        "codec": codec_name or "unknown", "ie": ie, "bpl": bpl, "codec_values": source,
        "loss_pct": round(loss, 3), "mean_jitter_ms": round(jitter, 3), "packet_time_ms": ptime,
        "one_way_delay_ms": round(one_way, 3),
        "delay_source": "half the RTCP round trip" if one_way else "not measured, 0 assumed",
        "effective_delay_ms": round(d, 3),
    }
    if key in WIDEBAND:
        inputs["note"] = "wideband codec scored on the narrowband scale; the real score is likely higher"
    return {"value": round(max(1.0, min(4.5, mos)), 2), "r_factor": round(r, 1), "estimate": True,
            "method": "simplified ITU-T G.107 E-model", "inputs": inputs}


# ----------------------------------------------------------------- streams
def build_streams(rtp: list[dict[str, Any]], rtcp: list[dict[str, Any]], sdps: list[dict[str, Any]],
                  endpoints: dict[tuple[str, int], list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """One row per RTP stream with statistics, codec, SDP link, RTCP and MOS estimate."""
    groups: dict[tuple, list[dict[str, Any]]] = {}
    for p in rtp:
        groups.setdefault((p["ssrc"], p["src"], p["sport"], p["dst"], p["dport"]), []).append(p)
    by_frame = {e["frame"]: e for e in sdps if e.get("frame") is not None}
    by_call: dict[str, list[dict[str, Any]]] = {}
    for e in sdps:
        by_call.setdefault(e["call_id"], []).append(e)
    rtcp_info = _rtcp_by_ssrc(rtcp)

    streams = []
    for (ssrc, src, sport, dst, dport), pkts in groups.items():
        pkts.sort(key=lambda p: p["frame"] or 0)
        first_time = pkts[0]["time"]
        stream: dict[str, Any] = {"ssrc": ssrc, "src": src, "sport": sport, "dst": dst, "dport": dport,
                                  "first_time": first_time, "setup_frame": next((p["setup_frame"] for p in pkts if p["setup_frame"]), None)}
        ref, how = link(stream, endpoints, by_frame)
        call_id = ref["entry"]["call_id"] if ref else None
        call_sdps = by_call.get(call_id, []) if call_id else []
        event_pts = {pt for e in call_sdps for m in e["sdp"]["media"] for pt in sdp_mod.telephone_event_pts(m)}
        event_pts |= {p["pt"] for p in pkts if "event" in p}
        pt_counts = Counter(p["pt"] for p in pkts)
        voice = [pt for pt, _ in pt_counts.most_common() if pt not in event_pts and pt != 13]
        main_pt = voice[0] if voice else pt_counts.most_common(1)[0][0]
        receiver_media = ref["media"] if ref and how == "sdp_destination" else (ref["media"] if ref else None)
        codec = _codec_for(main_pt, call_sdps, receiver_media)
        rate = codec.get("rate") if codec else None
        seq = sequence_stats(pkts)
        timing = timing_stats(pkts, rate, main_pt)
        last_time = pkts[-1]["time"]
        duration = round(last_time - first_time, 3) if last_time is not None and first_time is not None else None
        lost_pct = round(100.0 * seq["lost"] / seq["expected"], 3) if seq["expected"] else 0.0
        reports = rtcp_info.get(ssrc, {})
        rtcp_row = _rtcp_row(reports, rate)
        ptime = (ref["media"].get("ptime") if ref else None)
        row: dict[str, Any] = {
            "ssrc": f"0x{ssrc:08x}",
            "src": ep(src, sport), "dst": ep(dst, dport),
            "call_id": call_id, "linked_by": how,
            "sdp_frame": ref["entry"]["frame"] if ref else None,
            "payload_type": main_pt,
            "codec": sdp_mod.codec_label(codec) if codec else None,
            "codec_source": codec.get("source") if codec else None,
            "clock_rate": rate,
            "payload_types": dict(sorted((str(k), v) for k, v in pt_counts.items())) if len(pt_counts) > 1 else None,
            "first_time": iso(first_time), "last_time": iso(last_time), "duration_s": duration,
            "first_frame": pkts[0]["frame"], "last_frame": pkts[-1]["frame"],
            "packets": len(pkts), **seq, "lost_pct": lost_pct,
            **timing,
            "telephone_event_packets": sum(1 for p in pkts if p["pt"] in event_pts) or None,
            "marker_packets": sum(1 for p in pkts if p["marker"]) or None,
            "rtcp": rtcp_row or None,
        }
        if codec is None or not rate:
            row["jitter_note"] = "clock rate unknown (no SDP rtpmap and a dynamic payload type), jitter not computed"
        row["mos_estimate"] = mos_estimate(codec.get("name") if codec else None, lost_pct,
                                           timing.get("mean_jitter_ms"), rtcp_row.get("rtt_ms_max") if rtcp_row else None, ptime)
        streams.append(row)

    # Pair each stream with its reverse direction.
    # Through a NAT the reverse stream is sent to the address in the SDP rather than to
    # where the forward stream came from, so within a call either end matching counts.
    index = {(s["src"], s["dst"]): s for s in streams}
    for s in streams:
        back = index.get((s["dst"], s["src"]))
        if back is None and s.get("call_id"):
            back = next((o for o in streams if o is not s and o.get("call_id") == s["call_id"]
                         and (o["src"] == s["dst"] or o["dst"] == s["src"])), None)
        if back is not None:
            s["reverse_ssrc"] = back["ssrc"]
        else:
            s["one_way"] = True
    for s in streams:
        s["issues"] = issues(s)
    streams.sort(key=lambda s: (s.get("first_time") or "", s["src"]))
    return [compact(s) for s in streams]


def issues(s: dict[str, Any]) -> list[str]:
    out = []
    if s.get("lost_pct", 0) >= LOSS_ISSUE_PCT:
        out.append(f"{s['lost']} of {s['expected']} packets lost ({s['lost_pct']}%)")
    if (s.get("max_jitter_ms") or 0) >= JITTER_ISSUE_MS:
        out.append(f"max jitter {s['max_jitter_ms']} ms")
    if (s.get("max_delta_ms") or 0) >= DELTA_ISSUE_MS:
        out.append(f"gap of {s['max_delta_ms']} ms between packets")
    if s.get("duplicates"):
        out.append(f"duplicate packets: {s['duplicates']}")
    if s.get("out_of_order"):
        out.append(f"out-of-order packets: {s['out_of_order']}")
    if s.get("one_way"):
        out.append("no RTP seen in the reverse direction")
    if s.get("call_id") is None:
        out.append("not linked to any SDP in the capture")
    return out


def _rtcp_by_ssrc(rtcp: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    """Reception reports grouped by the SSRC they describe, with a round trip from the
    capture point to the reporter and back where the LSR matches a captured SR."""
    sr_times: dict[int, float] = {}
    for p in rtcp:
        if p["ntp_mid"] is not None and p["time"] is not None:
            sr_times.setdefault(p["ntp_mid"], p["time"])
    out: dict[int, dict[str, Any]] = {}
    for p in rtcp:
        if p["sender_ssrc"] is not None:
            info = out.setdefault(p["sender_ssrc"], {"blocks": [], "rtts": [], "sender_packets": None, "xr": []})
            if p["sender_packets"] is not None:
                info["sender_packets"] = p["sender_packets"]
        for b in p["blocks"]:
            if b["about"] is None:
                continue
            info = out.setdefault(b["about"], {"blocks": [], "rtts": [], "sender_packets": None, "xr": []})
            info["blocks"].append({**b, "reporter": p["sender_ssrc"], "time": p["time"]})
            if b["lsr"] and b["lsr"] in sr_times and p["time"] is not None:
                rtt = (p["time"] - sr_times[b["lsr"]] - (b["dlsr"] or 0) / 65536.0) * 1000.0
                if rtt >= 0:
                    info["rtts"].append(rtt)
    return out


def _rtcp_row(info: dict[str, Any], rate: int | None) -> dict[str, Any]:
    if not info or not (info["blocks"] or info["sender_packets"] is not None):
        return {}
    blocks = info["blocks"]
    row: dict[str, Any] = {"reports": len(blocks)}
    if info["sender_packets"] is not None:
        row["sender_reported_packets"] = info["sender_packets"]
    if blocks:
        row["fraction_lost_max_pct"] = round(max((b["fraction"] or 0) for b in blocks) * 100.0 / 256.0, 2)
        row["cumulative_lost_last"] = blocks[-1]["cum_lost"]
        jit = [b["jitter"] for b in blocks if b["jitter"] is not None]
        if jit and rate:
            row["jitter_max_ms"] = round(max(jit) * 1000.0 / rate, 3)
        elif jit:
            row["jitter_max_units"] = max(jit)
    if info["rtts"]:
        row["rtt_ms_max"] = round(max(info["rtts"]), 3)
        row["rtt_ms_mean"] = round(sum(info["rtts"]) / len(info["rtts"]), 3)
        row["rtt_note"] = "round trip from the capture point to the reporter and back (LSR/DLSR against the captured SR)"
    return row


def xr_reports(rtcp: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """RTCP XR VoIP metrics (RFC 3611) as the endpoints reported them."""
    out = []
    for p in rtcp:
        if p["xr"]:
            out.append(compact({"frame": p["frame"], "time": iso(p["time"]), "from": ep(p["src"], p["sport"]),
                                "reporter_ssrc": f"0x{p['sender_ssrc']:08x}" if p["sender_ssrc"] is not None else None,
                                **p["xr"]}))
    return out


def rtp_filter(addresses: set[str]) -> str:
    """RTP/RTCP to or from any of ``addresses`` (already validated as IP literals)."""
    v4 = sorted(a for a in addresses if ":" not in a)
    v6 = sorted(a for a in addresses if ":" in a)
    parts = []
    if v4:
        parts.append("ip.addr in {" + ", ".join(v4) + "}")
    if v6:
        parts.append("ipv6.addr in {" + ", ".join(v6) + "}")
    return f"({DISPLAY_FILTER}) && ({' || '.join(parts)})" if parts else DISPLAY_FILTER
