"""DTMF in a capture: RFC 4733 (formerly RFC 2833) telephone-events in RTP and SIP INFO
(application/dtmf-relay, application/dtmf), checked against the payload type the SDP
negotiated for telephone-event."""

from __future__ import annotations

import re
from typing import Any

from . import sdp as sdp_mod
from .fields import compact, iso, parse_time, to_int
from .rtp import ep, link

# RFC 4733 section 3.2 event codes.
EVENT_NAMES = {**{i: str(i) for i in range(10)}, 10: "*", 11: "#", 12: "A", 13: "B", 14: "C", 15: "D", 16: "flash"}

INFO_TYPES = ("application/dtmf-relay", "application/dtmf", "application/kpml-response+xml")
_SIGNAL = re.compile(r"^\s*Signal\s*=\s*(\S+)", re.I | re.M)
_DURATION = re.compile(r"^\s*Duration\s*=\s*(\d+)", re.I | re.M)
_KPML = re.compile(r'digits\s*=\s*"([^"]*)"', re.I)


def rtp_filter(addresses: set[str]) -> str:
    """RFC 4733 event packets, to or from ``addresses`` when given (validated IP literals)."""
    v4 = sorted(a for a in addresses if ":" not in a)
    v6 = sorted(a for a in addresses if ":" in a)
    parts = []
    if v4:
        parts.append("ip.addr in {" + ", ".join(v4) + "}")
    if v6:
        parts.append("ipv6.addr in {" + ", ".join(v6) + "}")
    return f"rtpevent && ({' || '.join(parts)})" if parts else "rtpevent"


def info_filter(call_id: str | None) -> str:
    """SIP INFO requests and their responses (of one Call-ID when given, already linted)."""
    base = 'sip.CSeq.method == "INFO"'
    return f'{base} && sip.Call-ID == "{call_id}"' if call_id else base


def negotiated(sdps: list[dict[str, Any]]) -> dict[str, dict[int, int | None]]:
    """Call-ID -> {telephone-event payload type: clock rate} from every SDP of the call."""
    out: dict[str, dict[int, int | None]] = {}
    for entry in sdps:
        call = out.setdefault(entry["call_id"], {})
        for media in entry["sdp"]["media"]:
            for c in media.get("codecs", []):
                if str(c.get("name", "")).upper() == "TELEPHONE-EVENT" and isinstance(c["pt"], int):
                    call[c["pt"]] = c.get("rate")
    return out


def rtp_events(packets: list[dict[str, Any]], sdps: list[dict[str, Any]],
               endpoints: dict[tuple[str, int], list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """One row per RFC 4733 event (a digit): the packets of one stream that share an RTP
    timestamp, however many updates and repeated end packets were sent."""
    by_frame = {e["frame"]: e for e in sdps if e.get("frame") is not None}
    pts = negotiated(sdps)
    groups: dict[tuple, list[dict[str, Any]]] = {}
    for p in packets:
        if "event" not in p:
            continue
        groups.setdefault((p["ssrc"], p["src"], p["sport"], p["dst"], p["dport"], p["ts"]), []).append(p)
    rows = []
    for (ssrc, src, sport, dst, dport, _ts), pkts in groups.items():
        pkts.sort(key=lambda p: p["frame"] or 0)
        first = pkts[0]
        stream = {"src": src, "sport": sport, "dst": dst, "dport": dport, "first_time": first["time"],
                  "setup_frame": first.get("setup_frame")}
        ref, how = link(stream, endpoints, by_frame)
        call_id = ref["entry"]["call_id"] if ref else None
        call_pts = pts.get(call_id, {}) if call_id else {}
        pt = first["pt"]
        rate = call_pts.get(pt) or 8000
        events = {p["event"]["id"] for p in pkts}
        ev = first["event"]["id"]
        durations = [p["event"]["duration"] for p in pkts if p["event"]["duration"] is not None]
        ends = [p for p in pkts if p["event"]["end"]]
        row = {
            "time": iso(first["time"]), "frame": first["frame"], "source": "rfc4733",
            "digit": EVENT_NAMES.get(ev, f"event {ev}"), "event": ev,
            "call_id": call_id, "src": ep(src, sport), "dst": ep(dst, dport), "ssrc": f"0x{ssrc:08x}",
            "payload_type": pt, "clock_rate": rate,
            "duration_ms": round(max(durations) * 1000.0 / rate, 1) if durations else None,
            "volume_dbm0": -first["event"]["volume"] if first["event"]["volume"] is not None else None,
            "packets": len(pkts), "end_packets": len(ends),
        }
        problems = []
        if not ends:
            problems.append("no end-of-event packet: the digit may be held or repeated by the receiver")
        if len(events) > 1:
            problems.append(f"one timestamp carries several events ({sorted(events)})")
        if call_id is None:
            problems.append("not linked to any SDP in the capture")
        elif pt not in call_pts:
            what = ", ".join(str(x) for x in sorted(call_pts)) if call_pts else "none"
            problems.append(f"payload type {pt} is not the negotiated telephone-event type ({what}); "
                            "the receiver may treat these packets as audio or drop them")
        row["issues"] = problems
        rows.append(compact(row))
    return rows


def info_events(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per SIP INFO carrying DTMF, with the status of its response."""
    responses: dict[tuple[str, str], int] = {}
    for m in messages:
        status = to_int(m["sip.Status-Code"])
        if status is not None and status >= 200:
            responses.setdefault((m["sip.Call-ID"], m["sip.CSeq.seq"]), status)
    rows = []
    for m in messages:
        if m["sip.Method"] != "INFO" or m.get("sip.resend") in ("1", "True"):
            continue
        ctype = (m.get("sip.Content-Type") or "").split(";")[0].strip().lower()
        body = sdp_mod.body_text(m.get("sip.msg_body"))
        digit = duration = None
        if ctype == "application/dtmf-relay":
            sig = _SIGNAL.search(body)
            dur = _DURATION.search(body)
            digit = sig.group(1) if sig else None
            duration = int(dur.group(1)) if dur else None
        elif ctype == "application/dtmf":
            digit = body.strip() or None
        elif ctype == "application/kpml-response+xml":
            k = _KPML.search(body)
            digit = k.group(1) if k else None
        else:
            continue
        if digit is not None and digit.isdigit() and int(digit) in EVENT_NAMES and len(digit) > 1:
            digit = EVENT_NAMES[int(digit)]
        status = responses.get((m["sip.Call-ID"], m["sip.CSeq.seq"]))
        problems = []
        if digit is None:
            problems.append(f"{ctype} body without a digit")
        if status is None:
            problems.append("no final response to the INFO in the capture")
        elif status >= 300:
            problems.append(f"INFO rejected with {status}: the far end does not accept DTMF this way")
        rows.append(compact({
            "time": iso(parse_time(m["frame.time_epoch"])), "frame": to_int(m["frame.number"]), "source": "sip_info",
            "digit": digit, "call_id": m["sip.Call-ID"], "src": m["ip.src"], "dst": m["ip.dst"],
            "content_type": ctype, "duration_ms": duration, "response": status, "issues": problems,
        }))
    return rows


def summarise(rows: list[dict[str, Any]], sdps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per call: the digits by method, the negotiated telephone-event types and a note
    when both methods carry the same digits (the far end may act on them twice)."""
    pts = negotiated(sdps)
    calls: dict[str, dict[str, Any]] = {}
    for r in rows:
        cid = r.get("call_id") or "(no call)"
        c = calls.setdefault(cid, {"call_id": cid, "rfc4733": "", "sip_info": ""})
        c[r["source"]] += str(r.get("digit") or "?")
    for cid, types in pts.items():
        c = calls.setdefault(cid, {"call_id": cid, "rfc4733": "", "sip_info": ""})
        c["telephone_event_payload_types"] = sorted(types)
    out = []
    for c in calls.values():
        if c["rfc4733"] and c["sip_info"]:
            c["note"] = ("this call sends DTMF both in RTP and in SIP INFO; a far end that honours both can act on a "
                         "digit twice, one that honours only one misses the others")
        if not c["rfc4733"] and not c["sip_info"]:
            continue
        out.append(compact(c))
    return out
