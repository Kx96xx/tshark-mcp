"""SIP dialog grouping (RFC 3261), built from ``-T fields`` output."""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

from .fields import compact, iso, parse_time, split_fields_line, to_int

FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "sip.Call-ID", "sip.Method", "sip.Status-Code",
    "sip.CSeq.method", "sip.CSeq.seq", "sip.from.addr", "sip.to.addr", "sip.r-uri", "sip.P-Asserted-Identity",
    "sip.Reason", "sip.Contact", "sip.resend", "sip", "sip.P-Preferred-Identity", "sip.auth.username",
]
AGGREGATOR = "|"

# Methods that open a dialog or transaction worth summarising on their own.
INITIAL_METHODS = ("INVITE", "REGISTER", "SUBSCRIBE", "MESSAGE", "OPTIONS", "PUBLISH", "NOTIFY", "REFER", "INFO", "UPDATE", "PRACK", "BYE", "CANCEL", "ACK")


def identity_filter(imsi: str | None, msisdn: str | None) -> str | None:
    parts = []
    if msisdn:
        for field in ("sip.from.user", "sip.to.user", "sip.r-uri.user", "sip.P-Asserted-Identity", "sip.P-Preferred-Identity"):
            parts.append(f'{field} contains "{msisdn}"')
    if imsi:
        # IMS private identities carry the IMSI (IMSI@ims.mnc...), as does the Authorization username.
        parts.append(f'sip.From contains "{imsi}"')
        parts.append(f'sip.auth contains "{imsi}"')
    return " || ".join(parts) if parts else None


def selection_filter(call_id: str | None, number: str | None, method: str | None) -> str | None:
    """First-pass filter for ``sip_dialogs``: messages of the wanted Call-ID, carrying
    the number in an identity header, or of the given method. Arguments must already
    be linted. The caller then fetches the complete dialogs with
    :func:`correlation_filter` so responses are not lost to the filter."""
    parts = []
    if call_id:
        parts.append(f'sip.Call-ID == "{call_id}"')
    if number:
        parts.append("(" + (identity_filter(None, number) or "") + ")")
    if method:
        parts.append(f'(sip.Method == "{method}" || sip.CSeq.method == "{method}")')
    return " && ".join(parts) if parts else None


def correlation_filter(call_ids: set[str]) -> str | None:
    if not call_ids:
        return None
    quoted = ", ".join('"' + c.replace('"', '') + '"' for c in sorted(call_ids))
    return f"sip.Call-ID in {{{quoted}}}"


# Fields a SIP message carries exactly once, so their n-th value belongs to the n-th
# message of a packet; requests carry one Method and Request-URI, responses one Status-Code.
_PER_MESSAGE = ("sip.Call-ID", "sip.CSeq.method", "sip.CSeq.seq", "sip.from.addr", "sip.to.addr", "sip.resend")
_PER_REQUEST = ("sip.Method", "sip.r-uri")
_PER_RESPONSE = ("sip.Status-Code",)
_PACKET = ("frame.number", "frame.time_epoch", "ip.src", "ip.dst")
_KIND = re.compile(r"\(([^()]*)\)\s*$")


def parse_messages(stdout: str, fields: list[str] | None = None, multi: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """One record per SIP message. A TCP segment can carry several messages; tshark
    then lists each field's values for all of them, and the protocol item text
    ("Session Initiation Protocol (INVITE)" or "(200)") says which is a request and
    which a response, so every value goes back to its own message. Optional headers
    (P-Asserted-Identity, Reason, Contact, ...) are kept for a message only when every
    message of the packet has exactly one. ``fields`` is :data:`FIELDS` followed by any
    extra columns (the message body, more headers); extras follow the same rule.
    Columns named in ``multi`` (headers that may repeat, such as P-Associated-URI)
    keep every value of a one-message packet, joined by the aggregator."""
    fields = fields or FIELDS
    out = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(fields):
            continue
        rec = dict(zip(fields, cols))
        call_ids = rec["sip.Call-ID"].split(AGGREGATOR) if rec["sip.Call-ID"] else []
        if len(call_ids) <= 1:
            for k, v in rec.items():
                if AGGREGATOR in v and k != "sip.P-Asserted-Identity" and k not in multi:
                    rec[k] = v.split(AGGREGATOR)[0]
            if rec["sip.Call-ID"]:
                out.append(rec)
            continue
        out.extend(_split_bundle(rec, len(call_ids)))
    return out


def _split_bundle(rec: dict[str, str], n: int) -> list[dict[str, Any]]:
    values = {k: (v.split(AGGREGATOR) if v else []) for k, v in rec.items()}
    kinds = [_message_kind(v) for v in values["sip"]]
    if len(kinds) != n or None in kinds:
        # No usable protocol item text: tell requests from responses by the counts.
        if len(values["sip.Method"]) == n:
            kinds = ["request"] * n
        elif len(values["sip.Status-Code"]) == n:
            kinds = ["response"] * n
        else:
            kinds = [None] * n
    counters = {"request": 0, "response": 0}
    messages = []
    for i in range(n):
        msg = {k: "" for k in rec}
        for k in ("frame.number", "frame.time_epoch", "ip.src", "ip.dst"):
            msg[k] = values[k][0] if values[k] else ""
        for k in _PER_MESSAGE:
            msg[k] = values[k][i] if len(values[k]) == n else ""
        kind = kinds[i]
        if kind is not None:
            j = counters[kind]
            counters[kind] += 1
            for k in (_PER_REQUEST if kind == "request" else _PER_RESPONSE):
                msg[k] = values[k][j] if j < len(values[k]) else ""
        for k in values:
            if k in _PACKET or k in _PER_MESSAGE or k in _PER_REQUEST or k in _PER_RESPONSE or k == "sip":
                continue
            if len(values[k]) == n:
                msg[k] = values[k][i]
        if msg["sip.Call-ID"]:
            messages.append(msg)
    return messages


def _message_kind(text: str) -> str | None:
    m = _KIND.search(text)
    if not m:
        return None
    token = m.group(1).strip()
    if token.isdigit():
        return "response"
    return "request" if token else None


def matching_call_ids(stdout: str, call_id: str | None = None, number: str | None = None, method: str | None = None,
                      imsi: str | None = None) -> set[str]:
    """Call-IDs with at least one message that itself satisfies every given criterion,
    the per-message counterpart of :func:`selection_filter` and :func:`identity_filter`
    (``number`` and ``imsi`` alone are ORed, as in a subscriber trace). Used to drop the
    dialogs that were only selected because their message shared a TCP segment with
    a matching one."""
    found = set()
    for rec in parse_messages(stdout):
        if call_id and rec["sip.Call-ID"] != call_id:
            continue
        if method and method not in (rec["sip.Method"], rec["sip.CSeq.method"]):
            continue
        if number or imsi:
            ids = " ".join(rec[k] for k in ("sip.from.addr", "sip.to.addr", "sip.r-uri", "sip.P-Asserted-Identity",
                                            "sip.P-Preferred-Identity"))
            hit = bool(number) and number in ids
            if not hit and imsi:
                hit = imsi in rec["sip.from.addr"] or imsi in rec["sip.auth.username"]
            if not hit:
                continue
        found.add(rec["sip.Call-ID"])
    return found


def selected_call_ids(stdout: str) -> tuple[set[str], set[str]]:
    """Call-IDs from a one-column (``sip.Call-ID``, comma-aggregated) selection pass:
    (those that were alone in a matching packet, those that shared one with other
    messages and so may not match themselves)."""
    alone: set[str] = set()
    shared: set[str] = set()
    for ln in stdout.splitlines():
        ids = [v.strip() for v in ln.strip().split(",") if v.strip()]
        (alone if len(ids) == 1 else shared).update(ids)
    return alone, shared - alone


def group_dialogs(stdout: str) -> list[dict[str, Any]]:
    dialogs: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
    for rec in parse_messages(stdout):
        call_id = rec["sip.Call-ID"]
        ts = parse_time(rec["frame.time_epoch"])
        d = dialogs.get(call_id)
        if d is None:
            d = dialogs[call_id] = {
                "call_id": call_id,
                "from": rec["sip.from.addr"] or None,
                "to": rec["sip.to.addr"] or None,
                "request_uri": rec["sip.r-uri"] or None,
                "p_asserted_identity": rec["sip.P-Asserted-Identity"] or None,
                "src": rec["ip.src"],
                "dst": rec["ip.dst"],
                "first_time": ts,
                "last_time": ts,
                "initial_method": None,
                "initial_cseq": None,
                "final_status": None,
                "final_time": None,
                "finals": {},
                "attempts": set(),
                "resent": 0,
                "messages": [],
            }
        method = rec["sip.Method"]
        status = to_int(rec["sip.Status-Code"])
        cseq_method = rec["sip.CSeq.method"]
        cseq = to_int(rec["sip.CSeq.seq"])
        resend = rec["sip.resend"] in ("1", "True")
        if resend:
            d["resent"] += 1
        if d["initial_method"] is None and method:
            d["initial_method"] = method
            d["initial_cseq"] = cseq
            d["request_uri"] = d["request_uri"] or rec["sip.r-uri"] or None
            d["p_asserted_identity"] = d["p_asserted_identity"] or rec["sip.P-Asserted-Identity"] or None
        entry = compact({
            "frame": to_int(rec["frame.number"]),
            "time": iso(ts),
            "dir": f'{rec["ip.src"]} > {rec["ip.dst"]}',
            "method": method or None,
            "status": status,
            "cseq": f"{cseq} {cseq_method}" if cseq is not None else None,
            "reason": rec["sip.Reason"] or None,
            "resend": resend or None,
        })
        d["messages"].append(entry)
        if ts is not None and (d["last_time"] is None or ts > d["last_time"]):
            d["last_time"] = ts
        if method and method == d["initial_method"] and cseq is not None:
            d["attempts"].add(cseq)
        if (status is not None and status >= 200 and d["final_status"] is None
                and cseq_method == d["initial_method"] and (d["initial_cseq"] is None or cseq == d["initial_cseq"])):
            d["final_status"] = status
            d["final_time"] = ts
        # A dialog may carry several transactions of the initial method (REGISTER 401, then
        # REGISTER with credentials 200, then refreshes); see _outcome.
        if status is not None and status >= 200 and cseq_method == d["initial_method"] and cseq is not None:
            d["finals"].setdefault(cseq, status)
    rows = []
    for d in dialogs.values():
        ttf = None
        if d["final_time"] is not None and d["first_time"] is not None:
            ttf = round((d["final_time"] - d["first_time"]) * 1000.0, 3)
        methods = [m["method"] for m in d["messages"] if m.get("method") and not m.get("resend")]
        duration = None
        if d["last_time"] is not None and d["first_time"] is not None:
            duration = round((d["last_time"] - d["first_time"]) * 1000.0, 3)
        outcome = _outcome(d["finals"])
        rows.append(compact({
            "call_id": d["call_id"],
            "time": iso(d["first_time"]),
            "duration_ms": duration,
            "src": d["src"],
            "dst": d["dst"],
            "initial_method": d["initial_method"],
            "request_uri": d["request_uri"],
            "from": d["from"],
            "to": d["to"],
            "p_asserted_identity": d["p_asserted_identity"],
            "final_status": d["final_status"],
            "time_to_final_ms": ttf,
            "outcome_status": outcome,
            "attempts": len(d["attempts"]) if len(d["attempts"]) > 1 else None,
            "resent_messages": d["resent"] or None,
            "no_final_response": d["initial_method"] is not None and d["final_status"] is None,
            "message_count": len(d["messages"]),
            "methods": methods,
            "messages": d["messages"],
        }))
    rows.sort(key=lambda r: r.get("time") or "")
    return rows


CHALLENGES = (401, 407)


def _outcome(finals: dict[int, int]) -> int | None:
    """The final status that settles the initial request: the first one, in CSeq order,
    that is not an authentication challenge (401/407) answered by a retry. Later
    transactions of the same method (re-INVITEs, REGISTER refreshes) do not change it;
    when every attempt was challenged, the last challenge is the outcome."""
    statuses = [finals[c] for c in sorted(finals)]
    for status in statuses:
        if status not in CHALLENGES:
            return status
    return statuses[-1] if statuses else None


def dialog_failed(row: dict[str, Any]) -> bool:
    """A dialog failed when its outcome (see _outcome) is a 4xx/5xx/6xx. A REGISTER
    answered 401 and then 200 after the challenge is a success."""
    status = row.get("outcome_status") or row.get("final_status") or 0
    return status >= 400


def call_ids(rows: list[dict[str, Any]]) -> set[str]:
    return {r["call_id"] for r in rows}


# ----------------------------------------------------------------- SDP per call
# The SIP fields plus the raw body and its type, for the media tools.
MEDIA_FIELDS = [*FIELDS, "sip.msg_body", "sip.Content-Type"]


def sdp_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every message of ``messages`` (from :func:`parse_messages` with
    :data:`MEDIA_FIELDS`) that carries SDP, in capture order, with its role in the
    RFC 3264 offer/answer exchange of its Call-ID. SDP in a request is an ``offer``
    (in ACK, or in PRACK after an offer in a reliable 18x, an ``answer``); SDP in a
    response is the ``answer`` to the offer its request carried (same CSeq), or an
    ``offer`` when the request had none (answered in the ACK); SDP in a failure
    response (a 488 listing what the far end supports) is ``failure_response``, not an
    answer. An SDP whose o= session
    id and version were already seen in the call is a ``repeat``: the answer sent in
    183 and again in 200, or the same body forwarded by a proxy on its other leg.
    Retransmissions are skipped."""
    from . import sdp as sdp_mod

    out: list[dict[str, Any]] = []
    seen: dict[str, set[str]] = {}
    offered_cseqs: dict[str, set[str]] = {}
    response_offer: dict[str, bool] = {}
    for rec in messages:
        if rec.get("sip.resend") in ("1", "True"):
            continue
        text = sdp_mod.extract(sdp_mod.body_text(rec.get("sip.msg_body")))
        if not text:
            continue
        parsed = sdp_mod.parse(text)
        if not parsed["media"]:
            continue
        call_id = rec["sip.Call-ID"]
        method = rec["sip.Method"]
        cseq = rec.get("sip.CSeq.seq", "")
        key = f'{parsed.get("origin")}|{parsed.get("origin_version")}'
        keys = seen.setdefault(call_id, set())
        if parsed.get("origin_version") and key in keys:
            role = "repeat"
        elif to_int(rec["sip.Status-Code"]) is not None and to_int(rec["sip.Status-Code"]) >= 300:
            role = "failure_response"
        elif method:
            if method == "ACK" or (method == "PRACK" and response_offer.get(call_id)):
                role = "answer"
                response_offer[call_id] = False
            else:
                role = "offer"
                offered_cseqs.setdefault(call_id, set()).add(cseq)
        elif cseq in offered_cseqs.get(call_id, set()):
            role = "answer"
        else:
            role = "offer"
            response_offer[call_id] = True
        keys.add(key)
        status = to_int(rec["sip.Status-Code"])
        out.append({
            "call_id": call_id,
            "frame": to_int(rec["frame.number"]),
            "time": parse_time(rec["frame.time_epoch"]),
            "src": rec["ip.src"],
            "dst": rec["ip.dst"],
            "message": method or (f'{status} {rec["sip.CSeq.method"]}'.strip() if status is not None else ""),
            "role": role,
            "sdp": parsed,
        })
    return out


def media_endpoints(sdps: list[dict[str, Any]]) -> dict[tuple[str, int], list[dict[str, Any]]]:
    """(address, port) -> the SDP media sections that advertised it as a receive address,
    for RTP and (on the RTCP port) RTCP, oldest first."""
    out: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for entry in sdps:
        for index, media in enumerate(entry["sdp"]["media"]):
            addr = media.get("address")
            if not addr or not media.get("port"):
                continue
            ref = {"entry": entry, "media": media, "index": index, "rtcp": False}
            out.setdefault((addr, media["port"]), []).append(ref)
            if media.get("rtcp_port"):
                out.setdefault((addr, media["rtcp_port"]), []).append({**ref, "rtcp": True})
    return out


# ----------------------------------------------------------------- one call in detail
# MEDIA_FIELDS plus what sip_call_detail needs; group_dialogs reads the leading FIELDS columns.
DETAIL_FIELDS = [*MEDIA_FIELDS, "sip.from.tag", "sip.Warning", "sip.Status-Line"]

# ITU-T Q.850 cause values most often seen in SIP Reason headers.
Q850 = {
    1: "Unallocated (unassigned) number", 3: "No route to destination", 16: "Normal call clearing",
    17: "User busy", 18: "No user responding", 19: "No answer from user (user alerted)", 20: "Subscriber absent",
    21: "Call rejected", 22: "Number changed", 27: "Destination out of order", 28: "Invalid number format",
    31: "Normal, unspecified", 34: "No circuit/channel available", 38: "Network out of order",
    41: "Temporary failure", 42: "Switching equipment congestion", 44: "Requested circuit/channel not available",
    47: "Resource unavailable, unspecified", 57: "Bearer capability not authorized",
    58: "Bearer capability not presently available", 65: "Bearer capability not implemented",
    79: "Service or option not implemented", 88: "Incompatible destination", 102: "Recovery on timer expiry",
    111: "Protocol error, unspecified", 127: "Interworking, unspecified",
}
_Q850 = re.compile(r"Q\.850\s*;\s*cause\s*=\s*(\d+)", re.I)


def reason_detail(reason: str) -> dict[str, Any]:
    """A Reason header with the Q.850 cause named."""
    out: dict[str, Any] = {"header": reason}
    m = _Q850.search(reason)
    if m:
        cause = int(m.group(1))
        out["q850_cause"] = cause
        if cause in Q850:
            out["q850_name"] = Q850[cause]
    return out


def _ms(a: float | None, b: float | None) -> float | None:
    return round((b - a) * 1000.0, 3) if a is not None and b is not None else None


def call_detail(stdout: str, call_id: str) -> dict[str, Any] | None:
    """One INVITE call from ``-T fields`` output of :data:`DETAIL_FIELDS`: the dialog
    row of :func:`group_dialogs` plus post-dial delay, answer and setup times, early
    media, retransmissions per message, the final response with its reason phrase,
    Reason and Warning headers (Q.850 causes named), the SDP offer/answer with the
    codecs both sides share, who sent BYE or CANCEL, and the call duration."""
    from . import sdp as sdp_mod

    rows = [r for r in group_dialogs(stdout) if r["call_id"] == call_id]
    if not rows:
        return None
    row = rows[0]
    msgs = [m for m in parse_messages(stdout, DETAIL_FIELDS) if m["sip.Call-ID"] == call_id]
    if not msgs:
        return None
    first = msgs[0]
    invite = next((m for m in msgs if m["sip.Method"] == "INVITE"), None)
    caller_tag = (invite or first)["sip.from.tag"] or None
    caller_ip = (invite or first)["ip.src"]
    t_invite = parse_time(invite["frame.time_epoch"]) if invite else None
    invite_cseq = invite["sip.CSeq.seq"] if invite else None

    def side(m: dict[str, Any]) -> str:
        tag = m["sip.from.tag"]
        if caller_tag and tag:
            return "caller" if tag == caller_tag else "callee"
        return "caller" if m["ip.src"] == caller_ip else "callee"

    retrans: dict[str, int] = {}
    provisional: list[tuple[int, float | None, bool]] = []
    final = None
    answer_time = ack_time = end_time = None
    ended_by = None
    reasons: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    for m in msgs:
        status = to_int(m["sip.Status-Code"])
        method = m["sip.Method"]
        label = method or f'{status} {m["sip.CSeq.method"]}'
        ts = parse_time(m["frame.time_epoch"])
        frame = to_int(m["frame.number"])
        if m["sip.resend"] in ("1", "True"):
            retrans[label] = retrans.get(label, 0) + 1
            continue
        is_invite_tx = m["sip.CSeq.method"] == "INVITE" and m["sip.CSeq.seq"] == invite_cseq
        has_sdp = bool(sdp_mod.extract(sdp_mod.body_text(m.get("sip.msg_body"))))
        if status is not None and is_invite_tx:
            if 100 < status < 200:
                provisional.append((status, ts, has_sdp))
            elif status >= 200 and final is None:
                line = m.get("sip.Status-Line") or ""
                phrase = line.split(" ", 2)[2] if line.count(" ") >= 2 else None
                final = {"status": status, "reason_phrase": phrase, "frame": frame, "time": ts}
                if status < 300:
                    answer_time = ts
        if method == "ACK" and m["sip.CSeq.seq"] == invite_cseq and ack_time is None:
            ack_time = ts
        if method in ("BYE", "CANCEL") and ended_by is None:
            ended_by = {"method": method, "by": side(m), "src": m["ip.src"], "frame": frame, "time": iso(ts)}
            end_time = ts
        if m.get("sip.Reason"):
            reasons.append({"frame": frame, "message": label, **reason_detail(m["sip.Reason"])})
        if m.get("sip.Warning"):
            warnings.append({"frame": frame, "message": label, "header": m["sip.Warning"]})

    timing: dict[str, Any] = {}
    if t_invite is not None:
        first_18x = next(((s, t, e) for s, t, e in provisional if s in (180, 183)), None)
        if first_18x:
            timing["post_dial_delay_ms"] = _ms(t_invite, first_18x[1])
            timing["post_dial_delay_to"] = first_18x[0]
        elif final is not None and final["status"] >= 300:
            # RFC 6076 Session Request Delay for a failed call ends at the failure response.
            timing["post_dial_delay_ms"] = _ms(t_invite, final["time"])
            timing["post_dial_delay_to"] = final["status"]
        ring = next((t for s, t, _ in provisional if s == 180), None)
        timing["ringing_ms"] = _ms(t_invite, ring)
        timing["answer_ms"] = _ms(t_invite, answer_time)
        if answer_time is not None:
            timing["setup_ms"] = _ms(t_invite, ack_time)
    early = [s for s, _, e in provisional if e]
    if early:
        timing["early_media"] = f"SDP in {early[0]}"
    if answer_time is not None:
        timing["call_duration_s"] = round(end_time - answer_time, 3) if end_time is not None else None
        if end_time is None:
            timing["call_duration_note"] = "no BYE in the capture"

    sdps = sdp_messages(msgs)
    offer = next((e for e in sdps if e["role"] == "offer"), None)
    answer = next((e for e in sdps if e["role"] == "answer"), None)
    refusal = next((e for e in sdps if e["role"] == "failure_response"), None)
    media: dict[str, Any] = {"sdp": [
        {"frame": e["frame"], "time": iso(e["time"]), "message": e["message"], "role": e["role"], "from": e["src"],
         "media": [sdp_mod.summary(x) for x in e["sdp"]["media"]]} for e in sdps]}
    if offer and answer and offer["sdp"]["media"] and answer["sdp"]["media"]:
        o, a = offer["sdp"]["media"][0], answer["sdp"]["media"][0]
        media["common_codecs"] = sdp_mod.common_codecs(o, a)
        chosen = sdp_mod.voice_codecs(a)
        media["negotiated_codec"] = sdp_mod.codec_label(chosen[0]) if chosen else None
    elif offer and refusal and offer["sdp"]["media"] and refusal["sdp"]["media"]:
        common = sdp_mod.common_codecs(offer["sdp"]["media"][0], refusal["sdp"]["media"][0])
        media["common_codecs"] = common
        if not common:
            media["note"] = f"no codec in common between the offer and the SDP in the {refusal['message'].split()[0]}"
    elif offer and final is not None and final["status"] >= 300:
        media["note"] = "the offer was not answered (call failed)"

    outcome = "answered" if answer_time is not None else (
        "cancelled" if ended_by and ended_by["method"] == "CANCEL" else (
            f"failed {final['status']}" if final else "no final response"))
    out = {
        **row,
        "outcome": outcome,
        "caller": caller_ip,
        "final_response": compact({k: v for k, v in (final or {}).items() if k != "time"}) or None,
        "provisional": [f"{s}{' with SDP' if e else ''}" for s, _, e in provisional] or None,
        "timing": compact(timing),
        "retransmissions": retrans or None,
        "reasons": reasons or None,
        "warnings": warnings or None,
        "ended_by": ended_by,
        "media": media,
    }
    out.pop("methods", None)
    sdp_frames = {e["frame"] for e in sdps}
    out["messages"] = [{**e, "sdp": True} if e.get("frame") in sdp_frames and not e.get("resend") else e
                       for e in row.get("messages", [])]
    return compact(out)
