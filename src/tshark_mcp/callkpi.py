"""SIP call KPIs: ASR, NER, SER, PDD and ACD per peer, trunk, prefix, user agent or interval.

Built from one ``-T fields`` pass over the SIP messages (the same parser as
``sip_dialogs``). A call is one Call-ID whose first request is an INVITE;
retransmissions are ignored, an INVITE challenged with 401/407 and sent again
is still one call, and re-INVITEs do not change the outcome.
"""

from __future__ import annotations

import re
import statistics
from typing import Any

from . import sip
from .fields import compact, iso, parse_time, to_int

FIELDS = [*sip.FIELDS, "sip.r-uri.user", "sip.to.user", "sip.from.user", "sip.User-Agent"]

GROUP_BY = ("peer", "trunk", "destination_prefix", "source_prefix", "user_agent", "interval")

# Failures the called user caused (ITU-T E.411 / ETSI TS 101 329-2 NER): busy and rejected
# always; no answer, timeout and caller abandon only once the callee was alerted.
USER_BUSY_OR_REJECT = frozenset({486, 600, 603})
USER_AFTER_ALERTING = frozenset({480, 408, 487})

TIMER_B_S = 32.0   # RFC 3261 17.1.1.2: an INVITE without any response times out after 64*T1
TIMER_C_S = 180.0  # RFC 3261 16.6: a proxy waits more than three minutes for a final once it got a provisional

METHOD = {
    "call": "one Call-ID whose first request is an INVITE; retransmissions ignored; a 401/407 challenge "
            "answered by a new INVITE is the same call; the outcome is the first final response to an INVITE "
            "that is not such a challenge",
    "asr_pct": "answered (2xx) / calls",
    "ser_pct": "RFC 6076 SER: answered / (calls - calls redirected with 3xx)",
    "ser_without_487_pct": "SER with calls the caller cancelled (487) also left out of the denominator",
    "ner_pct": "network effectiveness (ITU-T E.411, ETSI TS 101 329-2): (answered + busy or rejected by the user "
               "486/600/603 + no answer or abandoned after alerting 480/408/487 after a 180/183) / calls",
    "pdd_ms": "post-dial delay, RFC 6076 Session Request Delay: first INVITE to the first 180/183; for a call "
              "that failed without one, to the failure response",
    "answer_without_ringing_ms": "first INVITE to 200 for answered calls that got no 180/183",
    "ringing_ms": "first 180/183 to the 200 of answered calls",
    "acd_s": "200 to the first BYE, answered calls whose BYE is in the capture",
    "undecided": "calls with no final response whose capture ended within Timer B (32 s) of the INVITE, or "
                 "within Timer C (180 s) once a provisional came: counted in near_capture_end and left out "
                 "of every ratio",
}

_DIGITS = re.compile(r"\d+")


def normalise_number(user: str | None) -> str | None:
    """Digits of a called or calling user part: tel/URI parameters and visual separators
    dropped, a leading + or 00 international prefix stripped. None when it is not a number."""
    if not user:
        return None
    text = user.split(";", 1)[0].strip()
    if text.lower().startswith("tel:"):
        text = text[4:]
    text = text.replace("-", "").replace(".", "").replace(" ", "").replace("(", "").replace(")", "")
    if text.startswith("+"):
        text = text[1:]
    elif text.startswith("00"):
        text = text[2:]
    return text if text.isdigit() else None


def _pct(n: int, d: int) -> float | None:
    return round(100.0 * n / d, 1) if d else None


def _quantiles(values: list[float]) -> dict[str, Any] | None:
    if not values:
        return None
    vs = sorted(values)

    def q(p: float) -> float:
        k = (len(vs) - 1) * p / 100.0
        lo = int(k)
        hi = min(lo + 1, len(vs) - 1)
        return round(vs[lo] + (vs[hi] - vs[lo]) * (k - lo), 1)
    return {"p50": q(50), "p90": q(90), "p99": q(99), "max": round(vs[-1], 1), "calls": len(vs)}


def build_calls(stdout: str, capture_end: float | None) -> list[dict[str, Any]]:
    """One record per INVITE call, in order of the first INVITE."""
    calls: dict[str, dict[str, Any]] = {}
    for rec in sip.parse_messages(stdout, FIELDS):
        cid = rec["sip.Call-ID"]
        method = rec["sip.Method"]
        resend = rec["sip.resend"] in ("1", "True")
        c = calls.get(cid)
        if c is None:
            if method != "INVITE":
                calls[cid] = {"skip": True}
                continue
            c = calls[cid] = {
                "call_id": cid, "frame": to_int(rec["frame.number"]), "t0": parse_time(rec["frame.time_epoch"]),
                "src": rec["ip.src"], "dst": rec["ip.dst"],
                "to_user": rec["sip.r-uri.user"] or rec["sip.to.user"] or None,
                "from_user": rec["sip.from.user"] or None,
                "user_agent": rec["sip.User-Agent"] or None,
                "invite_cseqs": set(), "finals": {}, "final_time": {}, "final_reason": {},
                "first_18x": None, "answer": None, "bye": None, "cancel": None, "reasons": [],
                "last": None,
            }
        if c.get("skip"):
            continue
        ts = parse_time(rec["frame.time_epoch"])
        if ts is not None and (c["last"] is None or ts > c["last"]):
            c["last"] = ts
        if resend:
            continue
        status = to_int(rec["sip.Status-Code"])
        cseq = to_int(rec["sip.CSeq.seq"])
        cseq_method = rec["sip.CSeq.method"]
        if method == "INVITE" and cseq is not None and c["answer"] is None:
            c["invite_cseqs"].add(cseq)
        if method == "INVITE" and c["user_agent"] is None and rec["sip.User-Agent"]:
            c["user_agent"] = rec["sip.User-Agent"]
        if status is not None and cseq_method == "INVITE" and cseq in c["invite_cseqs"]:
            if status in (180, 183) and c["first_18x"] is None:
                c["first_18x"] = ts
            if status >= 200 and cseq not in c["finals"]:
                c["finals"][cseq] = status
                c["final_time"][cseq] = ts
                if rec["sip.Reason"]:
                    c["final_reason"][cseq] = rec["sip.Reason"]
                if 200 <= status < 300 and c["answer"] is None:
                    c["answer"] = ts
        if method == "BYE" and c["bye"] is None:
            c["bye"] = ts
            if rec["sip.Reason"]:
                c["reasons"].append(rec["sip.Reason"])
        if method == "CANCEL" and c["cancel"] is None:
            c["cancel"] = ts
            if rec["sip.Reason"]:
                c["reasons"].append(rec["sip.Reason"])

    out = []
    for c in calls.values():
        if c.get("skip"):
            continue
        status = sip._outcome(c["finals"])
        settled = next((cs for cs in sorted(c["finals"]) if c["finals"][cs] == status), None)
        t_final = c["final_time"].get(settled) if settled is not None else None
        row: dict[str, Any] = {
            "call_id": c["call_id"], "frame": c["frame"], "time": iso(c["t0"]), "t0": c["t0"],
            "src": c["src"], "dst": c["dst"], "to": c["to_user"], "from_user": c["from_user"],
            "user_agent": c["user_agent"], "status": status, "alerted": c["first_18x"] is not None,
        }
        if c["first_18x"] is not None and c["t0"] is not None:
            row["pdd_ms"] = round((c["first_18x"] - c["t0"]) * 1000.0, 1)
        elif status is not None and status >= 300 and t_final is not None and c["t0"] is not None:
            row["pdd_ms"] = round((t_final - c["t0"]) * 1000.0, 1)
        if c["answer"] is not None and c["t0"] is not None:
            if c["first_18x"] is None:
                row["answer_without_ringing_ms"] = round((c["answer"] - c["t0"]) * 1000.0, 1)
            else:
                row["ringing_ms"] = round((c["answer"] - c["first_18x"]) * 1000.0, 1)
            if c["bye"] is not None:
                row["duration_s"] = round(c["bye"] - c["answer"], 3)
        reason = c["final_reason"].get(settled) if settled is not None else None
        for text in [reason, *c["reasons"]]:
            if text:
                detail = sip.reason_detail(text)
                if "q850_cause" in detail:
                    row["q850_cause"] = detail["q850_cause"]
                    if "q850_name" in detail:
                        row["q850_name"] = detail["q850_name"]
                    break
        if status is None:
            row["no_final_response"] = True
            if capture_end is not None and c["t0"] is not None:
                window = TIMER_C_S if c["first_18x"] is not None else TIMER_B_S
                if capture_end - c["t0"] < window:
                    row["near_capture_end"] = True
        if c["cancel"] is not None:
            row["cancelled"] = True
        out.append(row)
    return out


def group_key(call: dict[str, Any], group_by: str, prefix_len: int, interval: float) -> str:
    if group_by == "peer":
        return call["dst"] or "unknown"
    if group_by == "trunk":
        return f"{call['src']} > {call['dst']}"
    if group_by in ("destination_prefix", "source_prefix"):
        number = normalise_number(call["to"] if group_by == "destination_prefix" else call["from_user"])
        return number[:prefix_len] if number else "non-numeric"
    if group_by == "user_agent":
        return call["user_agent"] or "none"
    t0 = call["t0"]
    return iso(t0 - (t0 % interval)) if t0 is not None else "unknown"


def kpis(calls: list[dict[str, Any]]) -> dict[str, Any]:
    """The KPI block for a set of calls (see :data:`METHOD`)."""
    undecided = [c for c in calls if c.get("near_capture_end")]
    decided = [c for c in calls if not c.get("near_capture_end")]
    n = len(decided)
    answered = [c for c in decided if c["status"] is not None and 200 <= c["status"] < 300]
    redirected = sum(1 for c in decided if c["status"] is not None and 300 <= c["status"] < 400)
    cancelled_487 = sum(1 for c in decided if c["status"] == 487)
    user_caused = sum(1 for c in decided if c["status"] in USER_BUSY_OR_REJECT
                      or (c["status"] in USER_AFTER_ALERTING and c["alerted"]))
    failed = [c for c in decided if c["status"] is not None and c["status"] >= 300]
    codes: dict[str, int] = {}
    q850: dict[str, int] = {}
    for c in failed:
        codes[str(c["status"])] = codes.get(str(c["status"]), 0) + 1
        if "q850_cause" in c:
            label = f"{c['q850_cause']} {c.get('q850_name', '')}".strip()
            q850[label] = q850.get(label, 0) + 1
    durations = [c["duration_s"] for c in answered if "duration_s" in c]
    out = {
        "calls": len(calls),
        "answered": len(answered),
        "failed": len(failed),
        "no_final_response": sum(1 for c in decided if c.get("no_final_response")),
        "near_capture_end": len(undecided),
        "asr_pct": _pct(len(answered), n),
        "ser_pct": _pct(len(answered), n - redirected),
        "ser_without_487_pct": _pct(len(answered), n - redirected - cancelled_487),
        "ner_pct": _pct(len(answered) + user_caused, n),
        "pdd_ms": _quantiles([c["pdd_ms"] for c in decided if "pdd_ms" in c]),
        "answer_without_ringing_ms": _quantiles([c["answer_without_ringing_ms"] for c in answered
                                                 if "answer_without_ringing_ms" in c]),
        "ringing_ms": _quantiles([c["ringing_ms"] for c in answered if "ringing_ms" in c]),
        "acd_s": ({"mean": round(statistics.fmean(durations), 1), "median": round(statistics.median(durations), 1),
                   "calls": len(durations)} if durations else None),
        "answered_without_bye": sum(1 for c in answered if "duration_s" not in c) or None,
        "failure_codes": dict(sorted(codes.items(), key=lambda kv: (-kv[1], kv[0]))) or None,
        "q850_causes": dict(sorted(q850.items(), key=lambda kv: (-kv[1], kv[0]))) or None,
    }
    return compact(out)


def worst_calls(calls: list[dict[str, Any]], group_by: str, prefix_len: int, interval: float,
                limit: int = 10) -> list[dict[str, Any]]:
    """Failed or unanswered calls first (by status), then the slowest post-dial delays."""
    def bad(c: dict[str, Any]) -> bool:
        return (c["status"] is None and not c.get("near_capture_end")) or (c["status"] or 0) >= 300

    def rank(c: dict[str, Any]) -> tuple:
        return (0 if bad(c) else 1, -(c.get("pdd_ms") or 0.0), c["frame"] or 0)
    picked = [c for c in calls if bad(c) or c.get("pdd_ms") is not None]
    picked.sort(key=rank)
    return [compact({"call_id": c["call_id"], "frame": c["frame"], "time": c["time"],
                     "group": group_key(c, group_by, prefix_len, interval) if group_by != "user_agent" else None,
                     "user_agent": c["user_agent"] if group_by == "user_agent" else None,
                     "status": c["status"], "q850_cause": c.get("q850_cause"), "pdd_ms": c.get("pdd_ms"),
                     "no_final_response": c.get("no_final_response")}) for c in picked[:limit]]


def summarise(calls: list[dict[str, Any]], group_by: str, prefix_len: int, interval: float
              ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """(group rows sorted by call count, the whole-file KPIs)."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for c in calls:
        groups.setdefault(group_key(c, group_by, prefix_len, interval), []).append(c)
    rows = []
    for key, members in groups.items():
        row = {group_by if group_by != "interval" else "interval_start": key, **kpis(members),
               "first_frame": min(c["frame"] for c in members if c["frame"] is not None)}
        rows.append(row)
    if group_by == "interval":
        rows.sort(key=lambda r: r["interval_start"])
    else:
        rows.sort(key=lambda r: (-r["calls"], str(r[group_by])))
    return rows, kpis(calls)
