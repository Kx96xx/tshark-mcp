"""SIP dialog grouping (RFC 3261), built from ``-T fields`` output."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from .fields import compact, iso, parse_time, split_fields_line, to_int

FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "sip.Call-ID", "sip.Method", "sip.Status-Code",
    "sip.CSeq.method", "sip.CSeq.seq", "sip.from.addr", "sip.to.addr", "sip.r-uri", "sip.P-Asserted-Identity",
    "sip.Reason", "sip.Contact",
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


def correlation_filter(call_ids: set[str]) -> str | None:
    if not call_ids:
        return None
    quoted = ", ".join('"' + c.replace('"', '') + '"' for c in sorted(call_ids))
    return f"sip.Call-ID in {{{quoted}}}"


def parse_messages(stdout: str) -> list[dict[str, Any]]:
    out = []
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(FIELDS):
            continue
        rec = dict(zip(FIELDS, cols))
        # A packet may carry several SIP messages; keep the first of each field.
        for k, v in rec.items():
            if AGGREGATOR in v and k not in ("sip.P-Asserted-Identity",):
                rec[k] = v.split(AGGREGATOR)[0]
        if not rec["sip.Call-ID"]:
            continue
        out.append(rec)
    return out


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
                "initial_method": None,
                "initial_cseq": None,
                "final_status": None,
                "final_time": None,
                "messages": [],
            }
        method = rec["sip.Method"]
        status = to_int(rec["sip.Status-Code"])
        cseq_method = rec["sip.CSeq.method"]
        cseq = to_int(rec["sip.CSeq.seq"])
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
        })
        d["messages"].append(entry)
        if (status is not None and status >= 200 and d["final_status"] is None
                and cseq_method == d["initial_method"] and (d["initial_cseq"] is None or cseq == d["initial_cseq"])):
            d["final_status"] = status
            d["final_time"] = ts
    rows = []
    for d in dialogs.values():
        ttf = None
        if d["final_time"] is not None and d["first_time"] is not None:
            ttf = round((d["final_time"] - d["first_time"]) * 1000.0, 3)
        methods = [m["method"] for m in d["messages"] if m.get("method")]
        rows.append(compact({
            "call_id": d["call_id"],
            "time": iso(d["first_time"]),
            "src": d["src"],
            "dst": d["dst"],
            "initial_method": d["initial_method"],
            "request_uri": d["request_uri"],
            "from": d["from"],
            "to": d["to"],
            "p_asserted_identity": d["p_asserted_identity"],
            "final_status": d["final_status"],
            "time_to_final_ms": ttf,
            "no_final_response": d["initial_method"] is not None and d["final_status"] is None,
            "message_count": len(d["messages"]),
            "methods": methods,
            "messages": d["messages"],
        }))
    rows.sort(key=lambda r: r.get("time") or "")
    return rows


def call_ids(rows: list[dict[str, Any]]) -> set[str]:
    return {r["call_id"] for r in rows}
