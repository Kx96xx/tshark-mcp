"""SMS over IMS (TS 24.341): SIP MESSAGE carrying ``application/vnd.3gpp.sms``.

Each MESSAGE carries one RP message (TS 24.011): RP-DATA with the TPDU, RP-ACK
or RP-ERROR answering it, or RP-SMMA. An SMS is two SIP transactions: the
MESSAGE with RP-DATA and, later, a MESSAGE in the other direction with the
RP-ACK or RP-ERROR of the same RP message reference. MO (UE to network) is
RP-DATA type 0 with an SMS-SUBMIT; MT (network to UE) is type 1 with an
SMS-DELIVER or SMS-STATUS-REPORT. A MESSAGE seen on several legs through the
CSCFs (same Call-ID and CSeq) is one transaction here.

tshark decodes the RP and TP layers (``gsm_a.rp``, ``gsm_sms``); the RP header
and the TP-Status of a status report are also read from the raw body, so the
result does not depend on how a tshark version names those fields.
"""

from __future__ import annotations

from typing import Any

from . import ims, sip
from .fields import compact, iso, parse_time, to_int

FILTER = 'sip.CSeq.method == "MESSAGE"'
EXTRA_FIELDS = [
    "sip.Content-Type", "sip.Status-Line", "sip.msg_body", "gsm_a.rp.msg_type", "gsm_a.rp.rp_message_reference",
    "gsm_a.rp.cause", "gsm_a.rp.tpdu", "gsm_a.dtap.cld_party_bcd_num", "gsm_a.dtap.clg_party_bcd_num",
    "gsm_sms.tp-mti", "gsm_sms.tp-mr", "gsm_sms.tp-srr", "gsm_sms.tp-fcs", "gsm_sms.tp-oa", "gsm_sms.tp-da",
    "gsm_sms.tp-ra", "gsm_sms.tp-dcs", "gsm_sms.tp.user_data_length", "gsm_sms.udh.mm.msg_id",
    "gsm_sms.udh.mm.msg_parts", "gsm_sms.udh.mm.msg_part",
]
SMS_TYPE = "application/vnd.3gpp.sms"
ACK_WINDOW = 60.0
"""Seconds after an RP-DATA within which its RP-ACK or RP-ERROR is looked for (TR1M
is 35 to 45 s)."""
REPORT_WINDOW = 3600.0

RP_TYPES = {
    0: "RP-DATA (MS to network)", 1: "RP-DATA (network to MS)", 2: "RP-ACK (MS to network)",
    3: "RP-ACK (network to MS)", 4: "RP-ERROR (MS to network)", 5: "RP-ERROR (network to MS)",
    6: "RP-SMMA (MS to network)",
}
# TS 24.011 table 8.4 (RP-Cause).
RP_CAUSES = {
    1: "Unassigned (unallocated) number", 8: "Operator determined barring", 10: "Call barred",
    21: "Short message transfer rejected", 22: "Memory capacity exceeded", 27: "Destination out of order",
    28: "Unidentified subscriber", 29: "Facility rejected", 30: "Unknown subscriber", 38: "Network out of order",
    41: "Temporary failure", 42: "Congestion", 47: "Resources unavailable, unspecified",
    50: "Requested facility not subscribed", 69: "Requested facility not implemented",
    81: "Invalid short message transfer reference value", 95: "Semantically incorrect message",
    96: "Invalid mandatory information", 97: "Message type non-existent or not implemented",
    98: "Message not compatible with short message protocol state",
    99: "Information element non-existent or not implemented", 111: "Protocol error, unspecified",
    127: "Interworking, unspecified",
}
# TP-MTI by direction (TS 23.040 9.2.3.1).
TP_MS_TO_SC = {0: "SMS-DELIVER-REPORT", 1: "SMS-SUBMIT", 2: "SMS-COMMAND"}
TP_SC_TO_MS = {0: "SMS-DELIVER", 1: "SMS-SUBMIT-REPORT", 2: "SMS-STATUS-REPORT"}
# TS 23.040 9.2.3.15 (TP-Status), the values seen in practice; the rest by range.
TP_STATUS = {
    0x00: "received by the recipient", 0x01: "forwarded, delivery not confirmed", 0x02: "replaced by the SC",
    0x20: "congestion, SC still trying", 0x21: "recipient busy, SC still trying",
    0x22: "no response from the recipient, SC still trying", 0x23: "service rejected, SC still trying",
    0x40: "remote procedure error", 0x41: "incompatible destination", 0x42: "connection rejected by the recipient",
    0x43: "not obtainable", 0x45: "no interworking available", 0x46: "validity period expired",
    0x47: "deleted by the originating SME", 0x48: "deleted by SC administration", 0x49: "message does not exist",
    0x60: "congestion, SC stopped trying", 0x61: "recipient busy, SC stopped trying",
    0x62: "no response from the recipient, SC stopped trying", 0x63: "service rejected, SC stopped trying",
}
# What a SIP failure to a MESSAGE usually means for SMS over IMS.
SIP_HINTS = {
    403: "Forbidden: the S-CSCF or IP-SM-GW refused the sender (not allowed to send SMS over IMS, or barred)",
    404: "Not Found: the recipient is not registered in IMS (no binding at the S-CSCF)",
    408: "Request Timeout: the next hop or the UE did not answer the MESSAGE",
    415: "Unsupported Media Type: the recipient does not accept application/vnd.3gpp.sms",
    480: "Temporarily Unavailable: the recipient is registered but cannot take the MESSAGE now",
    488: "Not Acceptable Here: the recipient's registration does not cover SMS over IP",
    500: "Server Internal Error at the S-CSCF or IP-SM-GW",
    503: "Service Unavailable: the S-CSCF or IP-SM-GW is overloaded or out of service",
    504: "Server Time-out: no answer from the IP-SM-GW or the SMSC behind it",
}


def _hex_bytes(text: str | None) -> bytes:
    import re

    cleaned = re.sub(r"[^0-9a-fA-F]", "", text or "")
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def rp_header(body: bytes) -> dict[str, int]:
    """RP message type, reference and (RP-ERROR) cause from the raw RP message."""
    if len(body) < 2:
        return {}
    out = {"type": body[0] & 0x07, "mr": body[1]}
    if out["type"] in (4, 5) and len(body) >= 4 and body[2] >= 1:
        out["cause"] = body[3] & 0x7F
    return out


def _bcd(data: bytes, digits: int) -> str:
    out = []
    for b in data:
        for nibble in (b & 0x0F, b >> 4):
            if nibble <= 9:
                out.append(str(nibble))
    return "".join(out[:digits])


def status_report(tpdu: bytes) -> dict[str, Any] | None:
    """TP-MR, recipient digits and TP-Status of an SMS-STATUS-REPORT TPDU."""
    if len(tpdu) < 4 or tpdu[0] & 0x03 != 2:
        return None
    mr = tpdu[1]
    ndigits = tpdu[2]
    end = 4 + (ndigits + 1) // 2
    st_at = end + 14  # TP-SCTS and TP-DT, seven octets each
    if len(tpdu) <= st_at:
        return {"tp_mr": mr}
    return {"tp_mr": mr, "tp_ra": _bcd(tpdu[4:end], ndigits), "tp_st": tpdu[st_at]}


def tp_status_name(st: int) -> str:
    if st in TP_STATUS:
        return TP_STATUS[st]
    if st < 0x20:
        return "transaction completed"
    if st < 0x40:
        return "temporary error, SC still trying"
    if st < 0x60:
        return "permanent error, SC stopped trying"
    return "temporary error, SC stopped trying"


def _first(rec: dict[str, Any], key: str) -> str:
    value = rec.get(key) or ""
    return value.split(sip.AGGREGATOR)[0].split(",")[0].strip()


def _pdu(rec: dict[str, Any]) -> dict[str, Any] | None:
    """The RP and TP content of one MESSAGE, or None when it carries no 3GPP SMS."""
    ctype = (rec.get("sip.Content-Type") or "").split(";")[0].strip().lower()
    body = _hex_bytes(rec.get("sip.msg_body"))
    rp_type = to_int(_first(rec, "gsm_a.rp.msg_type"))
    if ctype != SMS_TYPE and rp_type is None:
        return None
    raw = rp_header(body)
    rp_type = rp_type if rp_type is not None else raw.get("type")
    mr = to_int(_first(rec, "gsm_a.rp.rp_message_reference"))
    mr = mr if mr is not None else raw.get("mr")
    cause = to_int(_first(rec, "gsm_a.rp.cause"))
    cause = cause if cause is not None else raw.get("cause")
    out: dict[str, Any] = {"rp_type": rp_type, "mr": mr, "cause": cause, "body_present": bool(body) or rp_type is not None}
    if rp_type == 0:
        out["smsc"] = _first(rec, "gsm_a.dtap.cld_party_bcd_num") or None
    elif rp_type == 1:
        out["smsc"] = _first(rec, "gsm_a.dtap.clg_party_bcd_num") or None
    mti = to_int(_first(rec, "gsm_sms.tp-mti"))
    tpdu_raw = _hex_bytes(_first(rec, "gsm_a.rp.tpdu"))
    if mti is None and tpdu_raw:
        mti = tpdu_raw[0] & 0x03
    if mti is not None and rp_type is not None:
        names = TP_MS_TO_SC if rp_type % 2 == 0 else TP_SC_TO_MS
        parts = to_int(_first(rec, "gsm_sms.udh.mm.msg_parts"))
        tp: dict[str, Any] = {
            "type": names.get(mti, f"TP-MTI {mti}"),
            "tp_mr": to_int(_first(rec, "gsm_sms.tp-mr")),
            "tp_da": _first(rec, "gsm_sms.tp-da") or None,
            "tp_oa": _first(rec, "gsm_sms.tp-oa") or None,
            "status_report_requested": True if _first(rec, "gsm_sms.tp-srr") in ("1", "True") else None,
            "dcs": to_int(_first(rec, "gsm_sms.tp-dcs")),
            "user_data_length": to_int(_first(rec, "gsm_sms.tp.user_data_length")),
            "failure_cause": to_int(_first(rec, "gsm_sms.tp-fcs")),
        }
        if parts:
            tp["concatenated"] = (f"part {to_int(_first(rec, 'gsm_sms.udh.mm.msg_part'))} of {parts}, "
                                  f"reference {to_int(_first(rec, 'gsm_sms.udh.mm.msg_id'))}")
        if tp["type"] == "SMS-STATUS-REPORT":
            sr = status_report(tpdu_raw) or {}
            tp["tp_mr"] = tp["tp_mr"] if tp["tp_mr"] is not None else sr.get("tp_mr")
            tp["tp_ra"] = _first(rec, "gsm_sms.tp-ra") or sr.get("tp_ra")
            if sr.get("tp_st") is not None:
                tp["tp_st"] = sr["tp_st"]
                tp["status"] = tp_status_name(sr["tp_st"])
        out["tpdu"] = compact(tp)
    return out


def transactions(stdout: str, fields: list[str]) -> tuple[list[dict[str, Any]], int]:
    """MESSAGE transactions carrying 3GPP SMS, in the order first seen, and the
    number of other MESSAGE transactions (pager-mode text and the like)."""
    txs: dict[tuple[str, str], dict[str, Any]] = {}
    for rec in sip.parse_messages(stdout, fields):
        if rec["sip.CSeq.method"] != "MESSAGE":
            continue
        key = (rec["sip.Call-ID"], rec["sip.CSeq.seq"])
        ts = parse_time(rec["frame.time_epoch"])
        frame = to_int(rec["frame.number"])
        leg = (rec["ip.src"], rec["ip.dst"])
        tx = txs.get(key)
        if tx is None:
            tx = txs[key] = {"call_id": key[0], "request": None, "time": ts, "frame": frame, "legs": [], "seen": {},
                             "retransmissions": 0, "copies": 0, "finals": []}
        if ts is not None and (tx["time"] is None or ts < tx["time"]):
            tx["time"], tx["frame"] = ts, frame
        status = to_int(rec["sip.Status-Code"])
        kind = ("req" if rec["sip.Method"] else "rsp", status)
        last = tx["seen"].get((leg, kind))
        tx["seen"][(leg, kind)] = ts
        if rec.get("sip.resend") in ("1", "True") and last is not None:
            if ts is not None and abs(ts - last) <= ims.COPY_WINDOW:
                tx["copies"] += 1
            elif rec["sip.Method"]:
                tx["retransmissions"] += 1
            continue
        if rec["sip.Method"] == "MESSAGE":
            if leg not in tx["legs"]:
                tx["legs"].append(leg)
            if tx["request"] is None:
                tx["request"] = rec
        elif status is not None and status >= 200:
            tx["finals"].append({"status": status, "time": ts, "frame": frame})
    out, other = [], 0
    for tx in sorted(txs.values(), key=lambda t: (t["time"] if t["time"] is not None else 0.0, t["frame"] or 0)):
        if tx["request"] is None:
            continue
        pdu = _pdu(tx["request"])
        if pdu is None:
            other += 1
            continue
        req = tx["request"]
        tx["finals"].sort(key=lambda f: (f["time"] if f["time"] is not None else 0.0, f["frame"] or 0))
        final = tx["finals"][0] if tx["finals"] else None
        out.append({
            "call_id": tx["call_id"], "time": tx["time"], "frame": tx["frame"], "from": req["sip.from.addr"],
            "to": req["sip.to.addr"], "request_uri": req["sip.r-uri"], "pdu": pdu,
            "status": final["status"] if final else None, "status_frame": final["frame"] if final else None,
            "status_ms": (round((final["time"] - tx["time"]) * 1000.0, 3)
                          if final and final["time"] is not None and tx["time"] is not None else None),
            "other_leg_statuses": sorted({f["status"] for f in tx["finals"]} - {final["status"]}) if final else [],
            "legs": len(tx["legs"]), "retransmissions": tx["retransmissions"], "copies": tx["copies"],
            "users": {ims.user_of(req["sip.from.addr"]), ims.user_of(req["sip.to.addr"]),
                      ims.user_of(req["sip.r-uri"])} - {""},
        })
    return out, other


def _canon(user: str, aliases: dict[str, dict[str, Any]]) -> str:
    row = aliases.get(user)
    return ims.user_of(row["impu"]) if row else user


def _ue_user(tx: dict[str, Any]) -> str:
    """The UE's identity in an RP-DATA or RP-SMMA: the sender of an MO message, the
    recipient (To) of an MT one."""
    if tx["pdu"]["rp_type"] == 1:
        return ims.user_of(tx["to"]) or ims.user_of(tx["request_uri"])
    return ims.user_of(tx["from"])


def _ack_row(ack: dict[str, Any], data_time: float | None) -> dict[str, Any]:
    pdu = ack["pdu"]
    cause = pdu.get("cause")
    return compact({
        "rp_message": RP_TYPES.get(pdu["rp_type"]), "frame": ack["frame"], "time": iso(ack["time"]),
        "call_id": ack["call_id"],
        "delay_ms": round((ack["time"] - data_time) * 1000.0, 3) if ack["time"] is not None and data_time is not None else None,
        "rp_cause": cause, "rp_cause_name": RP_CAUSES.get(cause) if cause is not None else None,
        "tpdu": pdu.get("tpdu"), "sip_response": ack["status"], "sip_response_frame": ack["status_frame"],
        "no_sip_response": True if ack["status"] is None else None,
        "retransmissions": ack["retransmissions"] or None,
    })


def _sip_reason(status: int, frame: int | None) -> str:
    hint = SIP_HINTS.get(status) or f"refused with {status}"
    return f"the MESSAGE was answered {status} (frame {frame}): {hint}"


def messages(txs: list[dict[str, Any]], registrations: list[dict[str, Any]],
             capture_end: float | None) -> list[dict[str, Any]]:
    """One row per RP-DATA or RP-SMMA (with its RP-ACK/RP-ERROR and, for an MO
    submit that asked for one, its status report), plus one per RP-ACK/RP-ERROR that
    answers nothing in the capture."""
    aliases = ims.aliases(registrations)
    acks = [t for t in txs if t["pdu"]["rp_type"] in (2, 3, 4, 5)]
    used: set[int] = set()
    rows: list[dict[str, Any]] = []
    reports_for: dict[int, dict[str, Any]] = {}
    datas = [t for t in txs if t["pdu"]["rp_type"] not in (2, 3, 4, 5)]
    # Status reports first, so each MO submit can name its own.
    for t in datas:
        tp = t["pdu"].get("tpdu") or {}
        if t["pdu"]["rp_type"] != 1 or tp.get("type") != "SMS-STATUS-REPORT":
            continue
        ue = _canon(_ue_user(t), aliases)
        for s in datas:
            stp = s["pdu"].get("tpdu") or {}
            if (s["pdu"]["rp_type"] == 0 and stp.get("status_report_requested") and stp.get("tp_mr") == tp.get("tp_mr")
                    and _canon(_ue_user(s), aliases) == ue and id(s) not in reports_for
                    and s["time"] is not None and t["time"] is not None and 0 <= t["time"] - s["time"] <= REPORT_WINDOW):
                reports_for[id(s)] = t
                t["report_of"] = s["frame"]
                break
    for t in datas:
        rp_type = t["pdu"]["rp_type"]
        ue = _canon(_ue_user(t), aliases) if rp_type is not None else ""
        ack, how = None, None
        if t["pdu"]["mr"] is not None and t["time"] is not None:
            candidates = [a for a in acks if id(a) not in used and a["pdu"]["mr"] == t["pdu"]["mr"]
                          and a["time"] is not None and 0 <= a["time"] - t["time"] <= ACK_WINDOW
                          and not (a["call_id"] == t["call_id"])]
            ack = next((a for a in candidates if ue and ue in {_canon(u, aliases) for u in a["users"]}), None)
            how = "RP-MR and UE identity"
            if ack is None and len(candidates) == 1:
                ack, how = candidates[0], "RP-MR and time only (no identity in common)"
        if ack is not None:
            used.add(id(ack))
        rows.append(_data_row(t, ack, how, reports_for.get(id(t)), aliases, capture_end))
    for a in acks:
        if id(a) in used:
            continue
        rows.append(compact({
            "time": iso(a["time"]), "frame": a["frame"], "rp_message": RP_TYPES.get(a["pdu"]["rp_type"]),
            "rp_mr": a["pdu"]["mr"], "call_id": a["call_id"], "from": a["from"], "to": a["to"],
            "request_uri": a["request_uri"], "ack": _ack_row(a, None), "verdict": "orphan_ack",
            "reasons": [f"no RP-DATA with RP-MR {a['pdu']['mr']} within {int(ACK_WINDOW)} s before it in the capture"],
        }))
    rows.sort(key=lambda r: (r.get("time") or "", r.get("frame") or 0))
    return rows


def _data_row(t: dict[str, Any], ack: dict[str, Any] | None, how: str | None, report: dict[str, Any] | None,
              aliases: dict[str, dict[str, Any]], capture_end: float | None) -> dict[str, Any]:
    pdu = t["pdu"]
    rp_type = pdu["rp_type"]
    direction = "MO" if rp_type in (0, 6) else "MT" if rp_type == 1 else None
    reasons: list[str] = []
    ue_user = _ue_user(t) if rp_type is not None else ""
    reg = aliases.get(ue_user) if ue_user else None
    ue_reg = None
    if reg is not None:
        ue_reg = compact({"impu": reg["impu"], "first_frame": reg.get("first_frame"), "verdict": reg["verdict"],
                          "smsip": reg.get("smsip")})
    elif ue_user:
        ue_reg = {"found": False}
    no_smsip = reg is not None and reg.get("smsip") is False
    status = t["status"]
    verdict = None
    if not pdu.get("body_present"):
        reasons.append("the SMS body is not in the capture (cut or stripped), so the RP layer is unknown")
    if ack is not None:
        ack_type = ack["pdu"]["rp_type"]
        expected = {3, 5} if direction == "MO" else {2, 4}
        if direction and ack_type not in expected:
            sender = "the network" if direction == "MO" else "the UE"
            reasons.append(f"the {RP_TYPES[ack_type].split(' (')[0]} (frame {ack['frame']}) is coded "
                           f"{RP_TYPES[ack_type].split(' (')[1].rstrip(')')} (type {ack_type}) although {sender} "
                           "sends it: the receiver may discard it as a protocol error")
        if ack_type in (4, 5):
            verdict = "rejected"
            cause = ack["pdu"].get("cause")
            reasons.append(f"RP-ERROR at frame {ack['frame']}" + (f", cause {cause} ({RP_CAUSES.get(cause, 'unknown')})"
                                                                  if cause is not None else ""))
        else:
            verdict = "delivered" if direction == "MT" else "accepted"
        if ack["status"] is None or ack["status"] >= 300:
            what = "was never answered" if ack["status"] is None else f"was answered {ack['status']}"
            to = "the UE" if direction == "MO" else "the network"
            reasons.append(f"the MESSAGE carrying the {RP_TYPES[ack_type].split(' (')[0]} (frame {ack['frame']}) {what}: "
                           f"{to} did not accept the RP answer"
                           + (", so the UE treats the SMS as failed and may send it again" if direction == "MO" else ""))
            if verdict != "rejected":
                verdict = "ack_not_delivered"
        if how and how != "RP-MR and UE identity":
            reasons.append(f"paired with its answer by {how}")
    elif status is not None and status >= 300:
        verdict = "not_registered_for_sms" if no_smsip else "sip_failed"
        reasons.append(_sip_reason(status, t["status_frame"]))
    elif rp_type is None:
        verdict = "rp_unknown"
        reasons.append("without the RP layer the answer cannot be paired"
                       + (f"; the MESSAGE itself was answered {status} (frame {t['status_frame']})" if status else ""))
    elif status is not None:
        left = capture_end - t["time"] if capture_end is not None and t["time"] is not None else None
        if left is not None and left < ACK_WINDOW:
            verdict = "in_progress"
            reasons.append(f"the MESSAGE was answered {status} but no RP answer yet; the capture ends "
                           f"{round(left, 1)} s after it, before the {int(ACK_WINDOW)} s the answer may take")
        else:
            verdict = "no_rp_ack"
            reasons.append(f"the MESSAGE was answered {status} (frame {t['status_frame']}) but no RP-ACK or RP-ERROR "
                           f"with RP-MR {pdu['mr']} came back within {int(ACK_WINDOW)} s: the "
                           + ("UE" if direction == "MT" else "IP-SM-GW or SMSC") + " did not answer the RP layer")
    elif capture_end is not None and t["time"] is not None and capture_end - t["time"] <= ims.IN_PROGRESS_WINDOW:
        verdict = "in_progress"
        reasons.append(f"no SIP response yet; the capture ends {round(capture_end - t['time'], 1)} s after the MESSAGE")
    else:
        verdict = "not_registered_for_sms" if no_smsip else "no_response"
        reasons.append("the MESSAGE got no final SIP response in the capture"
                       + (f" ({t['retransmissions']} retransmissions)" if t["retransmissions"] else ""))
    if no_smsip:
        reasons.append(f"the UE registered without +g.3gpp.smsip (REGISTER at frame {reg.get('first_frame')}): "
                       "the network should not use SMS over IMS for it"
                       + (", which explains the failure" if verdict in ("not_registered_for_sms",) else ""))
    if report is not None:
        st = (report["pdu"].get("tpdu") or {})
        if st.get("tp_st") is not None and st["tp_st"] >= 0x20:
            reasons.append(f"the status report (frame {report['frame']}) says {st.get('status')}")
    elif direction == "MO" and (pdu.get("tpdu") or {}).get("status_report_requested") and verdict == "accepted":
        reasons.append("a status report was requested and none came back in the capture")
    tp = pdu.get("tpdu") or {}
    return compact({
        "time": iso(t["time"]), "frame": t["frame"], "direction": direction,
        "rp_message": RP_TYPES.get(rp_type) if rp_type is not None else None, "rp_mr": pdu["mr"],
        "call_id": t["call_id"], "from": t["from"], "to": t["to"], "request_uri": t["request_uri"],
        "smsc_digits": pdu.get("smsc"), "tpdu": tp,
        "status_report_of_frame": t.get("report_of"),
        "sip_response": status, "sip_response_frame": t["status_frame"], "sip_response_ms": t["status_ms"],
        "other_leg_statuses": t["other_leg_statuses"],
        "legs": t["legs"] if t["legs"] > 1 else None, "retransmissions": t["retransmissions"] or None,
        "copies": t["copies"] or None,
        "ack": _ack_row(ack, t["time"]) if ack is not None else None,
        "status_report": compact({"frame": report["frame"], "time": iso(report["time"]),
                                  "tp_st": (report["pdu"].get("tpdu") or {}).get("tp_st"),
                                  "status": (report["pdu"].get("tpdu") or {}).get("status")}) if report else None,
        "ue_registration": ue_reg,
        "verdict": verdict,
    }) | {"reasons": reasons}


def matches(row: dict[str, Any], number: str | None, imsi: str | None) -> bool:
    """Whether a row names ``number`` (digits in a SIP/tel user, TP address or SMSC)
    or ``imsi`` (in a SIP user or the registered IMPU)."""
    tp = row.get("tpdu") or {}
    names = [row.get("from"), row.get("to"), row.get("request_uri"), (row.get("ue_registration") or {}).get("impu"),
             tp.get("tp_oa"), tp.get("tp_da"), tp.get("tp_ra"), row.get("smsc_digits")]
    users = {ims.user_of(n) for n in names if n}
    if number and not any(number in u for u in users):
        return False
    if imsi and not any(imsi in u for u in users):
        return False
    return True
