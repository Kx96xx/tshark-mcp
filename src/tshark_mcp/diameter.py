"""Diameter (RFC 6733 and 3GPP applications) transaction extraction."""

from __future__ import annotations

from typing import Any

from .fields import (
    Json, all_values, compact, endpoints, first, frame_interface, frame_number, frame_time, iso, protocol_messages,
    to_int,
)
from .pairing import CaptureEnd, Message, Transaction, base_row, mark_unanswered_near_end, pair_messages

LAYER = "diameter"
JSON_LAYERS = "frame ip ipv6 diameter"

# code -> (request abbreviation, answer abbreviation, name)
COMMANDS: dict[int, tuple[str, str, str]] = {
    257: ("CER", "CEA", "Capabilities-Exchange"),
    258: ("RAR", "RAA", "Re-Auth"),
    265: ("AAR", "AAA", "AA"),
    271: ("ACR", "ACA", "Accounting"),
    272: ("CCR", "CCA", "Credit-Control"),
    274: ("ASR", "ASA", "Abort-Session"),
    275: ("STR", "STA", "Session-Termination"),
    280: ("DWR", "DWA", "Device-Watchdog"),
    282: ("DPR", "DPA", "Disconnect-Peer"),
    300: ("UAR", "UAA", "User-Authorization"),
    301: ("SAR", "SAA", "Server-Assignment"),
    302: ("LIR", "LIA", "Location-Info"),
    303: ("MAR", "MAA", "Multimedia-Auth"),
    304: ("RTR", "RTA", "Registration-Termination"),
    305: ("PPR", "PPA", "Push-Profile"),
    306: ("UDR", "UDA", "User-Data"),
    307: ("PUR", "PUA", "Profile-Update"),
    308: ("SNR", "SNA", "Subscribe-Notifications"),
    309: ("PNR", "PNA", "Push-Notification"),
    316: ("ULR", "ULA", "Update-Location"),
    317: ("CLR", "CLA", "Cancel-Location"),
    318: ("AIR", "AIA", "Authentication-Information"),
    319: ("IDR", "IDA", "Insert-Subscriber-Data"),
    320: ("DSR", "DSA", "Delete-Subscriber-Data"),
    321: ("PUR", "PUA", "Purge-UE"),
    322: ("RSR", "RSA", "Reset"),
    323: ("NOR", "NOA", "Notify"),
    324: ("ECR", "ECA", "ME-Identity-Check"),
    8388620: ("PLR", "PLA", "Provide-Location"),
    8388621: ("LRR", "LRA", "Location-Report"),
}

APPLICATIONS: dict[int, str] = {
    0: "Base",
    1: "NASREQ",
    3: "Base Accounting",
    4: "Credit-Control (Gy/Ro)",
    16777216: "Cx/Dx",
    16777217: "Sh",
    16777236: "Rx",
    16777238: "Gx",
    16777250: "STa",
    16777251: "S6a/S6d",
    16777252: "S13",
    16777255: "SLg",
    16777264: "SWm",
    16777265: "SWx",
    16777266: "Gxx",
    16777267: "S9",
    16777272: "S6b",
    16777291: "SLh",
    16777302: "Sy",
    16777308: "S6c",
    16777312: "S6m",
    16777345: "S6t",
    4294967295: "Relay",
}

RESULT_CODES: dict[int, str] = {
    1001: "DIAMETER_MULTI_ROUND_AUTH",
    2001: "DIAMETER_SUCCESS",
    2002: "DIAMETER_LIMITED_SUCCESS",
    3001: "DIAMETER_COMMAND_UNSUPPORTED",
    3002: "DIAMETER_UNABLE_TO_DELIVER",
    3003: "DIAMETER_REALM_NOT_SERVED",
    3004: "DIAMETER_TOO_BUSY",
    3005: "DIAMETER_LOOP_DETECTED",
    3006: "DIAMETER_REDIRECT_INDICATION",
    3007: "DIAMETER_APPLICATION_UNSUPPORTED",
    3008: "DIAMETER_INVALID_HDR_BITS",
    3009: "DIAMETER_INVALID_AVP_BITS",
    3010: "DIAMETER_UNKNOWN_PEER",
    4001: "DIAMETER_AUTHENTICATION_REJECTED",
    4002: "DIAMETER_OUT_OF_SPACE",
    4003: "ELECTION_LOST",
    4010: "DIAMETER_END_USER_SERVICE_DENIED",
    4011: "DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE",
    4012: "DIAMETER_CREDIT_LIMIT_REACHED",
    5001: "DIAMETER_AVP_UNSUPPORTED",
    5002: "DIAMETER_UNKNOWN_SESSION_ID",
    5003: "DIAMETER_AUTHORIZATION_REJECTED",
    5004: "DIAMETER_INVALID_AVP_VALUE",
    5005: "DIAMETER_MISSING_AVP",
    5006: "DIAMETER_RESOURCES_EXCEEDED",
    5007: "DIAMETER_CONTRADICTING_AVPS",
    5008: "DIAMETER_AVP_NOT_ALLOWED",
    5009: "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES",
    5010: "DIAMETER_NO_COMMON_APPLICATION",
    5011: "DIAMETER_UNSUPPORTED_VERSION",
    5012: "DIAMETER_UNABLE_TO_COMPLY",
    5013: "DIAMETER_INVALID_BIT_IN_HEADER",
    5014: "DIAMETER_INVALID_AVP_LENGTH",
    5015: "DIAMETER_INVALID_MESSAGE_LENGTH",
    5016: "DIAMETER_INVALID_AVP_BIT_COMBO",
    5017: "DIAMETER_NO_COMMON_SECURITY",
    5030: "DIAMETER_USER_UNKNOWN",
    5031: "DIAMETER_RATING_FAILED",
}

# 3GPP Experimental-Result-Code values (TS 29.272, 29.229, 29.329, 29.212).
EXPERIMENTAL_RESULT_CODES: dict[int, str] = {
    2001: "DIAMETER_FIRST_REGISTRATION",
    2002: "DIAMETER_SUBSEQUENT_REGISTRATION",
    2003: "DIAMETER_UNREGISTERED_SERVICE",
    2004: "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED",
    4100: "DIAMETER_USER_DATA_NOT_AVAILABLE",
    4101: "DIAMETER_PRIOR_UPDATE_IN_PROGRESS",
    4181: "DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE",
    4182: "DIAMETER_ERROR_CAMEL_SUBSCRIPTION_PRESENT",
    4261: "REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED",
    5001: "DIAMETER_ERROR_USER_UNKNOWN",
    5002: "DIAMETER_ERROR_IDENTITIES_DONT_MATCH",
    5003: "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED",
    5004: "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
    5005: "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED",
    5006: "DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED",
    5007: "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE",
    5008: "DIAMETER_ERROR_TOO_MUCH_DATA",
    5009: "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA",
    5011: "DIAMETER_ERROR_FEATURE_UNSUPPORTED",
    5012: "DIAMETER_ERROR_SERVING_NODE_FEATURE_UNSUPPORTED",
    5100: "DIAMETER_ERROR_USER_DATA_NOT_RECOGNIZED",
    5101: "DIAMETER_ERROR_OPERATION_NOT_ALLOWED",
    5102: "DIAMETER_ERROR_USER_DATA_CANNOT_BE_READ",
    5103: "DIAMETER_ERROR_USER_DATA_CANNOT_BE_MODIFIED",
    5104: "DIAMETER_ERROR_USER_DATA_CANNOT_BE_NOTIFIED",
    5105: "DIAMETER_ERROR_TRANSPARENT_DATA_OUT_OF_SYNC",
    5106: "DIAMETER_ERROR_SUBS_DATA_ABSENT",
    5107: "DIAMETER_ERROR_NO_SUBSCRIPTION_TO_DATA",
    5108: "DIAMETER_ERROR_DSAI_NOT_AVAILABLE",
    5420: "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION",
    5421: "DIAMETER_ERROR_RAT_NOT_ALLOWED",
    5422: "DIAMETER_ERROR_EQUIPMENT_UNKNOWN",
    5423: "DIAMETER_ERROR_UNKNOWN_SERVING_NODE",
    5450: "DIAMETER_ERROR_USER_NO_NON_3GPP_SUBSCRIPTION",
    5451: "DIAMETER_ERROR_USER_NO_APN_SUBSCRIPTION",
    5452: "DIAMETER_ERROR_RAT_TYPE_NOT_ALLOWED",
    5470: "DIAMETER_ERROR_INITIAL_PARAMETERS",
    5471: "DIAMETER_ERROR_TRIGGER_EVENT",
    5472: "DIAMETER_PCC_RULE_EVENT",
    5473: "DIAMETER_ERROR_BEARER_NOT_AUTHORIZED",
    5474: "DIAMETER_ERROR_TRAFFIC_MAPPING_INFO_REJECTED",
    5061: "INVALID_SERVICE_INFORMATION",
    5062: "FILTER_RESTRICTIONS",
    5063: "REQUESTED_SERVICE_NOT_AUTHORIZED",
    5064: "DUPLICATED_AF_SESSION",
    5065: "IP-CAN_SESSION_NOT_AVAILABLE",
    5066: "UNAUTHORIZED_NON_EMERGENCY_SESSION",
    5067: "UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY",
    5068: "TEMPORARY_NETWORK_FAILURE",
    5490: "DIAMETER_ERROR_UNAUTHORIZED_REQUESTING_NETWORK",
    5510: "DIAMETER_ERROR_UNKNOWN_POLICY_COUNTERS",
}


def command_name(code: int, is_request: bool) -> str:
    entry = COMMANDS.get(code)
    if entry is None:
        return f"cmd-{code}-{'R' if is_request else 'A'}"
    return entry[0] if is_request else entry[1]


def identity_filter(imsi: str | None, msisdn: str | None) -> str | None:
    """First-pass filter: requests that name the subscriber."""
    parts = []
    if imsi:
        parts.append(f'diameter.User-Name == "{imsi}"')
        parts.append(f'diameter.User-Name contains "{imsi}"')
    if msisdn:
        parts.append(f'diameter.User-Name contains "{msisdn}"')
        parts.append(f'diameter.Public-Identity contains "{msisdn}"')
        parts.append(f'diameter.MSISDN == {_tbcd_bytes(msisdn)}')
    return " || ".join(parts) if parts else None


def correlation_filter(sessions: set[str]) -> str | None:
    """Second-pass filter: every message of the sessions found in pass one."""
    if not sessions:
        return None
    quoted = ", ".join('"' + s.replace('"', '') + '"' for s in sorted(sessions))
    return f"diameter.Session-Id in {{{quoted}}}"


def _tbcd_bytes(digits: str) -> str:
    if len(digits) % 2:
        digits += "f"
    pairs = [digits[i + 1] + digits[i] for i in range(0, len(digits), 2)]
    return ":".join(pairs)


def _top_avps(msg: Json) -> list[Json]:
    """The command-level AVPs of one Diameter message (tshark's ``diameter.avp_tree``, one entry per AVP
    with ``--no-duplicate-keys``); an AVP inside a grouped AVP sits deeper, under ``<Name>_tree``."""
    tree = msg.get("diameter.avp_tree")
    if isinstance(tree, list):
        return [a for a in tree if isinstance(a, dict)]
    return [tree] if isinstance(tree, dict) else []


def command_results(msg: Json) -> tuple[int | None, int | None, list[int]]:
    """(command-level Result-Code, command-level Experimental-Result-Code, Result-Codes inside each
    Multiple-Services-Credit-Control). A Result-Code nested in Proxy-Info, an MSCC or any other grouped
    AVP is not the answer's result (RFC 6733 7.1, RFC 4006 8.16)."""
    top = _top_avps(msg)
    if not top:  # no AVP tree to tell the levels apart: the first one found, as before
        return (to_int(first(msg, "diameter.Result-Code")), to_int(first(msg, "diameter.Experimental-Result-Code")), [])
    rc = next((to_int(a["diameter.Result-Code"]) for a in top if "diameter.Result-Code" in a), None)
    erc = next((to_int(first(a, "diameter.Experimental-Result-Code")) for a in top
                if "diameter.Experimental-Result" in a or "diameter.Experimental-Result_tree" in a), None)
    mscc = [code for a in top if "diameter.Multiple-Services-Credit-Control_tree" in a
            for code in [to_int(first(a["diameter.Multiple-Services-Credit-Control_tree"], "diameter.Result-Code"))]
            if code is not None]
    return rc, erc, mscc


def extract_messages(packets: list[Json], keep_raw: bool = False) -> list[Message]:
    """One Message per Diameter PDU; ``keep_raw`` keeps the dissected PDU under ``raw``
    for the AVP tools."""
    messages: list[Message] = []
    for packet in packets:
        ts = frame_time(packet)
        frame = frame_number(packet)
        src, dst = endpoints(packet)
        iface = frame_interface(packet)
        for msg in protocol_messages(packet, LAYER):
            code = to_int(first(msg, "diameter.cmd.code"))
            if code is None:
                continue
            is_request = first(msg, "diameter.flags.request") == "1"
            hbh = to_int(first(msg, "diameter.hopbyhopid"))
            e2e = to_int(first(msg, "diameter.endtoendid"))
            session = first(msg, "diameter.Session-Id")
            rc, erc, mscc = command_results(msg)
            fields: dict[str, Any] = {
                "command_code": code,
                "application_id": to_int(first(msg, "diameter.applicationId")),
                "session_id": session,
                "hop_by_hop": hbh,
                "end_to_end": e2e,
                "origin_host": first(msg, "diameter.Origin-Host"),
                "origin_realm": first(msg, "diameter.Origin-Realm"),
                "destination_host": first(msg, "diameter.Destination-Host"),
                "destination_realm": first(msg, "diameter.Destination-Realm"),
                "user_name": first(msg, "diameter.User-Name"),
                "public_identity": first(msg, "diameter.Public-Identity"),
                "msisdn_raw": first(msg, "diameter.MSISDN"),
                "result_code": rc,
                "experimental_result_code": erc,
                "mscc_result_codes": mscc,
                "error_flag": first(msg, "diameter.flags.error") == "1",
                "retransmit_flag": first(msg, "diameter.flags.T") == "1",
            }
            if keep_raw:
                fields["raw"] = msg
            messages.append(Message(
                frame=frame, time=ts, src=src, dst=dst, is_request=is_request,
                key=(hbh, e2e), name=command_name(code, is_request), fields=fields, interface=iface,
            ))
    return messages


def _compatible(request: Message, answer: Message) -> bool:
    rs, as_ = request.fields.get("session_id"), answer.fields.get("session_id")
    if rs and as_ and rs != as_:
        return False
    return request.fields["command_code"] == answer.fields["command_code"]


def pair(messages: list[Message]) -> list[Transaction]:
    return pair_messages(messages, compatible=_compatible)


def transaction_row(tx: Transaction) -> dict[str, Any]:
    req, ans = tx.request, tx.answer
    anchor = req or ans
    assert anchor is not None
    f = anchor.fields
    code = f["command_code"]
    entry = COMMANDS.get(code)
    row = base_row(tx)
    row.update({
        "command_code": code,
        "command": entry[2] if entry else None,
        "request": entry[0] if entry else f"cmd-{code}-R",
        "answer": (entry[1] if entry else f"cmd-{code}-A") if ans else None,
        "application_id": f.get("application_id"),
        "application": APPLICATIONS.get(f["application_id"]) if f.get("application_id") is not None else None,
        "session_id": f.get("session_id") or (ans.fields.get("session_id") if ans else None),
        "hop_by_hop": _hex(f.get("hop_by_hop")),
        "end_to_end": _hex(f.get("end_to_end")),
        "origin_host": (req or anchor).fields.get("origin_host"),
        "origin_realm": (req or anchor).fields.get("origin_realm"),
        "destination_host": (req or anchor).fields.get("destination_host"),
        "destination_realm": (req or anchor).fields.get("destination_realm"),
        "user_name": (req.fields.get("user_name") if req else None) or (ans.fields.get("user_name") if ans else None),
    })
    if req is not None and req.fields.get("retransmit_flag"):
        row["retransmitted"] = True
    if ans is not None:
        rc = ans.fields.get("result_code")
        erc = ans.fields.get("experimental_result_code")
        row["answer_origin_host"] = ans.fields.get("origin_host")
        if rc is not None:
            row["result_code"] = rc
            row["result"] = RESULT_CODES.get(rc, f"result-{rc}")
        if erc is not None:
            row["experimental_result_code"] = erc
            if rc is None:  # RFC 6733 7.6: Experimental-Result stands in for Result-Code, never beside it
                row["result"] = EXPERIMENTAL_RESULT_CODES.get(erc, f"experimental-{erc}")
        mscc = ans.fields.get("mscc_result_codes") or []
        if mscc:
            row["mscc_result_codes"] = mscc
            bad = [c for c in mscc if not 2000 <= c < 3000]
            if bad:
                row["mscc_results"] = [RESULT_CODES.get(c, f"result-{c}") for c in bad]
        if rc is None and erc is None:
            row["result"] = "no Result-Code AVP"
        row["success"] = _is_success(rc, erc)
        if ans.fields.get("error_flag"):
            row["error_bit"] = True
    return compact(row)


def _is_success(rc: int | None, erc: int | None) -> bool:
    """Command-level success. A credit-control answer can succeed while one service unit fails
    (DIAMETER_CREDIT_LIMIT_REACHED in an MSCC): that is in ``mscc_result_codes``, not here."""
    if rc is not None:
        return 2000 <= rc < 3000
    if erc is not None:
        return 2000 <= erc < 3000
    return False


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:08x}"


def subscriber_sessions(messages: list[Message], imsi: str | None, msisdn: str | None,
                        exact_imsi: bool = False) -> set[str]:
    """Session-Ids of the messages that themselves name the subscriber.

    Several Diameter messages can share one SCTP packet, so a packet that matched an
    identity filter may also carry other subscribers' sessions; only the sessions
    whose own messages carry the IMSI (User-Name) or MSISDN (User-Name,
    Public-Identity or MSISDN AVP) belong to the subscriber.
    """
    tbcd = _tbcd_bytes(msisdn).lower() if msisdn else None
    found: set[str] = set()
    for m in messages:
        sid = m.fields.get("session_id")
        if not sid:
            continue
        user = m.fields.get("user_name") or ""
        hit = False
        if imsi:
            hit = user == imsi if exact_imsi else imsi in user
        if not hit and msisdn:
            hit = (msisdn in user or msisdn in (m.fields.get("public_identity") or "")
                   or (m.fields.get("msisdn_raw") or "").lower() == tbcd)
        if hit:
            found.add(sid)
    return found


def session_ids(messages: list[Message]) -> set[str]:
    return {m.fields["session_id"] for m in messages if m.fields.get("session_id")}


def session_filter(session_id: str | None, imsi: str | None, command_code: int | None) -> str | None:
    """Display filter selecting the messages of interest for ``diameter_sessions``.

    Arguments must already be linted (``lint_quoted_value`` / ``lint_digits``).
    The pieces are ANDed: a Session-Id narrows to one session, an IMSI to the
    sessions whose User-Name carries it and a command code to one command. An
    answer does not repeat the User-Name, so the caller fetches the whole
    session in a second pass with :func:`correlation_filter`.
    """
    parts = []
    if session_id:
        parts.append(f'diameter.Session-Id == "{session_id}"')
    if imsi:
        parts.append(f'diameter.User-Name == "{imsi}"')
    if command_code is not None:
        parts.append(f"diameter.cmd.code == {int(command_code)}")
    return " && ".join(parts) if parts else None


def session_rows(transactions: list[Transaction], capture_end: CaptureEnd | None = None) -> tuple[list[dict[str, Any]], int]:
    """Group paired transactions by Session-Id.

    Returns the session rows (ordered by first message) and the number of
    transactions that carried no Session-Id (Device-Watchdog, Capabilities-
    Exchange and other peer-level commands), which are left out of the rows.
    ``capture_end`` (see :func:`pairing.mark_unanswered_near_end`) flags unanswered
    requests the capture stopped too soon after; each session counts them as
    ``unanswered_near_capture_end``.
    """
    sessions: dict[str, dict[str, Any]] = {}
    without_session = 0
    all_rows = [transaction_row(tx) for tx in transactions]
    mark_unanswered_near_end(transactions, all_rows, capture_end)
    for tx, row in zip(transactions, all_rows):
        sid = row.get("session_id")
        if not sid:
            without_session += 1
            continue
        anchor = tx.request or tx.answer
        assert anchor is not None
        end = tx.answer or tx.request
        assert end is not None
        s = sessions.get(sid)
        if s is None:
            s = sessions[sid] = {
                "session_id": sid,
                "application_id": row.get("application_id"),
                "application": row.get("application"),
                "origin_host": row.get("origin_host"),
                "destination_host": row.get("destination_host") or row.get("answer_origin_host"),
                "origin_realm": row.get("origin_realm"),
                "destination_realm": row.get("destination_realm"),
                "user_name": row.get("user_name"),
                "src": row.get("src"),
                "dst": row.get("dst"),
                "_first": anchor.time,
                "_last": end.time,
                "transactions": [],
                "request_codes": [],
                "answer_codes": [],
                "result_codes": [],
                "unanswered": 0,
                "unanswered_near_capture_end": 0,
                "failed": 0,
            }
        s["_first"] = min(s["_first"], anchor.time)
        s["_last"] = max(s["_last"], end.time)
        for key in ("user_name", "destination_host", "application", "application_id"):
            if s.get(key) is None and row.get(key) is not None:
                s[key] = row[key]
        s["request_codes"].append(row["command_code"])
        if row.get("answer"):
            s["answer_codes"].append(row["command_code"])
        code = row.get("result_code", row.get("experimental_result_code"))
        if code is not None:
            s["result_codes"].append(code)
        if row.get("unanswered"):
            s["unanswered"] += 1
            if row.get("near_capture_end"):
                s["unanswered_near_capture_end"] += 1
        if row.get("success") is False:
            s["failed"] += 1
        s["transactions"].append(compact({
            "time": row.get("time"),
            "request": row.get("request"),
            "answer": row.get("answer"),
            "command_code": row["command_code"],
            "command": row.get("command"),
            "hop_by_hop": row.get("hop_by_hop"),
            "end_to_end": row.get("end_to_end"),
            "request_frame": row.get("request_frame"),
            "answer_frame": row.get("answer_frame"),
            "result_code": row.get("result_code"),
            "experimental_result_code": row.get("experimental_result_code"),
            "result": row.get("result"),
            "success": row.get("success"),
            "rtt_ms": row.get("rtt_ms"),
            "unanswered": row.get("unanswered"),
            "near_capture_end": row.get("near_capture_end"),
            "note": row.get("note"),
            "unmatched_answer": row.get("unmatched_answer"),
            "retransmitted": row.get("retransmitted"),
        }))
    rows = []
    for s in sorted(sessions.values(), key=lambda x: x["_first"]):
        rtts = [t["rtt_ms"] for t in s["transactions"] if t.get("rtt_ms") is not None]
        rows.append(compact({
            "session_id": s["session_id"],
            "first_time": iso(s["_first"]),
            "last_time": iso(s["_last"]),
            "duration_ms": round((s["_last"] - s["_first"]) * 1000.0, 3),
            "application_id": s["application_id"],
            "application": s["application"],
            "origin_host": s["origin_host"],
            "destination_host": s["destination_host"],
            "origin_realm": s["origin_realm"],
            "destination_realm": s["destination_realm"],
            "user_name": s["user_name"],
            "src": s["src"],
            "dst": s["dst"],
            "transaction_count": len(s["transactions"]),
            "request_codes": s["request_codes"],
            "answer_codes": s["answer_codes"],
            "result_codes": s["result_codes"],
            "unanswered": s["unanswered"],
            "unanswered_near_capture_end": s["unanswered_near_capture_end"] or None,
            "failed": s["failed"],
            "max_rtt_ms": max(rtts) if rtts else None,
            "transactions": s["transactions"],
        }))
    return rows, without_session


__all__ = [
    "APPLICATIONS", "COMMANDS", "EXPERIMENTAL_RESULT_CODES", "JSON_LAYERS", "LAYER", "RESULT_CODES",
    "all_values", "Json", "command_name", "correlation_filter", "extract_messages", "identity_filter", "pair",
    "session_filter", "session_ids", "session_rows", "subscriber_sessions", "transaction_row",
]
