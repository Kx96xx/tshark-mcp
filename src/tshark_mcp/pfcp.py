"""PFCP (TS 29.244): the N4 / Sxa / Sxb interface between SMF or PGW-C and UPF or PGW-U.

Requests are paired with responses by sequence number and peers. Session messages
are then grouped into PFCP sessions: the Session Establishment Request carries the
control plane's F-SEID and the response the user plane's, and every later message
of the session carries the peer's SEID in its header. Node messages (Heartbeat,
Association Setup/Update/Release) are summarised per peer, including the Recovery
Time Stamp, whose change means the peer restarted and lost its sessions.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .fields import Json, compact, endpoints, first, frame_interface, frame_number, frame_time, iso, iter_values, protocol_messages, to_int
from .pairing import Message, Transaction, base_row, pair_messages

LAYER = "pfcp"
JSON_LAYERS = "frame ip ipv6 pfcp e212"
BASE_FILTER = "pfcp"

MESSAGE_TYPES: dict[int, str] = {
    1: "Heartbeat Request", 2: "Heartbeat Response", 3: "PFD Management Request", 4: "PFD Management Response",
    5: "Association Setup Request", 6: "Association Setup Response",
    7: "Association Update Request", 8: "Association Update Response",
    9: "Association Release Request", 10: "Association Release Response", 11: "Version Not Supported Response",
    12: "Node Report Request", 13: "Node Report Response",
    14: "Session Set Deletion Request", 15: "Session Set Deletion Response",
    16: "Session Set Modification Request", 17: "Session Set Modification Response",
    50: "Session Establishment Request", 51: "Session Establishment Response",
    52: "Session Modification Request", 53: "Session Modification Response",
    54: "Session Deletion Request", 55: "Session Deletion Response",
    56: "Session Report Request", 57: "Session Report Response",
}
REQUEST_TO_RESPONSE: dict[int, int] = {1: 2, 3: 4, 5: 6, 7: 8, 9: 10, 12: 13, 14: 15, 16: 17, 50: 51, 52: 53, 54: 55, 56: 57}
RESPONSE_TYPES: frozenset[int] = frozenset(REQUEST_TO_RESPONSE.values()) | {11}
SESSION_TYPES: frozenset[int] = frozenset(range(50, 58))

CAUSES: dict[int, str] = {
    1: "Request accepted", 2: "More Usage Report to send", 3: "Request partially accepted",
    64: "Request rejected (reason not specified)", 65: "Session context not found", 66: "Mandatory IE missing",
    67: "Conditional IE missing", 68: "Invalid length", 69: "Mandatory IE incorrect", 70: "Invalid Forwarding Policy",
    71: "Invalid F-TEID allocation option", 72: "No established PFCP Association",
    73: "Rule creation/modification Failure", 74: "PFCP entity in congestion", 75: "No resources available",
    76: "Service not supported", 77: "System failure", 78: "Redirection Requested",
    79: "All dynamic addresses are occupied", 80: "Unknown Pre-defined Rule", 81: "Unknown Application ID",
    82: "L2TP tunnel Establishment failure", 83: "L2TP session Establishment failure", 84: "L2TP tunnel Release",
    85: "L2TP session Release", 86: "PFCP session restoration failure due to requested SEID already allocated",
    87: "L2TP tunnel establishment failure - tunnel auth failure",
    88: "L2TP session establishment failure - session auth failure",
    89: "L2TP tunnel establishment failure - LNS not reachable",
}

# Grouped IEs counted per message (TS 29.244 table 8.1.2-1).
RULE_IES: dict[int, str] = {
    1: "create_pdr", 3: "create_far", 5: "create_urr", 7: "create_qer", 8: "created_pdr",
    9: "update_pdr", 10: "update_far", 13: "update_urr", 14: "update_qer",
    15: "remove_pdr", 16: "remove_far", 17: "remove_urr", 18: "remove_qer",
}
USAGE_REPORT_IES = frozenset({78, 79, 80})
REPORT_TYPES = (("dldr", "DLDR"), ("usar", "USAR"), ("erir", "ERIR"), ("upir", "UPIR"), ("tmir", "TMIR"),
                ("sesr", "SESR"), ("uisr", "UISR"))
REPORT_NAMES = {"DLDR": "downlink data report", "USAR": "usage report", "ERIR": "error indication report",
                "UPIR": "user plane inactivity report", "TMIR": "TSC management information report",
                "SESR": "session report", "UISR": "UP initiated session request"}
APPLY_ACTIONS = ("drop", "forw", "buff", "nocp", "dupl", "ipma", "ipmd", "dfrt", "edrt", "bdpn", "ddpn")
COPY_WINDOW_S = 0.05


def message_name(msg_type: int) -> str:
    return MESSAGE_TYPES.get(msg_type, f"message-type-{msg_type}")


def cause_name(cause: int | None) -> str | None:
    return None if cause is None else CAUSES.get(cause, f"cause-{cause}")


def parse_seid(value: Any) -> int:
    """A 64-bit SEID given as an int, decimal string or 0x hex string."""
    seid = int(value) if isinstance(value, int) else int(str(value).strip(), 0)
    if not 0 < seid <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(value)
    return seid


def parse_ip(value: str) -> str:
    return str(ipaddress.ip_address(str(value).strip()))


def selection_filter(seid: int | None, ue_ip: str | None) -> str | None:
    parts = []
    if seid is not None:
        parts.append(f"pfcp.seid == 0x{seid:016x}")
    if ue_ip:
        field = "pfcp.ue_ip_addr_ipv6" if ":" in ue_ip else "pfcp.ue_ip_addr_ipv4"
        parts.append(f"{field} == {ue_ip}")
    return " || ".join(parts) if parts else None


def seid_filter(seids: set[int]) -> str | None:
    seids = {s for s in seids if s}
    if not seids:
        return None
    return "pfcp.seid in {" + ", ".join(f"0x{s:016x}" for s in sorted(seids)) + "}"


def _hex64(value: str | int | None) -> str | None:
    if value is None:
        return None
    n = value if isinstance(value, int) else to_int(value)
    return None if n is None else f"0x{n:016x}"


def _ie_items(msg: Json):
    """Top-level IEs of a PFCP message as (ie_type, dict); repeated IEs come as lists."""
    for key, value in msg.items():
        for item in (value if isinstance(value, list) else [value]):
            if isinstance(item, dict) and "pfcp.ie_type" in item:
                yield to_int(str(item["pfcp.ie_type"])), item


def _f_seid(msg: Json) -> tuple[int | None, str | None]:
    for ie_type, ie in _ie_items(msg):
        if ie_type == 57:
            return to_int(first(ie, "pfcp.seid")), first(ie, "pfcp.f_seid.ipv4") or first(ie, "pfcp.f_seid.ipv6")
    return None, None


def _actions(ie: Json) -> str | None:
    names = [a.upper() for a in APPLY_ACTIONS if first(ie, f"pfcp.apply_action.{a}") in ("1", "True", "true")]
    return "|".join(names) if names else None


def _usage(ie: Json) -> dict[str, Any]:
    triggers = sorted({k.rsplit(".", 1)[1].upper() for k, v in _flat(ie) if
                       k.startswith("pfcp.usage_report_trigger") and v in ("1", "True", "true")})
    return compact({
        "urr_id": to_int(first(ie, "pfcp.urr_id")),
        "total_bytes": to_int(first(ie, "pfcp.volume_measurement.tovol")),
        "uplink_bytes": to_int(first(ie, "pfcp.volume_measurement.ulvol")),
        "downlink_bytes": to_int(first(ie, "pfcp.volume_measurement.dlvol")),
        "duration_s": to_int(first(ie, "pfcp.duration_measurement")),
        "triggers": triggers or None,
    })


def _flat(obj: Any):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                yield from _flat(v)
            else:
                yield k, str(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _flat(item)


def extract_messages(packets: list[Json]) -> list[Message]:
    messages: list[Message] = []
    for packet in packets:
        ts = frame_time(packet)
        frame = frame_number(packet)
        src, dst = endpoints(packet)
        for msg in protocol_messages(packet, LAYER):
            mtype = to_int(first(msg, "pfcp.msg_type"))
            if mtype is None:
                continue
            header_seid = to_int(msg.get("pfcp.seid")) if isinstance(msg.get("pfcp.seid"), str) else None
            f_seid, f_seid_ip = _f_seid(msg)
            rules: dict[str, int] = {}
            far_actions: dict[str, str] = {}
            usage: list[dict[str, Any]] = []
            ue_ips: list[str] = []
            for ie_type, ie in _ie_items(msg):
                if ie_type in RULE_IES:
                    rules[RULE_IES[ie_type]] = rules.get(RULE_IES[ie_type], 0) + 1
                    if ie_type in (3, 10):
                        action = _actions(ie)
                        far = first(ie, "pfcp.far_id")
                        if action and far is not None:
                            far_actions[str(to_int(far))] = action
                elif ie_type in USAGE_REPORT_IES:
                    usage.append(_usage(ie))
            for value in [*iter_values(msg, "pfcp.ue_ip_addr_ipv4"), *iter_values(msg, "pfcp.ue_ip_addr_ipv6")]:
                if value not in ue_ips:
                    ue_ips.append(value)
            reports = [name for key, name in REPORT_TYPES if first(msg, f"pfcp.report_type.{key}") in ("1", "True", "true")]
            cause = to_int(first(msg, "pfcp.cause"))
            fields: dict[str, Any] = {
                "message_type": mtype,
                "seq": to_int(first(msg, "pfcp.seqno")),
                "seid": header_seid,
                "f_seid": f_seid,
                "f_seid_ip": f_seid_ip,
                "node_id": first(msg, "pfcp.node_id_ipv4") or first(msg, "pfcp.node_id_ipv6") or first(msg, "pfcp.node_id_fqdn"),
                "cause": cause,
                "offending_ie": to_int(first(msg, "pfcp.offending_ie")),
                "ue_ips": ue_ips,
                "network_instance": first(msg, "pfcp.network_instance"),
                "dnn": first(msg, "pfcp.apn_dnn"),
                "imsi": first(msg, "e212.imsi"),
                "recovery_time": first(msg, "pfcp.recovery_time_stamp"),
                "rules": rules,
                "far_actions": far_actions,
                "reports": reports,
                "usage": usage,
            }
            messages.append(Message(
                frame=frame, time=ts, src=src, dst=dst, is_request=mtype not in RESPONSE_TYPES,
                key=fields["seq"], name=message_name(mtype), fields=fields, interface=frame_interface(packet),
                expects_answer=mtype in REQUEST_TO_RESPONSE,
            ))
    return messages


def _compatible(request: Message, answer: Message) -> int:
    if REQUEST_TO_RESPONSE.get(request.fields["message_type"]) != answer.fields["message_type"]:
        return 0
    if request.peers == answer.peers:
        return 2
    if request.dst == answer.src or request.src == answer.dst:
        return 1
    return 0


def pair(messages: list[Message]) -> list[Transaction]:
    return pair_messages(messages, compatible=_compatible)


def mark_copies(txs: list[Transaction], rows: list[dict[str, Any]]) -> None:
    """The same request (sequence number, message, sender and receiver) seen again within
    50 ms is a copy of one packet (two capture points), not a new request."""
    seen: dict[tuple, Message] = {}
    for tx, row in zip(txs, rows):
        req = tx.request
        if req is None:
            continue
        k = (req.src, req.dst, req.fields["seq"], req.fields["message_type"])
        prev = seen.get(k)
        if prev is not None and abs(req.time - prev.time) <= COPY_WINDOW_S:
            row["copy_of_frame"] = prev.frame
        else:
            seen[k] = req


def transaction_row(tx: Transaction) -> dict[str, Any]:
    req, ans = tx.request, tx.answer
    anchor = req or ans
    assert anchor is not None
    row = base_row(tx)
    row.update({"message": anchor.name, "response": ans.name if (ans and req) else None,
                "seq": anchor.fields.get("seq"), "seid": _hex64(anchor.fields.get("seid"))})
    if req is not None:
        f = req.fields
        row.update({
            "node_id": f.get("node_id"), "cp_f_seid": _hex64(f.get("f_seid")), "ue_ip": f.get("ue_ips") or None,
            "network_instance": f.get("network_instance"), "dnn": f.get("dnn"), "imsi": f.get("imsi"),
            "rules": f.get("rules") or None, "far_actions": f.get("far_actions") or None,
            "report_types": f.get("reports") or None, "usage": f.get("usage") or None,
            "recovery_time": f.get("recovery_time"),
        })
    if ans is not None:
        f = ans.fields
        cause = f.get("cause")
        row.update({
            "cause": cause, "cause_name": cause_name(cause),
            "accepted": (cause in (1, 2, 3)) if cause is not None else None,
            "offending_ie": f.get("offending_ie"),
            "up_f_seid": _hex64(f.get("f_seid")) if f.get("message_type") == 51 else None,
            "response_rules": f.get("rules") or None,
            "response_usage": f.get("usage") or None,
            "response_recovery_time": f.get("recovery_time"),
        })
        if req is not None and ans.peers != req.peers:
            row["response_path"] = f"{ans.src} > {ans.dst}"
    return compact(row)


# ------------------------------------------------------------------ sessions and nodes
def _same_request(a: Message, b: Message) -> bool:
    return (a.fields["seq"] == b.fields["seq"] and a.fields["message_type"] == b.fields["message_type"]
            and abs(a.time - b.time) <= COPY_WINDOW_S)


def sessions(txs: list[Transaction]) -> list[dict[str, Any]]:
    """One record per PFCP session found: who, when, what happened to it."""
    by_seid: dict[int, dict[str, Any]] = {}
    records: list[dict[str, Any]] = []
    last_req: dict[int, Message] = {}

    def new(**kw: Any) -> dict[str, Any]:
        rec = {"cp_seid": None, "up_seid": None, "cp": None, "up": None, "ue_ip": [], "network_instance": None,
               "dnn": None, "imsi": None, "established": None, "establishment": None, "modifications": 0,
               "failed_modifications": 0, "reports": {}, "deleted": None, "deletion": None, "unanswered": 0,
               "copies": 0, "first": None, "last": None, "usage": {"total_bytes": 0, "uplink_bytes": 0, "downlink_bytes": 0},
               "usage_reports": 0, "issues": [], "_rejected": False}
        rec.update(kw)
        records.append(rec)
        return rec

    for tx in sorted(txs, key=lambda t: t.time):
        req, ans = tx.request, tx.answer
        anchor = req or ans
        assert anchor is not None
        mtype = anchor.fields["message_type"]
        if mtype not in SESSION_TYPES:
            continue
        if mtype in (50, 51):
            cp_seid = req.fields.get("f_seid") if req else None
            up_seid = ans.fields.get("f_seid") if ans else None
            rec = (by_seid.get(cp_seid) if cp_seid else None) or (by_seid.get(up_seid) if up_seid else None)
            if rec is not None and req is not None and rec.get("_est_req") is not None and _same_request(rec["_est_req"], req):
                rec["copies"] += 1
            else:
                rec = new(cp_seid=cp_seid, up_seid=up_seid, _est_req=req)
                rec["cp"] = req.src if req else (ans.dst if ans else None)
                rec["up"] = req.dst if req else (ans.src if ans else None)
                rec["established"] = iso(anchor.time)
                if req is not None:
                    rec["ue_ip"] = list(req.fields.get("ue_ips") or [])
                    rec["network_instance"] = req.fields.get("network_instance")
                    rec["dnn"] = req.fields.get("dnn")
                    rec["imsi"] = req.fields.get("imsi")
                cause = ans.fields.get("cause") if ans else None
                rec["establishment"] = ("no response" if ans is None else
                                        f"{cause} {cause_name(cause)}" if cause is not None else "answered")
                if cause is not None and cause not in (1, 2, 3):
                    rec["_rejected"] = True
                    rec["issues"].append(f"establishment rejected: {cause} {cause_name(cause)}")
            rec["up_seid"] = rec["up_seid"] or up_seid
            for s in (cp_seid, up_seid):
                if s:
                    by_seid[s] = rec
        else:
            seid = (req.fields.get("seid") if req else None) or (ans.fields.get("seid") if ans else None)
            rec = by_seid.get(seid) if seid else None
            if rec is None:
                rec = new(**({"up_seid": seid} if req is not None and req.fields["message_type"] in (52, 54) else
                             {"cp_seid": seid}))
                rec["established"] = "before the capture"
                if req is not None:
                    rec["cp"], rec["up"] = (req.src, req.dst) if req.fields["message_type"] in (52, 54) else (req.dst, req.src)
                if seid:
                    by_seid[seid] = rec
            # A session from before the capture: the other side's SEID is in the header of
            # the messages it sends (a response to the CP, or a report from the UP).
            for m in (req, ans):
                if m is None or not m.fields.get("seid"):
                    continue
                from_cp = m.fields["message_type"] in (52, 54, 57)
                side = "up_seid" if from_cp else "cp_seid"
                if rec[side] is None:
                    rec[side] = m.fields["seid"]
                    by_seid.setdefault(m.fields["seid"], rec)
            prev = last_req.get(id(rec))
            if req is not None and prev is not None and _same_request(prev, req):
                rec["copies"] += 1
                continue
            if req is not None:
                last_req[id(rec)] = req
                for ip in req.fields.get("ue_ips") or []:
                    if ip not in rec["ue_ip"]:
                        rec["ue_ip"].append(ip)
            cause = ans.fields.get("cause") if ans else None
            failed = cause is not None and cause not in (1, 2, 3)
            if mtype in (52, 53):
                rec["modifications"] += 1
                if failed:
                    rec["failed_modifications"] += 1
                    rec["issues"].append(f"modification rejected at {iso(anchor.time)}: {cause} {cause_name(cause)}")
                actions = (req.fields.get("far_actions") if req else None) or {}
                for far, action in actions.items():
                    if "BUFF" in action or "DROP" in action:
                        rec["issues"].append(f"FAR {far} set to {action} at {iso(anchor.time)}")
            elif mtype in (54, 55):
                rec["deleted"] = iso(anchor.time)
                rec["deletion"] = ("no response" if ans is None else
                                   f"{cause} {cause_name(cause)}" if cause is not None else "answered")
                if cause == 65:
                    rec["issues"].append("deletion answered 'Session context not found': the UP no longer had the session")
            elif mtype in (56, 57):
                for name in (req.fields.get("reports") if req else None) or ["unknown"]:
                    rec["reports"][name] = rec["reports"].get(name, 0) + 1
                if cause == 65:
                    rec["issues"].append(f"session report answered 'Session context not found' at {iso(anchor.time)}: "
                                         "the CP no longer had the session")
        for m in (req, ans):
            if m is None:
                continue
            for u in m.fields.get("usage") or []:
                rec["usage_reports"] += 1
                for k in ("total_bytes", "uplink_bytes", "downlink_bytes"):
                    rec["usage"][k] += u.get(k) or 0
        if tx.unanswered:
            rec["unanswered"] += 1
        rec["first"] = rec["first"] or iso(anchor.time)
        rec["last"] = iso((ans or req).time)  # type: ignore[union-attr]
    out = []
    for rec in records:
        rec.pop("_est_req", None)
        if rec["unanswered"]:
            rec["issues"].append(f'{rec["unanswered"]} request(s) without a response')
        if rec["reports"].get("ERIR"):
            rec["issues"].append("error indication reported by the UP (the peer GTP-U node does not know the tunnel)")
        state = ("rejected" if rec.pop("_rejected") else "deleted" if rec["deleted"]
                 else "no response" if rec["establishment"] == "no response" else "active")
        rec["state"] = state
        if not rec["usage_reports"]:
            rec.pop("usage")
        rec["cp_seid"], rec["up_seid"] = _hex64(rec["cp_seid"]), _hex64(rec["up_seid"])
        out.append(compact(rec))
    return out


def nodes(txs: list[Transaction]) -> list[dict[str, Any]]:
    """Per peer pair: association setup, heartbeats and Recovery Time Stamp changes."""
    peers: dict[frozenset[str], dict[str, Any]] = {}
    for tx in sorted(txs, key=lambda t: t.time):
        anchor = tx.request or tx.answer
        assert anchor is not None
        mtype = anchor.fields["message_type"]
        if mtype in SESSION_TYPES:
            continue
        rec = peers.setdefault(anchor.peers, {"peers": sorted(anchor.peers), "node_ids": {}, "messages": {},
                                              "heartbeats": 0, "heartbeats_unanswered": 0, "recovery_times": {},
                                              "restarts": [], "association": None})
        rec["messages"][anchor.name] = rec["messages"].get(anchor.name, 0) + 1
        for m in (tx.request, tx.answer):
            if m is None:
                continue
            if m.fields.get("node_id"):
                rec["node_ids"][m.src] = m.fields["node_id"]
            stamp = m.fields.get("recovery_time")
            if stamp:
                seen = rec["recovery_times"].setdefault(m.src, [])
                if seen and seen[-1] != stamp:
                    rec["restarts"].append(f"{m.src} restarted: Recovery Time Stamp {seen[-1]} -> {stamp} "
                                           f"(frame {m.frame}, {iso(m.time)}); its PFCP sessions are lost")
                if not seen or seen[-1] != stamp:
                    seen.append(stamp)
        if mtype in (1, 2):
            rec["heartbeats"] += 1
            if tx.unanswered:
                rec["heartbeats_unanswered"] += 1
        if mtype in (5, 6) and tx.answer is not None:
            cause = tx.answer.fields.get("cause")
            rec["association"] = f"{cause} {cause_name(cause)}" if cause is not None else "answered"
        elif mtype == 5 and tx.answer is None:
            rec["association"] = "no response"
    return [compact(r) for r in peers.values()]


def control_seids(messages: list[Message]) -> set[int]:
    out: set[int] = set()
    for m in messages:
        for key in ("seid", "f_seid"):
            if m.fields.get(key):
                out.add(m.fields[key])
    return out
