"""GTPv2-C (TS 29.274) session signalling and GTP-U (TS 29.281) user-plane summaries."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .fields import (
    Json,    compact, dicts_with, endpoints, first, frame_interface, frame_number, frame_time, iso, parse_time,
    protocol_messages, split_fields_line, to_int,
)
from .pairing import Message, Transaction, base_row, pair_messages

LAYER = "gtpv2"
JSON_LAYERS = "frame ip ipv6 gtpv2 e212 e164"

MESSAGE_TYPES: dict[int, str] = {
    1: "Echo Request", 2: "Echo Response", 3: "Version Not Supported Indication",
    32: "Create Session Request", 33: "Create Session Response",
    34: "Modify Bearer Request", 35: "Modify Bearer Response",
    36: "Delete Session Request", 37: "Delete Session Response",
    38: "Change Notification Request", 39: "Change Notification Response",
    40: "Remote UE Report Notification", 41: "Remote UE Report Acknowledge",
    64: "Modify Bearer Command", 65: "Modify Bearer Failure Indication",
    66: "Delete Bearer Command", 67: "Delete Bearer Failure Indication",
    68: "Bearer Resource Command", 69: "Bearer Resource Failure Indication",
    70: "Downlink Data Notification Failure Indication",
    71: "Trace Session Activation", 72: "Trace Session Deactivation", 73: "Stop Paging Indication",
    95: "Create Bearer Request", 96: "Create Bearer Response",
    97: "Update Bearer Request", 98: "Update Bearer Response",
    99: "Delete Bearer Request", 100: "Delete Bearer Response",
    101: "Delete PDN Connection Set Request", 102: "Delete PDN Connection Set Response",
    103: "PGW Downlink Triggering Notification", 104: "PGW Downlink Triggering Acknowledge",
    128: "Identification Request", 129: "Identification Response",
    130: "Context Request", 131: "Context Response", 132: "Context Acknowledge",
    133: "Forward Relocation Request", 134: "Forward Relocation Response",
    135: "Forward Relocation Complete Notification", 136: "Forward Relocation Complete Acknowledge",
    137: "Forward Access Context Notification", 138: "Forward Access Context Acknowledge",
    139: "Relocation Cancel Request", 140: "Relocation Cancel Response",
    141: "Configuration Transfer Tunnel", 149: "Detach Notification", 150: "Detach Acknowledge",
    151: "CS Paging Indication", 152: "RAN Information Relay", 153: "Alert MME Notification",
    154: "Alert MME Acknowledge", 155: "UE Activity Notification", 156: "UE Activity Acknowledge",
    157: "ISR Status Indication", 158: "UE Registration Query Request", 159: "UE Registration Query Response",
    160: "Create Forwarding Tunnel Request", 161: "Create Forwarding Tunnel Response",
    162: "Suspend Notification", 163: "Suspend Acknowledge",
    164: "Resume Notification", 165: "Resume Acknowledge",
    166: "Create Indirect Data Forwarding Tunnel Request", 167: "Create Indirect Data Forwarding Tunnel Response",
    168: "Delete Indirect Data Forwarding Tunnel Request", 169: "Delete Indirect Data Forwarding Tunnel Response",
    170: "Release Access Bearers Request", 171: "Release Access Bearers Response",
    176: "Downlink Data Notification", 177: "Downlink Data Notification Acknowledge",
    179: "PGW Restart Notification", 180: "PGW Restart Notification Acknowledge",
    200: "Update PDN Connection Set Request", 201: "Update PDN Connection Set Response",
    211: "Modify Access Bearers Request", 212: "Modify Access Bearers Response",
}

# Request message type -> response message type. Types absent from this table
# and from its values are one-way (commands, indications, notifications without
# an acknowledge) and are reported without an "unanswered" flag.
REQUEST_TO_RESPONSE: dict[int, int] = {
    1: 2, 32: 33, 34: 35, 36: 37, 38: 39, 40: 41, 95: 96, 97: 98, 99: 100, 101: 102, 103: 104,
    128: 129, 130: 131, 133: 134, 135: 136, 137: 138, 139: 140, 149: 150, 153: 154, 155: 156,
    158: 159, 160: 161, 162: 163, 164: 165, 166: 167, 168: 169, 170: 171, 176: 177, 179: 180,
    200: 201, 211: 212,
    # Commands are answered only on failure; pair them with the failure indication.
    64: 65, 66: 67, 68: 69,
}
RESPONSE_TYPES: frozenset[int] = frozenset(REQUEST_TO_RESPONSE.values())
ONE_WAY_COMMANDS: frozenset[int] = frozenset({64, 66, 68})

CAUSES: dict[int, str] = {
    1: "Reserved", 2: "Local Detach", 3: "Complete Detach", 4: "RAT changed from 3GPP to Non-3GPP",
    5: "ISR deactivation", 6: "Error Indication received from RNC/eNodeB/S4-SGSN/MME", 7: "IMSI Detach Only",
    8: "Reactivation Requested", 9: "PDN reconnection to this APN disallowed",
    10: "Access changed from Non-3GPP to 3GPP", 11: "PDN connection inactivity timer expires",
    12: "PGW not responding", 13: "Network Failure", 14: "QoS parameter mismatch",
    16: "Request accepted", 17: "Request accepted partially", 18: "New PDN type due to network preference",
    19: "New PDN type due to single address bearer only",
    64: "Context Not Found", 65: "Invalid Message Format", 66: "Version not supported by next peer",
    67: "Invalid length", 68: "Service not supported", 69: "Mandatory IE incorrect", 70: "Mandatory IE missing",
    72: "System failure", 73: "No resources available", 74: "Semantic error in the TFT operation",
    75: "Syntactic error in the TFT operation", 76: "Semantic errors in packet filter(s)",
    77: "Syntactic errors in packet filter(s)", 78: "Missing or unknown APN", 80: "GRE key not found",
    81: "Relocation failure", 82: "Denied in RAT", 83: "Preferred PDN type not supported",
    84: "All dynamic addresses are occupied", 85: "UE context without TFT already activated",
    86: "Protocol type not supported", 87: "UE not responding", 88: "UE refuses", 89: "Service denied",
    90: "Unable to page UE", 91: "No memory available", 92: "User authentication failed",
    93: "APN access denied - no subscription", 94: "Request rejected (reason not specified)",
    95: "P-TMSI Signature mismatch", 96: "IMSI/IMEI not known", 97: "Semantic error in the TAD operation",
    98: "Syntactic error in the TAD operation", 100: "Remote peer not responding",
    101: "Collision with network initiated request", 102: "Unable to page UE due to Suspension",
    103: "Conditional IE missing", 104: "APN Restriction type Incompatible with currently active PDN connection",
    105: "Invalid overall length of the triggered response message and a piggybacked initial message",
    106: "Data forwarding not supported", 107: "Invalid reply from remote peer", 108: "Fallback to GTPv1",
    109: "Invalid peer", 110: "Temporarily rejected due to handover/TAU/RAU procedure in progress",
    111: "Modifications not limited to S1-U bearers", 112: "Request rejected for a PMIPv6 reason",
    113: "APN Congestion", 114: "Bearer handling not supported", 115: "UE already re-attached",
    116: "Multiple PDN connections for a given APN not allowed",
    117: "Target access restricted for the subscriber", 119: "MME/SGSN refuses due to VPLMN Policy",
    120: "GTP-C Entity Congestion", 121: "Late Overlapping Request", 122: "Timed out Request",
    123: "UE is temporarily not reachable due to power saving",
    124: "Relocation failure due to NAS message redirection",
    125: "UE not authorised by OCS or external AAA Server",
    126: "Multiple accesses to a PDN connection not allowed", 127: "Request rejected due to UE capability",
    128: "S1-U Path Failure", 129: "5GC not allowed", 130: "PGW mismatch with network slice subscribed by the UE",
    131: "Rejection due to paging restriction",
}

FTEID_INTERFACES: dict[int, str] = {
    0: "S1-U eNodeB GTP-U", 1: "S1-U SGW GTP-U", 2: "S12 RNC GTP-U", 3: "S12 SGW GTP-U",
    4: "S5/S8 SGW GTP-U", 5: "S5/S8 PGW GTP-U", 6: "S5/S8 SGW GTP-C", 7: "S5/S8 PGW GTP-C",
    8: "S5/S8 SGW PMIPv6", 9: "S5/S8 PGW PMIPv6", 10: "S11 MME GTP-C", 11: "S11/S4 SGW GTP-C",
    12: "S10/N26 MME GTP-C", 13: "S3 MME GTP-C", 14: "S3 SGSN GTP-C", 15: "S4 SGSN GTP-U",
    16: "S4 SGW GTP-U", 17: "S4 SGSN GTP-C", 18: "S16 SGSN GTP-C",
    19: "eNodeB/gNodeB GTP-U DL data forwarding", 20: "eNodeB GTP-U UL data forwarding",
    21: "RNC GTP-U data forwarding", 22: "SGSN GTP-U data forwarding", 23: "SGW/UPF GTP-U DL data forwarding",
    24: "Sm MBMS GW GTP-C", 25: "Sn MBMS GW GTP-C", 26: "Sm MME GTP-C", 27: "Sn SGSN GTP-C",
    28: "SGW GTP-U UL data forwarding", 29: "Sn SGSN GTP-U", 30: "S2b ePDG GTP-C", 31: "S2b-U ePDG GTP-U",
    32: "S2b PGW GTP-C", 33: "S2b-U PGW GTP-U", 34: "S2a TWAN GTP-U", 35: "S2a TWAN GTP-C",
    36: "S2a PGW GTP-C", 37: "S2a PGW GTP-U", 38: "S11 MME GTP-U", 39: "S11 SGW GTP-U",
    40: "N26 AMF GTP-C", 41: "N19mb UPF GTP-U",
}


def message_name(msg_type: int) -> str:
    return MESSAGE_TYPES.get(msg_type, f"message-type-{msg_type}")


def identity_filter(imsi: str | None, msisdn: str | None) -> str | None:
    parts = []
    if imsi:
        parts.append(f'(gtpv2 && e212.imsi == "{imsi}")')
    if msisdn:
        parts.append(f'(gtpv2 && e164.msisdn == "{msisdn}")')
    return " || ".join(parts) if parts else None


_OPERATOR_ID = re.compile(r"\.mnc[0-9]{3}\.mcc[0-9]{3}\.gprs$")


def apn_matches(seen: str | None, wanted: str) -> bool:
    """``wanted`` equals the APN seen, or is its network identifier when the APN seen
    carries the operator identifier (``.mncNNN.mccNNN.gprs``)."""
    if not seen:
        return False
    seen, wanted = seen.lower(), wanted.lower()
    if seen == wanted:
        return True
    return not _OPERATOR_ID.search(wanted) and _OPERATOR_ID.sub("", seen) == wanted


def selection_filter(imsi: str | None, apn: str | None, teid: int | None) -> str | None:
    """First-pass filter for ``gtp_sessions``: messages that name the subscriber, APN
    or tunnel. Arguments must already be linted. Responses repeat none of these, so
    the caller widens to the matching sequence numbers with :func:`correlation_filter`
    and keeps only the transactions :func:`row_matches` accepts."""
    parts = []
    if imsi:
        parts.append(f'e212.imsi == "{imsi}"')
    if apn:
        # APNs are case-insensitive (TS 23.003); lower() has been a display filter function since Wireshark 1.x.
        # A roaming SGW sends the network identifier with the operator identifier appended
        # (internet.mnc001.mcc001.gprs), so the bare network identifier matches that too.
        ni = apn.lower()
        if _OPERATOR_ID.search(ni):
            parts.append(f'lower(gtpv2.apn) == "{ni}"')
        else:
            pattern = "^" + ni.replace(".", "[.]") + "([.]mnc[0-9]{3}[.]mcc[0-9]{3}[.]gprs)?$"
            parts.append(f'lower(gtpv2.apn) matches "{pattern}"')
    if teid is not None:
        parts.append(f"(gtpv2.teid == 0x{teid:08x} || gtpv2.f_teid_gre_key == 0x{teid:08x})")
    return " && ".join(parts) if parts else None


def row_matches(row: dict[str, Any], imsi: str | None, apn: str | None, teid: int | None) -> bool:
    """Whether a transaction row satisfies every structured filter that was given."""
    if imsi and row.get("imsi") != imsi:
        return False
    if apn and not apn_matches(row.get("apn"), apn):
        return False
    if teid is not None:
        wanted = f"0x{teid:08x}"
        carried = {row.get("teid")}
        for ft in list(row.get("request_fteids") or []) + list(row.get("response_fteids") or []):
            carried.add(ft.get("teid"))
        if wanted not in carried:
            return False
    return True


def correlation_filter(seqs: set[int], teids: set[int]) -> str | None:
    parts = []
    if seqs:
        parts.append("gtpv2.seq in {" + ", ".join(str(s) for s in sorted(seqs)) + "}")
    teids = {t for t in teids if t}
    if teids:
        parts.append("gtpv2.teid in {" + ", ".join(f"0x{t:08x}" for t in sorted(teids)) + "}")
    return " || ".join(parts) if parts else None


def _fteids(msg: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for ie in dicts_with(msg, "gtpv2.f_teid_interface_type"):
        iface = to_int(ie.get("gtpv2.f_teid_interface_type"))
        out.append(compact({
            "interface": FTEID_INTERFACES.get(iface if iface is not None else -1, f"interface-{iface}"),
            "teid": _hex(to_int(ie.get("gtpv2.f_teid_gre_key"))),
            "ipv4": ie.get("gtpv2.f_teid_ipv4"),
            "ipv6": ie.get("gtpv2.f_teid_ipv6"),
        }))
    return out


def extract_messages(packets: list[Json]) -> list[Message]:
    messages: list[Message] = []
    for packet in packets:
        ts = frame_time(packet)
        frame = frame_number(packet)
        iface = frame_interface(packet)
        src, dst = endpoints(packet)
        for msg in protocol_messages(packet, LAYER):
            mtype = to_int(first(msg, "gtpv2.message_type"))
            if mtype is None:
                continue
            seq = to_int(first(msg, "gtpv2.seq"))
            is_response = mtype in RESPONSE_TYPES
            fteids = _fteids(msg)
            cause = to_int(first(msg, "gtpv2.cause"))
            fields: dict[str, Any] = {
                "message_type": mtype,
                "seq": seq,
                "teid": to_int(first(msg, "gtpv2.teid")),
                "imsi": first(msg, "e212.imsi"),
                "msisdn": first(msg, "e164.msisdn"),
                "apn": first(msg, "gtpv2.apn"),
                "cause": cause,
                "paa_ipv4": _nonzero(first(msg, "gtpv2.pdn_addr_and_prefix.ipv4")),
                "paa_ipv6": first(msg, "gtpv2.pdn_addr_and_prefix.ipv6"),
                "rat_type": to_int(first(msg, "gtpv2.rat_type")),
                "ebi": to_int(first(msg, "gtpv2.ebi")),
                "fteids": fteids,
            }
            messages.append(Message(
                frame=frame, time=ts, src=src, dst=dst, is_request=not is_response,
                key=seq, name=message_name(mtype), fields=fields, interface=iface,
                expects_answer=mtype in REQUEST_TO_RESPONSE and mtype not in ONE_WAY_COMMANDS,
            ))
    return messages


def _compatible(request: Message, answer: Message) -> int:
    """Rank a response for a request with the same sequence number.

    2: the expected response type between the same two peers.
    1: the expected response type sent by the host that received the request
       (or towards the host that sent it) but seen on another address, which is
       what a capture on a proxy or NAT boundary shows.
    0: not a match.
    """
    if REQUEST_TO_RESPONSE.get(request.fields["message_type"]) != answer.fields["message_type"]:
        return 0
    if request.peers == answer.peers:
        return 2
    if request.dst == answer.src or request.src == answer.dst:
        return 1
    return 0


def pair(messages: list[Message]) -> list[Transaction]:
    return pair_messages(messages, compatible=_compatible)


def transaction_row(tx: Transaction) -> dict[str, Any]:
    req, ans = tx.request, tx.answer
    anchor = req or ans
    assert anchor is not None
    row = base_row(tx)
    row.update({
        "message": anchor.name,
        "response": ans.name if (ans and req) else None,
        "seq": anchor.fields.get("seq"),
        "teid": _hex(anchor.fields.get("teid")),
    })
    if req is not None:
        row.update({
            "imsi": req.fields.get("imsi"),
            "msisdn": req.fields.get("msisdn"),
            "apn": req.fields.get("apn"),
            "rat_type": req.fields.get("rat_type"),
            "ebi": req.fields.get("ebi"),
            "request_fteids": req.fields.get("fteids"),
        })
        if req.fields.get("message_type") in ONE_WAY_COMMANDS and ans is None:
            row["note"] = "command; a response is only sent on failure"
    if ans is not None:
        cause = ans.fields.get("cause")
        row.update({
            "cause": cause,
            "cause_name": CAUSES.get(cause, f"cause-{cause}") if cause is not None else None,
            "accepted": (cause is not None and cause < 64) if cause is not None else None,
            "paa": ans.fields.get("paa_ipv4") or ans.fields.get("paa_ipv6"),
            "response_fteids": ans.fields.get("fteids"),
        })
        if req is not None and ans.peers != req.peers:
            row["response_path"] = f"{ans.src} > {ans.dst}"
    return compact(row)


def control_teids(messages: list[Message]) -> set[int]:
    """TEIDs that later messages of the same session will carry in their header."""
    teids: set[int] = set()
    for m in messages:
        header = m.fields.get("teid")
        if header:
            teids.add(header)
        for ft in m.fields.get("fteids", []):
            if "GTP-C" in ft.get("interface", "") and ft.get("teid"):
                teids.add(int(ft["teid"], 16))
    return teids


def sequence_numbers(messages: list[Message]) -> set[int]:
    return {m.fields["seq"] for m in messages if m.fields.get("seq") is not None}


def announced_teids(msg: Message) -> list[tuple[int, str | None]]:
    """Control-plane F-TEIDs a message announces (TEID and address): the TEID its
    sender expects in the header of later messages of the session."""
    out = []
    for ft in msg.fields.get("fteids", []):
        if "GTP-C" in ft.get("interface", "") and ft.get("teid"):
            teid = int(ft["teid"], 16)
            if teid:
                out.append((teid, ft.get("ipv4") or ft.get("ipv6")))
    return out


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:08x}"


def _nonzero(addr: str | None) -> str | None:
    return None if addr in (None, "0.0.0.0", "::") else addr


# ----------------------------------------------------------------------- GTP-U
USER_PLANE_FIELDS = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst", "gtp.teid", "gtp.length", "gtp.message",
                     "frame.number"]


def user_plane_filter(teid: int | None) -> str:
    base = "gtp.message == 0xff"
    if teid is not None:
        return f"{base} && gtp.teid == 0x{teid:08x}"
    return base


def summarise_user_plane(stdout: str) -> list[dict[str, Any]]:
    """Aggregate ``-T fields`` output (one G-PDU per line) per TEID."""
    buckets: dict[str, dict[str, Any]] = {}
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(USER_PLANE_FIELDS):
            continue
        ts = parse_time(cols[0])
        frame_len = to_int(cols[1], 0) or 0
        srcs, dsts = cols[2].split(","), cols[3].split(",")
        teid = cols[4].split(",")[0]
        payload = to_int(cols[5].split(",")[0], 0) or 0
        if not teid:
            continue
        b = buckets.get(teid)
        if b is None:
            b = buckets[teid] = {
                "teid": teid, "outer_src": srcs[0], "outer_dst": dsts[0], "packets": 0, "frame_bytes": 0,
                "payload_bytes": 0, "first": ts, "last": ts, "inner_src": defaultdict(int), "inner_dst": defaultdict(int),
                "first_frame": to_int(cols[7].split(",")[0]),
            }
        b["last_frame"] = to_int(cols[7].split(",")[0])
        b["packets"] += 1
        b["frame_bytes"] += frame_len
        b["payload_bytes"] += payload
        if ts is not None:
            b["first"] = ts if b["first"] is None else min(b["first"], ts)
            b["last"] = ts if b["last"] is None else max(b["last"], ts)
        if len(srcs) > 1:
            b["inner_src"][srcs[1]] += 1
        if len(dsts) > 1:
            b["inner_dst"][dsts[1]] += 1
    rows = []
    for b in buckets.values():
        duration = (b["last"] - b["first"]) if (b["first"] is not None and b["last"] is not None) else None
        rows.append(compact({
            "teid": b["teid"],
            "outer_src": b["outer_src"],
            "outer_dst": b["outer_dst"],
            "packets": b["packets"],
            "frame_bytes": b["frame_bytes"],
            "payload_bytes": b["payload_bytes"],
            "first": iso(b["first"]),
            "last": iso(b["last"]),
            "first_frame": b["first_frame"],
            "last_frame": b["last_frame"],
            "duration_s": round(duration, 6) if duration is not None else None,
            "inner_src": _top(b["inner_src"]),
            "inner_dst": _top(b["inner_dst"]),
        }))
    rows.sort(key=lambda r: (-r["packets"], r["teid"]))
    return rows


def _top(counter: dict[str, int], n: int = 5) -> list[dict[str, Any]]:
    items = sorted(counter.items(), key=lambda kv: -kv[1])[:n]
    return [{"addr": a, "packets": c} for a, c in items]
