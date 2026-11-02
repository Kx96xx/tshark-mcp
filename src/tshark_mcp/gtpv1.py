"""GTPv1-C (TS 29.060, Gn/Gp) PDP context signalling."""

from __future__ import annotations

from typing import Any

from .fields import Json, all_values, compact, endpoints, first, frame_number, frame_time, protocol_messages, to_int
from .pairing import Message, Transaction, base_row, pair_messages

LAYER = "gtp"
JSON_LAYERS = "frame ip ipv6 gtp"
BASE_FILTER = "gtp && gtp.message != 0xff"

MESSAGE_TYPES: dict[int, str] = {
    1: "Echo Request", 2: "Echo Response", 3: "Version Not Supported",
    4: "Node Alive Request", 5: "Node Alive Response", 6: "Redirection Request", 7: "Redirection Response",
    16: "Create PDP Context Request", 17: "Create PDP Context Response",
    18: "Update PDP Context Request", 19: "Update PDP Context Response",
    20: "Delete PDP Context Request", 21: "Delete PDP Context Response",
    22: "Initiate PDP Context Activation Request", 23: "Initiate PDP Context Activation Response",
    26: "Error Indication", 27: "PDU Notification Request", 28: "PDU Notification Response",
    29: "PDU Notification Reject Request", 30: "PDU Notification Reject Response",
    31: "Supported Extension Headers Notification",
    32: "Send Routeing Information for GPRS Request", 33: "Send Routeing Information for GPRS Response",
    34: "Failure Report Request", 35: "Failure Report Response",
    36: "Note MS GPRS Present Request", 37: "Note MS GPRS Present Response",
    48: "Identification Request", 49: "Identification Response",
    50: "SGSN Context Request", 51: "SGSN Context Response", 52: "SGSN Context Acknowledge",
    53: "Forward Relocation Request", 54: "Forward Relocation Response", 55: "Forward Relocation Complete",
    56: "Relocation Cancel Request", 57: "Relocation Cancel Response", 58: "Forward SRNS Context",
    59: "Forward Relocation Complete Acknowledge", 60: "Forward SRNS Context Acknowledge",
    70: "RAN Information Relay", 240: "Data Record Transfer Request", 241: "Data Record Transfer Response",
    254: "End Marker",
}

REQUEST_TO_RESPONSE: dict[int, int] = {
    1: 2, 4: 5, 6: 7, 16: 17, 18: 19, 20: 21, 22: 23, 27: 28, 29: 30, 32: 33, 34: 35, 36: 37, 48: 49, 50: 51,
    53: 54, 55: 59, 56: 57, 58: 60, 240: 241,
}
RESPONSE_TYPES: frozenset[int] = frozenset(REQUEST_TO_RESPONSE.values())
ONE_WAY: frozenset[int] = frozenset({3, 26, 31, 52, 70, 254})

CAUSES: dict[int, str] = {
    0: "Request IMSI", 1: "Request IMEI", 2: "Request IMSI and IMEI", 3: "No identity needed", 4: "MS refuses",
    5: "MS is not GPRS responding", 6: "Reactivation requested", 7: "PDP address inactivity timer expires",
    8: "Network failure", 9: "QoS parameter mismatch",
    128: "Request accepted", 129: "New PDP type due to network preference",
    130: "New PDP type due to single address bearer only",
    192: "Non-existent", 193: "Invalid message format", 194: "IMSI/IMEI not known", 195: "MS is GPRS detached",
    196: "MS is not GPRS responding", 197: "MS refuses", 198: "Version not supported", 199: "No resources available",
    200: "Service not supported", 201: "Mandatory IE incorrect", 202: "Mandatory IE missing",
    203: "Optional IE incorrect", 204: "System failure", 205: "Roaming restriction", 206: "P-TMSI signature mismatch",
    207: "GPRS connection suspended", 208: "Authentication failure", 209: "User authentication failed",
    210: "Context not found", 211: "All dynamic PDP addresses are occupied", 212: "No memory is available",
    213: "Relocation failure", 214: "Unknown mandatory extension header", 215: "Semantic error in the TFT operation",
    216: "Syntactic error in the TFT operation", 217: "Semantic errors in packet filter(s)",
    218: "Syntactic errors in packet filter(s)", 219: "Missing or unknown APN", 220: "Unknown PDP address or PDP type",
    221: "PDP context without TFT already activated", 222: "APN access denied - no subscription",
    223: "APN restriction type incompatible with currently active PDP contexts",
    224: "MS MBMS capabilities insufficient", 225: "Invalid correlation-ID", 226: "MBMS bearer context superseded",
    227: "Bearer control mode violation", 228: "Collision with network initiated request", 229: "APN congestion",
    230: "Bearer handling not supported", 231: "Target access restricted for the subscriber",
    232: "UE is temporarily not reachable due to power saving", 233: "Relocation failure due to NAS message redirection",
}

RAT_TYPES = {1: "UTRAN", 2: "GERAN", 3: "WLAN", 4: "GAN", 5: "HSPA Evolution", 6: "EUTRAN"}


def message_name(msg_type: int) -> str:
    return MESSAGE_TYPES.get(msg_type, f"message-type-{msg_type}")


def identity_filter(imsi: str | None, msisdn: str | None) -> str | None:
    parts = []
    if imsi:
        parts.append(f'({BASE_FILTER} && e212.imsi == "{imsi}")')
    if msisdn:
        parts.append(f'({BASE_FILTER} && e164.msisdn == "{msisdn}")')
    return " || ".join(parts) if parts else None


def selection_filter(imsi: str | None, apn: str | None, teid: int | None) -> str | None:
    parts = []
    if imsi:
        parts.append(f'e212.imsi == "{imsi}"')
    if apn:
        parts.append(f'lower(gtp.apn) == "{apn.lower()}"')
    if teid is not None:
        h = f"0x{teid:08x}"
        parts.append(f"(gtp.teid == {h} || gtp.teid_cp == {h} || gtp.teid_data == {h})")
    return " && ".join(parts) if parts else None


def correlation_filter(seqs: set[int], teids: set[int]) -> str | None:
    parts = []
    if seqs:
        parts.append("gtp.seq_number in {" + ", ".join(str(s) for s in sorted(seqs)) + "}")
    teids = {t for t in teids if t}
    if teids:
        parts.append("gtp.teid in {" + ", ".join(f"0x{t:08x}" for t in sorted(teids)) + "}")
    if not parts:
        return None
    return f"({BASE_FILTER}) && (" + " || ".join(parts) + ")"


def extract_messages(packets: list[Json]) -> list[Message]:
    messages: list[Message] = []
    for packet in packets:
        ts = frame_time(packet)
        frame = frame_number(packet)
        src, dst = endpoints(packet)
        for msg in protocol_messages(packet, LAYER):
            mtype = to_int(first(msg, "gtp.message"))
            if mtype is None or mtype == 0xFF:
                continue
            gsn = all_values(msg, "gtp.gsn_ipv4") or all_values(msg, "gtp.gsn_ipv6")
            rat = to_int(first(msg, "gtp.ext_rat_type"))
            fields: dict[str, Any] = {
                "message_type": mtype,
                "seq": to_int(first(msg, "gtp.seq_number")),
                "teid": to_int(first(msg, "gtp.teid")),
                "imsi": first(msg, "e212.imsi"),
                "msisdn": first(msg, "e164.msisdn"),
                "apn": first(msg, "gtp.apn"),
                "nsapi": to_int(first(msg, "gtp.nsapi")),
                "cause": to_int(first(msg, "gtp.cause")),
                "teid_cp": to_int(first(msg, "gtp.teid_cp")),
                "teid_data": to_int(first(msg, "gtp.teid_data")),
                "gsn_control": gsn[0] if gsn else None,
                "gsn_user": gsn[1] if len(gsn) > 1 else None,
                "end_user_address": first(msg, "gtp.user_ipv4") or first(msg, "gtp.user_ipv6"),
                "rat_type": RAT_TYPES.get(rat, f"rat-{rat}") if rat is not None else None,
                "imeisv": first(msg, "gtp.ext_imeisv"),
            }
            messages.append(Message(
                frame=frame, time=ts, src=src, dst=dst, is_request=mtype not in RESPONSE_TYPES,
                key=fields["seq"], name=message_name(mtype), fields=fields,
                expects_answer=mtype in REQUEST_TO_RESPONSE,
            ))
    return messages


def _compatible(request: Message, answer: Message) -> int:
    """As for GTPv2: 2 for the same two peers, 1 for a response from the request's
    target (or to its sender) on another address, as a proxy or NAT shows it."""
    if REQUEST_TO_RESPONSE.get(request.fields["message_type"]) != answer.fields["message_type"]:
        return 0
    if request.peers == answer.peers:
        return 2
    if request.dst == answer.src or request.src == answer.dst:
        return 1
    return 0


def pair(messages: list[Message]) -> list[Transaction]:
    return pair_messages(messages, compatible=_compatible)


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:08x}"


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
        f = req.fields
        row.update({
            "imsi": f.get("imsi"), "msisdn": f.get("msisdn"), "apn": f.get("apn"), "nsapi": f.get("nsapi"),
            "rat_type": f.get("rat_type"), "imeisv": f.get("imeisv"),
            "request_teid_cp": _hex(f.get("teid_cp")), "request_teid_data": _hex(f.get("teid_data")),
            "request_gsn": f.get("gsn_control"),
        })
    if ans is not None:
        f = ans.fields
        cause = f.get("cause")
        row.update({
            "cause": cause,
            "cause_name": CAUSES.get(cause, f"cause-{cause}") if cause is not None else None,
            "accepted": (128 <= cause < 192) if cause is not None else None,
            "end_user_address": f.get("end_user_address"),
            "response_teid_cp": _hex(f.get("teid_cp")), "response_teid_data": _hex(f.get("teid_data")),
            "response_gsn": f.get("gsn_control"),
        })
        if req is not None and ans.peers != req.peers:
            row["response_path"] = f"{ans.src} > {ans.dst}"
    return compact(row)


def row_matches(row: dict[str, Any], imsi: str | None, apn: str | None, teid: int | None) -> bool:
    if imsi and row.get("imsi") != imsi:
        return False
    if apn and (row.get("apn") or "").lower() != apn.lower():
        return False
    if teid is not None:
        wanted = f"0x{teid:08x}"
        if wanted not in {row.get(k) for k in ("teid", "request_teid_cp", "request_teid_data", "response_teid_cp",
                                               "response_teid_data")}:
            return False
    return True


def control_teids(messages: list[Message]) -> set[int]:
    """TEIDs later messages of the same PDP context carry in their header."""
    out: set[int] = set()
    for m in messages:
        for key in ("teid", "teid_cp"):
            if m.fields.get(key):
                out.add(m.fields[key])
    return out


def sequence_numbers(messages: list[Message]) -> set[int]:
    return {m.fields["seq"] for m in messages if m.fields.get("seq") is not None}
