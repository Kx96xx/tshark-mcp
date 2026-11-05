"""SIGTRAN stack: M3UA, SCCP, TCAP and MAP (SS7 over IP) plus SCTP association summaries."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from .fields import (
    Json,    all_values, compact, dicts_with, endpoints, first, frame_number, frame_time, iso, parse_time,
    split_fields_line, to_int,
)

JSON_LAYERS = "frame ip ipv6 sctp m3ua sccp tcap gsm_map camel gsm_sms e212 e164"
MESSAGE_FILTER = "sccp || m3ua"

SCCP_TYPES: dict[int, str] = {
    0x01: "CR", 0x02: "CC", 0x03: "CREF", 0x04: "RLSD", 0x05: "RLC", 0x06: "DT1", 0x07: "DT2", 0x08: "AK",
    0x09: "UDT", 0x0A: "UDTS", 0x0B: "ED", 0x0C: "EA", 0x0D: "RSR", 0x0E: "RSC", 0x0F: "ERR", 0x10: "IT",
    0x11: "XUDT", 0x12: "XUDTS", 0x13: "LUDT", 0x14: "LUDTS",
}

M3UA_CLASSES: dict[int, str] = {
    0: "MGMT", 1: "Transfer", 2: "SSNM", 3: "ASPSM", 4: "ASPTM", 9: "RKM",
}
M3UA_TYPES: dict[tuple[int, int], str] = {
    (0, 0): "ERR", (0, 1): "NTFY", (1, 1): "DATA",
    (2, 1): "DUNA", (2, 2): "DAVA", (2, 3): "DAUD", (2, 4): "SCON", (2, 5): "DUPU", (2, 6): "DRST",
    (3, 1): "ASPUP", (3, 2): "ASPDN", (3, 3): "BEAT", (3, 4): "ASPUP_ACK", (3, 5): "ASPDN_ACK", (3, 6): "BEAT_ACK",
    (4, 1): "ASPAC", (4, 2): "ASPIA", (4, 3): "ASPAC_ACK", (4, 4): "ASPIA_ACK",
}

# MAP operation codes (TS 29.002).
MAP_OPERATIONS: dict[int, str] = {
    2: "updateLocation", 3: "cancelLocation", 4: "provideRoamingNumber", 6: "resumeCallHandling",
    7: "insertSubscriberData", 8: "deleteSubscriberData", 10: "registerSS", 11: "eraseSS", 12: "activateSS",
    13: "deactivateSS", 14: "interrogateSS", 17: "registerPassword", 18: "getPassword", 20: "releaseResources",
    22: "sendRoutingInfo", 23: "updateGprsLocation", 24: "sendRoutingInfoForGprs", 25: "failureReport",
    26: "noteMsPresentForGprs", 29: "sendEndSignal", 33: "provideSubscriberInfo", 34: "anyTimeInterrogation",
    37: "reset", 38: "forwardCheckSS-Indication", 43: "checkIMEI", 44: "mt-forwardSM", 45: "sendRoutingInfoForSM",
    46: "mo-forwardSM", 47: "reportSM-DeliveryStatus", 50: "activateTraceMode", 51: "deactivateTraceMode",
    56: "sendAuthenticationInfo", 57: "restoreData", 58: "sendIMSI", 59: "processUnstructuredSS-Request",
    60: "unstructuredSS-Request", 61: "unstructuredSS-Notify", 63: "informServiceCentre", 64: "alertServiceCentre",
    66: "readyForSM", 67: "purgeMS", 68: "prepareHandover", 69: "prepareSubsequentHandover",
    70: "provideSubscriberLocation", 71: "sendGroupCallEndSignal", 73: "sendRoutingInfoForLCS",
    74: "subscriberLocationReport", 83: "noteSubscriberDataModified", 85: "mo-forwardSM-v1",
}

MAP_ERRORS: dict[int, str] = {
    1: "unknownSubscriber", 3: "unknownMSC", 5: "unidentifiedSubscriber", 6: "absentSubscriberSM",
    7: "unknownEquipment", 8: "roamingNotAllowed", 9: "illegalSubscriber", 10: "bearerServiceNotProvisioned",
    11: "teleserviceNotProvisioned", 12: "illegalEquipment", 13: "callBarred", 21: "facilityNotSupported",
    27: "absentSubscriber", 31: "subscriberBusyForMT-SMS", 32: "sm-DeliveryFailure", 33: "messageWaitingListFull",
    34: "systemFailure", 35: "dataMissing", 36: "unexpectedDataValue", 51: "resourceLimitation",
    54: "noRoamingNumberAvailable", 71: "unknownOrUnreachableLCSClient",
}

# CAMEL (CAP) operations and errors, 3GPP TS 29.078 (the values tshark's camel dissector names).
CAMEL_OPERATIONS: dict[int, str] = {
    0: "initialDP", 16: "assistRequestInstructions", 17: "establishTemporaryConnection",
    18: "disconnectForwardConnection", 19: "connectToResource", 20: "connect", 22: "releaseCall",
    23: "requestReportBCSMEvent", 24: "eventReportBCSM", 27: "collectInformation", 31: "continue",
    32: "initiateCallAttempt", 33: "resetTimer", 34: "furnishChargingInformation", 35: "applyCharging",
    36: "applyChargingReport", 41: "callGap", 44: "callInformationReport", 45: "callInformationRequest",
    46: "sendChargingInformation", 47: "playAnnouncement", 48: "promptAndCollectUserInformation",
    49: "specializedResourceReport", 53: "cancel", 55: "activityTest", 60: "initialDPSMS",
    61: "furnishChargingInformationSMS", 62: "connectSMS", 63: "requestReportSMSEvent", 64: "eventReportSMS",
    65: "continueSMS", 66: "releaseSMS", 67: "resetTimerSMS", 70: "activityTestGPRS", 71: "applyChargingGPRS",
    72: "applyChargingReportGPRS", 73: "cancelGPRS", 74: "connectGPRS", 75: "continueGPRS",
    76: "entityReleasedGPRS", 77: "furnishChargingInformationGPRS", 78: "initialDPGPRS", 79: "releaseGPRS",
    80: "eventReportGPRS", 81: "requestReportGPRSEvent", 82: "resetTimerGPRS", 83: "sendChargingInformationGPRS",
    86: "disconnectForwardConnectionWithArgument", 88: "continueWithArgument", 90: "disconnectLeg", 93: "moveLeg",
    95: "splitLeg", 96: "entityReleased", 97: "playTone",
}
CAMEL_ERRORS: dict[int, str] = {
    0: "canceled", 1: "cancelFailed", 3: "eTCFailed", 4: "improperCallerResponse", 6: "missingCustomerRecord",
    7: "missingParameter", 8: "parameterOutOfRange", 10: "requestedInfoError", 11: "systemFailure",
    12: "taskRefused", 13: "unavailableResource", 14: "unexpectedComponentSequence", 15: "unexpectedDataValue",
    16: "unexpectedParameter", 17: "unknownLegID", 50: "unknownPDPID", 51: "unknownCSID",
}
_CAMEL_COMPONENT_KEYS = (
    ("camel.invoke_element", "invoke"), ("camel.returnResult_element", "returnResultLast"),
    ("camel.returnError_element", "returnError"), ("camel.reject_element", "reject"),
)

_COMPONENT_KEYS = (
    ("gsm_old.invoke_element", "invoke"),
    ("gsm_old.returnResultLast_element", "returnResultLast"),
    ("gsm_old.returnResultNotLast_element", "returnResultNotLast"),
    ("gsm_old.returnError_element", "returnError"),
    ("gsm_old.reject_element", "reject"),
    ("tcap.invoke_element", "invoke"),
    ("tcap.returnResultLast_element", "returnResultLast"),
    ("tcap.returnError_element", "returnError"),
    ("tcap.reject_element", "reject"),
)
_TCAP_TYPES = (
    ("tcap.begin_element", "begin"), ("tcap.continue_element", "continue"), ("tcap.end_element", "end"),
    ("tcap.abort_element", "abort"), ("tcap.unidirectional_element", "unidirectional"),
)


def identity_filter(imsi: str | None, msisdn: str | None) -> str | None:
    parts = []
    if imsi:
        parts.append(f'(tcap && e212.imsi == "{imsi}")')
    if msisdn:
        parts.append(f'(tcap && e164.msisdn == "{msisdn}")')
        parts.append(f'(tcap && gsm_sms.tp-da == "{msisdn}")')
        parts.append(f'(tcap && gsm_sms.tp-oa == "{msisdn}")')
    return " || ".join(parts) if parts else None


def correlation_filter(tids: set[str]) -> str | None:
    if not tids:
        return None
    return "tcap.tid in {" + ", ".join(sorted(tids)) + "}"


def _camel_components(camel_layer: Any) -> list[dict[str, Any]]:
    """CAP components: the operation from ``camel.local`` (inside ``camel.result_element`` for a
    result), the error from ``camel.error_code_local``, the invoke id from ``camel.present``."""
    comps: list[dict[str, Any]] = []
    for key, kind in _CAMEL_COMPONENT_KEYS:
        for comp in dicts_with(camel_layer, key):
            body = comp[key]
            opcode = to_int(first(body, "camel.local"))
            err = to_int(first(body, "camel.error_code_local"))
            comps.append(compact({
                "type": kind, "application": "camel",
                "invoke_id": to_int(first(body, "camel.present")),
                "opcode": opcode if kind != "returnError" else None,
                "operation": (CAMEL_OPERATIONS.get(opcode, f"cap-op-{opcode}")
                              if opcode is not None and kind != "returnError" else None),
                "error_code": err,
                "error": CAMEL_ERRORS.get(err, f"cap-err-{err}") if err is not None else None,
                "problem": first(body, "camel.invokeProblem") or first(body, "camel.general")
                if kind == "reject" else None,
            }))
    return comps


def _components(tcap_layer: Any, map_layer: Any, camel_layer: Any = None) -> list[dict[str, Any]]:
    if camel_layer is not None:
        camel = _camel_components(camel_layer)
        if camel:
            return camel
    comps: list[dict[str, Any]] = []
    for source in (map_layer, tcap_layer):
        if source is None:
            continue
        for key, kind in _COMPONENT_KEYS:
            for comp in dicts_with(source, key):
                body = comp[key]
                opcode = to_int(first(body, "gsm_old.localValue") or first(body, "tcap.localValue"))
                err = to_int(first(body, "gsm_old.errorCode") or first(body, "gsm_map.errorCode"))
                entry = compact({
                    "type": kind,
                    "invoke_id": to_int(first(body, "gsm_old.invokeID") or first(body, "tcap.invokeID")),
                    "opcode": opcode,
                    "operation": MAP_OPERATIONS.get(opcode, f"op-{opcode}") if opcode is not None else None,
                    "error_code": err,
                    "error": MAP_ERRORS.get(err, f"err-{err}") if err is not None else None,
                    "problem": first(body, "gsm_old.invokeProblem") or first(body, "gsm_old.returnResultProblem"),
                })
                # In a returnError, gsm_old.errorCode is the index of the ERROR CHOICE
                # (0 = localValue); the error code itself is the localValue below it.
                if kind == "returnError" and opcode is not None:
                    entry["error_code"] = opcode
                    entry["error"] = MAP_ERRORS.get(opcode, f"err-{opcode}")
                    entry.pop("opcode", None)
                    entry.pop("operation", None)
                comps.append(entry)
        if comps:
            break
    return comps


def _layer(packet_layers: dict[str, Any], name: str) -> Any:
    value = packet_layers.get(name)
    if isinstance(value, list):
        return value[0] if value else None
    return value


def extract_rows(packets: list[Json]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for packet in packets:
        lyr = packet.get("_source", {}).get("layers", {})
        ts = frame_time(packet)
        frame = frame_number(packet)
        src, dst = endpoints(packet)
        m3ua = _layer(lyr, "m3ua")
        sccp = _layer(lyr, "sccp")
        tcap = _layer(lyr, "tcap")
        gsm_map = _layer(lyr, "gsm_map")
        camel = lyr.get("camel")  # every CAP layer: tshark adds one per component (requestReportBCSMEvent + continue)
        gsm_sms = _layer(lyr, "gsm_sms")
        if m3ua is None and sccp is None:
            continue
        row: dict[str, Any] = {"frame": frame, "time": iso(ts), "src": src, "dst": dst}
        if m3ua is not None:
            cls, typ = to_int(first(m3ua, "m3ua.message_class")), to_int(first(m3ua, "m3ua.message_type"))
            row["m3ua"] = M3UA_TYPES.get((cls or -1, typ or -1), f"class-{cls}-type-{typ}")
            row["opc"] = to_int(first(m3ua, "m3ua.protocol_data_opc"))
            row["dpc"] = to_int(first(m3ua, "m3ua.protocol_data_dpc"))
        if sccp is not None:
            stype = to_int(first(sccp, "sccp.message_type"))
            row["sccp"] = SCCP_TYPES.get(stype or -1, f"type-{stype}")
            row["called_gt"] = first(sccp, "sccp.called.digits")
            row["called_ssn"] = to_int(first(sccp, "sccp.called.ssn"))
            row["calling_gt"] = first(sccp, "sccp.calling.digits")
            row["calling_ssn"] = to_int(first(sccp, "sccp.calling.ssn"))
            seg_first = first(sccp, "sccp.segmentation.first")
            if seg_first is not None:
                row["segmentation"] = compact({
                    "first_segment": seg_first in ("1", "0x01", "True"),
                    "remaining_segments": to_int(first(sccp, "sccp.segmentation.remaining")),
                    "local_reference": first(sccp, "sccp.segmentation.slr"),
                })
                if tcap is None:
                    row["note"] = "segmented SCCP payload; TCAP not dissected in this segment"
        if tcap is not None:
            for key, kind in _TCAP_TYPES:
                if key in tcap or first(tcap, key) is not None:
                    row["tcap"] = kind
                    break
            row["otid"] = _tid(first(tcap, "tcap.otid"))
            row["dtid"] = _tid(first(tcap, "tcap.dtid"))
            row["components"] = _components(tcap, gsm_map, camel)
            if gsm_map is not None or gsm_sms is not None:
                app_layers = [l for l in (gsm_map, gsm_sms, tcap) if l is not None]
                row["imsi"] = _map_imsi(app_layers)
                row["msisdn"] = _map_msisdn(app_layers)
                if gsm_sms is not None:
                    row["sms"] = compact({
                        "tp_da": first(gsm_sms, "gsm_sms.tp-da"),
                        "tp_oa": first(gsm_sms, "gsm_sms.tp-oa"),
                        "tp_mti": to_int(first(gsm_sms, "gsm_sms.tp-mti")),
                    })
        rows.append(compact(row))
    return _link_transactions(rows)


def decode_tbcd(raw: str | None, address_string: bool = False) -> str | None:
    """Decode a colon-separated TBCD byte string ("00:01:01:21:43:65:87:f9") to digits.
    With ``address_string`` the leading TON/NPI octet of an ISDN-AddressString is skipped.
    Used when the tshark build does not emit the decoded e212/e164 field."""
    if not raw:
        return None
    try:
        data = bytes.fromhex(raw.replace(":", ""))
    except ValueError:
        return None
    if address_string:
        data = data[1:]
    digits = []
    for byte in data:
        for nibble in (byte & 0x0F, byte >> 4):
            if nibble == 0x0F:
                break
            digits.append(str(nibble) if nibble < 10 else "*#abc"[nibble - 10])
    return "".join(digits) or None


def _map_imsi(obj: Any) -> str | None:
    """The IMSI: the decoded ``e212.imsi`` when the dissector emits it, otherwise the raw
    TBCD bytes of any ``*.imsi`` field (older tshark builds leave some MAP IMSIs raw)."""
    found = first(obj, "e212.imsi")
    if found:
        return found
    for key, value in _walk_items(obj):
        if key.lower().endswith(".imsi") and isinstance(value, str) and ":" in value:
            decoded = decode_tbcd(value)
            if decoded:
                return decoded
    return None


def _walk_items(obj: Any):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key, value
            if isinstance(value, (dict, list)):
                yield from _walk_items(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_items(item)


def _map_msisdn(obj: Any) -> str | None:
    """The subscriber MSISDN. ``e164.msisdn`` is emitted under every ISDN-AddressString
    (VLR, HLR and SMSC numbers included), so only subtrees named msisdn count. Older
    dissectors leave the raw address string, which is decoded as TBCD."""
    for key, value in _walk_items(obj):
        if key.lower().endswith("msisdn_tree") and isinstance(value, dict):
            found = first(value, "e164.msisdn")
            if found:
                return found
    for key, value in _walk_items(obj):
        if key.lower().endswith("msisdn") and isinstance(value, str) and ":" in value:
            found = decode_tbcd(value, address_string=True)
            if found:
                return found
    return None



def _tid(value: str | None) -> str | None:
    return None if value is None else value.replace(":", "")


def _link_transactions(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mark Begins answered by a later End/Continue/Abort with matching transaction id."""
    begins: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("tcap") == "begin" and row.get("otid"):
            begins[row["otid"]] = row
            row["unanswered"] = True
    for row in rows:
        if row.get("tcap") in ("end", "continue", "abort") and row.get("dtid") in begins:
            begin = begins[row["dtid"]]
            begin.pop("unanswered", None)
            begin["answered_in_frame"] = row["frame"]
            row["in_response_to_frame"] = begin["frame"]
            _name_results(row, begin)
            if row.get("tcap") == "end":
                t0, t1 = parse_time(begin["time"].replace("Z", "+00:00")) if begin.get("time") else None, None
                t1 = parse_time(row["time"].replace("Z", "+00:00")) if row.get("time") else None
                if t0 is not None and t1 is not None:
                    row["rtt_ms"] = round((t1 - t0) * 1000.0, 3)
    return rows


def _name_results(reply: dict[str, Any], begin: dict[str, Any]) -> None:
    """A returnResult or returnError need not repeat the operation code (a
    mo-forwardSM result usually does not); take it from the invoke with the same
    invoke id in the Begin it answers."""
    invokes = {c.get("invoke_id"): c for c in begin.get("components", []) if c.get("type") == "invoke"}
    for comp in reply.get("components", []):
        if comp.get("type") == "invoke" or comp.get("operation") or comp.get("invoke_id") is None:
            continue
        invoke = invokes.get(comp["invoke_id"])
        if invoke and invoke.get("operation"):
            comp["operation"] = invoke["operation"]
            if invoke.get("opcode") is not None:
                comp.setdefault("opcode", invoke["opcode"])


def transaction_ids(rows: list[dict[str, Any]]) -> set[str]:
    tids = set()
    for row in rows:
        for key in ("otid", "dtid"):
            v = row.get(key)
            if v:
                tids.add(":".join(v[i:i + 2] for i in range(0, len(v), 2)))
    return tids


# ----------------------------------------------------------------------- SCTP
SCTP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "sctp.srcport", "sctp.dstport", "sctp.verification_tag",
    "sctp.chunk_type", "sctp.init_initiate_tag", "sctp.initack_initiate_tag", "sctp.retransmission",
    "sctp.data_tsn", "sctp.abort_t_bit",
]
SCTP_FILTER = "sctp"

CHUNK_TYPES: dict[int, str] = {
    0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK", 4: "HEARTBEAT", 5: "HEARTBEAT_ACK", 6: "ABORT", 7: "SHUTDOWN",
    8: "SHUTDOWN_ACK", 9: "ERROR", 10: "COOKIE_ECHO", 11: "COOKIE_ACK", 12: "ECNE", 13: "CWR",
    14: "SHUTDOWN_COMPLETE", 15: "AUTH", 64: "I_DATA", 128: "ASCONF_ACK", 130: "RE_CONFIG", 132: "PAD",
    192: "FORWARD_TSN", 193: "ASCONF", 194: "I_FORWARD_TSN",
}


def summarise_sctp(stdout: str) -> list[dict[str, Any]]:
    """Group SCTP packets into associations keyed by the unordered endpoint pair."""
    assocs: "OrderedDict[tuple, dict[str, Any]]" = OrderedDict()
    for line in stdout.splitlines():
        cols = split_fields_line(line)
        if len(cols) < len(SCTP_FIELDS):
            continue
        rec = dict(zip(SCTP_FIELDS, cols))
        a = (rec["ip.src"], rec["sctp.srcport"])
        b = (rec["ip.dst"], rec["sctp.dstport"])
        key = tuple(sorted((a, b)))
        ts = parse_time(rec["frame.time_epoch"])
        s = assocs.get(key)
        if s is None:
            s = assocs[key] = {
                "endpoint_a": f"{key[0][0]}:{key[0][1]}", "endpoint_b": f"{key[1][0]}:{key[1][1]}",
                "first": ts, "last": ts, "packets": 0, "chunks": {}, "init_tags": {}, "heartbeats": 0,
                "heartbeat_acks": 0, "retransmissions": 0, "data_chunks": 0, "abort": False, "shutdown": False,
                "init_frame": None, "init_ack_frame": None, "abort_frame": None,
                "first_frame": to_int(rec["frame.number"]),
                # Handshake bookkeeping: an INIT waiting for its answer, per sender; INITs answered
                # by ABORT; who sent INITs (both ends: an INIT collision, RFC 9260 5.2.1).
                "pending_init": {}, "inits_aborted": 0, "aborted_frames": [], "init_senders": set(),
                "init_collision_frame": None,
            }
        s["packets"] += 1
        s["last_frame"] = to_int(rec["frame.number"])
        if ts is not None:
            s["last"] = ts if s["last"] is None else max(s["last"], ts)
        if rec["sctp.retransmission"]:
            s["retransmissions"] += len([v for v in rec["sctp.retransmission"].split(",") if v])
        for ct in filter(None, rec["sctp.chunk_type"].split(",")):
            n = to_int(ct)
            name = CHUNK_TYPES.get(n if n is not None else -1, f"chunk-{ct}")
            s["chunks"][name] = s["chunks"].get(name, 0) + 1
            frame_no = to_int(rec["frame.number"])
            sender = (rec["ip.src"], rec["sctp.srcport"])
            if name == "INIT":
                if sender not in s["init_senders"] and s["init_senders"] and s["init_collision_frame"] is None:
                    s["init_collision_frame"] = frame_no
                s["init_senders"].add(sender)
                s["pending_init"][sender] = frame_no
            elif name == "ABORT" and s["pending_init"] and s["init_ack_frame"] is None:
                peer_inits = [f for snd, f in s["pending_init"].items() if snd != sender]
                if peer_inits:
                    s["inits_aborted"] += 1
                    if len(s["aborted_frames"]) < 5:
                        s["aborted_frames"].append(max(peer_inits))
                    s["pending_init"] = {snd: f for snd, f in s["pending_init"].items() if snd == sender}
            elif name == "INIT_ACK":
                s["pending_init"] = {}
            if name == "INIT":
                s["init_frame"] = s["init_frame"] or to_int(rec["frame.number"])
                if rec["sctp.init_initiate_tag"]:
                    s["init_tags"][rec["ip.src"]] = rec["sctp.init_initiate_tag"].split(",")[0]
            elif name == "INIT_ACK":
                s["init_ack_frame"] = s["init_ack_frame"] or to_int(rec["frame.number"])
                if rec["sctp.initack_initiate_tag"]:
                    s["init_tags"][rec["ip.src"]] = rec["sctp.initack_initiate_tag"].split(",")[0]
            elif name == "HEARTBEAT":
                s["heartbeats"] += 1
            elif name == "HEARTBEAT_ACK":
                s["heartbeat_acks"] += 1
            elif name == "DATA":
                s["data_chunks"] += 1
            elif name == "ABORT":
                s["abort"] = True
                s["abort_frame"] = s["abort_frame"] or to_int(rec["frame.number"])
            elif name in ("SHUTDOWN", "SHUTDOWN_ACK", "SHUTDOWN_COMPLETE"):
                s["shutdown"] = True
    rows = []
    for s in assocs.values():
        handshake = "complete" if (s["init_frame"] and s["init_ack_frame"]) else (
            "INIT without INIT_ACK" if s["init_frame"] else "not in capture")
        issues = []
        if s["inits_aborted"]:
            n = s["inits_aborted"]
            issues.append(f"{n} INIT{'s' if n != 1 else ''} answered with ABORT (frames "
                          f"{', '.join(str(f) for f in s['aborted_frames'][:3])}): the peer refused the association "
                          "(nothing listening on that port, an endpoint or stream limit, or a mismatched configuration)")
        if s["init_collision_frame"] is not None:
            issues.append(f"INIT collision: both ends sent INIT (frame {s['init_collision_frame']}), so the "
                          "association was set up by the RFC 9260 5.2.4 collision procedure"
                          + (" and completed" if handshake == "complete" else ""))
        if s["heartbeats"] - s["heartbeat_acks"] >= 3:
            issues.append(f"{s['heartbeats'] - s['heartbeat_acks']} HEARTBEATs not acknowledged: the path or the "
                          "peer is not answering")
        rows.append(compact({
            "endpoint_a": s["endpoint_a"],
            "endpoint_b": s["endpoint_b"],
            "first": iso(s["first"]),
            "last": iso(s["last"]),
            "packets": s["packets"],
            "first_frame": s["first_frame"],
            "last_frame": s["last_frame"],
            "handshake": handshake,
            "init_frame": s["init_frame"],
            "init_ack_frame": s["init_ack_frame"],
            "initiate_tags": s["init_tags"] or None,
            "data_chunks": s["data_chunks"],
            "heartbeats_sent": s["heartbeats"],
            "heartbeats_acked": s["heartbeat_acks"],
            "heartbeats_unacked": max(0, s["heartbeats"] - s["heartbeat_acks"]),
            "retransmissions": s["retransmissions"],
            "abort_seen": s["abort"],
            "abort_frame": s["abort_frame"],
            "shutdown_seen": s["shutdown"],
            "chunk_counts": s["chunks"],
            "inits_aborted": s["inits_aborted"] or None,
            "init_collision": True if s["init_collision_frame"] is not None else None,
            "issues": issues or None,
        }))
    return rows


__all__ = [
    "CHUNK_TYPES", "JSON_LAYERS", "MAP_ERRORS", "MAP_OPERATIONS", "MESSAGE_FILTER", "SCCP_TYPES", "SCTP_FIELDS",
    "SCTP_FILTER", "all_values", "correlation_filter", "decode_tbcd", "extract_rows", "identity_filter", "summarise_sctp",
    "transaction_ids",
]
