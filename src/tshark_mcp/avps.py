"""Diameter AVP trees and the key S6a/S6d, Gx and base-protocol AVPs, from tshark JSON.

tshark puts every AVP of a message in ``diameter.avp_tree`` (one dict per AVP,
holding ``diameter.avp.code``, flags and length plus one ``diameter.<Name>``
value), and a grouped AVP's members in ``diameter.<Name>_tree.diameter.avp_tree``.
:func:`avp_tree` turns that into a nested ``{name: value}`` mapping (a list when
a name repeats), names the enumerated values and flag bits that matter for
mobility and policy troubleshooting, and stops at a leaf cap.
:func:`key_view` then picks the AVPs an engineer reads first for each command.
"""

from __future__ import annotations

from typing import Any

from .fields import Json, to_int

# Enumerated AVPs (TS 29.272, 29.212, 29.229, RFC 6733, RFC 4006): value -> name.
ENUMS: dict[str, dict[int, str]] = {
    "Cancellation-Type": {0: "MME_UPDATE_PROCEDURE", 1: "SGSN_UPDATE_PROCEDURE", 2: "SUBSCRIPTION_WITHDRAWAL",
                          3: "UPDATE_PROCEDURE_IWF", 4: "INITIAL_ATTACH_PROCEDURE"},
    "Subscriber-Status": {0: "SERVICE_GRANTED", 1: "OPERATOR_DETERMINED_BARRING"},
    "Network-Access-Mode": {0: "PACKET_AND_CIRCUIT", 1: "RESERVED", 2: "ONLY_PACKET"},
    "PDN-Type": {0: "IPv4", 1: "IPv6", 2: "IPv4v6", 3: "IPv4_OR_IPv6", 4: "Non-IP", 5: "Ethernet"},
    "RAT-Type": {0: "WLAN", 1: "VIRTUAL", 2: "TRUSTED-N3GA", 3: "WIRELINE", 1000: "UTRAN", 1001: "GERAN",
                 1002: "GAN", 1003: "HSPA_EVOLUTION", 1004: "EUTRAN", 1005: "EUTRAN-NB-IoT", 1006: "NR",
                 1007: "LTE-M", 1008: "NR-U", 1009: "NR-SATELLITE"},
    "All-APN-Configurations-Included-Indicator": {0: "All_APN_CONFIGURATIONS_INCLUDED",
                                                  1: "MODIFIED_ADDED_APN_CONFIGURATIONS_INCLUDED"},
    "VPLMN-Dynamic-Address-Allowed": {0: "NOTALLOWED", 1: "ALLOWED"},
    "PDN-GW-Allocation-Type": {0: "STATIC", 1: "DYNAMIC"},
    "Pre-emption-Capability": {0: "PRE-EMPTION_CAPABILITY_ENABLED", 1: "PRE-EMPTION_CAPABILITY_DISABLED"},
    "Pre-emption-Vulnerability": {0: "PRE-EMPTION_VULNERABILITY_ENABLED", 1: "PRE-EMPTION_VULNERABILITY_DISABLED"},
    "Auth-Session-State": {0: "STATE_MAINTAINED", 1: "NO_STATE_MAINTAINED"},
    "Disconnect-Cause": {0: "REBOOTING", 1: "BUSY", 2: "DO_NOT_WANT_TO_TALK_TO_YOU"},
    "Termination-Cause": {1: "DIAMETER_LOGOUT", 2: "DIAMETER_SERVICE_NOT_PROVIDED", 3: "DIAMETER_BAD_ANSWER",
                          4: "DIAMETER_ADMINISTRATIVE", 5: "DIAMETER_LINK_BROKEN", 6: "DIAMETER_AUTH_EXPIRED",
                          7: "DIAMETER_USER_MOVED", 8: "DIAMETER_SESSION_TIMEOUT"},
    "CC-Request-Type": {1: "INITIAL_REQUEST", 2: "UPDATE_REQUEST", 3: "TERMINATION_REQUEST", 4: "EVENT_REQUEST"},
    "IP-CAN-Type": {0: "3GPP-GPRS", 1: "DOCSIS", 2: "xDSL", 3: "WiMAX", 4: "3GPP2", 5: "3GPP-EPS", 6: "Non-3GPP-EPS",
                    7: "FBA", 8: "3GPP-5GS", 9: "Non-3GPP-5GS"},
    "Bearer-Control-Mode": {0: "UE_ONLY", 1: "RESERVED", 2: "UE_NW"},
    "Network-Request-Support": {0: "NETWORK_REQUEST_NOT_SUPPORTED", 1: "NETWORK_REQUEST_SUPPORTED"},
    "Rule-Failure-Code": {1: "UNKNOWN_RULE_NAME", 2: "RATING_GROUP_ERROR", 3: "SERVICE_IDENTIFIER_ERROR",
                          4: "GW/PCEF_MALFUNCTION", 5: "RESOURCES_LIMITATION", 6: "MAX_NR_BEARERS_REACHED",
                          7: "UNKNOWN_BEARER_ID", 8: "MISSING_BEARER_ID", 9: "MISSING_FLOW_INFORMATION",
                          10: "RESOURCE_ALLOCATION_FAILURE", 11: "UNSUCCESSFUL_QOS_VALIDATION",
                          12: "INCORRECT_FLOW_INFORMATION", 13: "PS_TO_CS_HANDOVER",
                          14: "TDF_APPLICATION_IDENTIFIER_ERROR", 15: "NO_BEARER_BOUND",
                          16: "FILTER_RESTRICTIONS", 17: "AN_GW_FAILED", 18: "MISSING_REDIRECT_SERVER_ADDRESS",
                          19: "CM_END_USER_SERVICE_DENIED", 20: "CM_CREDIT_CONTROL_NOT_APPLICABLE",
                          21: "CM_AUTHORIZATION_REJECTED", 22: "CM_USER_UNKNOWN", 23: "CM_RATING_FAILED"},
    "Event-Trigger": {0: "SGSN_CHANGE", 1: "QOS_CHANGE", 2: "RAT_CHANGE", 3: "TFT_CHANGE", 4: "PLMN_CHANGE",
                      5: "LOSS_OF_BEARER", 6: "RECOVERY_OF_BEARER", 7: "IP-CAN_CHANGE",
                      11: "QOS_CHANGE_EXCEEDING_AUTHORIZATION", 12: "RAI_CHANGE", 13: "USER_LOCATION_CHANGE",
                      14: "NO_EVENT_TRIGGERS", 17: "UE_IP_ADDRESS_ALLOCATE", 18: "UE_IP_ADDRESS_RELEASE",
                      19: "DEFAULT_EPS_BEARER_QOS_CHANGE", 20: "AN_GW_CHANGE", 21: "SUCCESSFUL_RESOURCE_ALLOCATION",
                      22: "RESOURCE_MODIFICATION_REQUEST", 26: "TAI_CHANGE", 27: "ECGI_CHANGE",
                      33: "USAGE_REPORT", 36: "APPLICATION_START", 37: "APPLICATION_STOP"},
    "UE-SRVCC-Capability": {0: "UE-SRVCC-NOT-SUPPORTED", 1: "UE-SRVCC-SUPPORTED"},
    "IMS-Voice-Over-PS-Sessions-Supported": {0: "NOT_SUPPORTED", 1: "SUPPORTED"},
    "Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions": {0: "NOT_SUPPORTED", 1: "SUPPORTED"},
    "Server-Assignment-Type": {0: "NO_ASSIGNMENT", 1: "REGISTRATION", 2: "RE_REGISTRATION", 3: "UNREGISTERED_USER",
                               4: "TIMEOUT_DEREGISTRATION", 5: "USER_DEREGISTRATION",
                               6: "TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME",
                               7: "USER_DEREGISTRATION_STORE_SERVER_NAME", 8: "ADMINISTRATIVE_DEREGISTRATION",
                               9: "AUTHENTICATION_FAILURE", 10: "AUTHENTICATION_TIMEOUT",
                               11: "DEREGISTRATION_TOO_MUCH_DATA", 12: "AAA_USER_DATA_REQUEST",
                               13: "PGW_UPDATE", 14: "RESTORATION"},
    "Reason-Code": {0: "PERMANENT_TERMINATION", 1: "NEW_SERVER_ASSIGNED", 2: "SERVER_CHANGE",
                    3: "REMOVE_S-CSCF"},
}

# Bit-string AVPs: bit number -> name (TS 29.272 section 7.3).
FLAGS: dict[str, dict[int, str]] = {
    "ULR-Flags": {0: "Single-Registration-Indication", 1: "S6a/S6d-Indicator", 2: "Skip-Subscriber-Data",
                  3: "GPRS-Subscription-Data-Indicator", 4: "Node-Type-Indicator", 5: "Initial-Attach-Indicator",
                  6: "PS-LCS-Not-Supported-By-UE", 7: "SMS-Only-Indication", 8: "Dual-Registration-5G-Indicator",
                  9: "Inter-PLMN-inter-MME-handover", 10: "Intra-PLMN-inter-MME-handover"},
    "ULA-Flags": {0: "Separation-Indication", 1: "MME-Registered-for-SMS"},
    "CLR-Flags": {0: "S6a/S6d-Indicator", 1: "Reattach-Required"},
    "PUR-Flags": {0: "UE-Purged-in-MME", 1: "UE-Purged-in-SGSN"},
    "PUA-Flags": {0: "Freeze-M-TMSI", 1: "Freeze-P-TMSI"},
    "IDR-Flags": {0: "UE-Reachability-Request", 1: "T-ADS-Data-Request", 2: "EPS-User-State-Request",
                  3: "EPS-Location-Information-Request", 4: "Current-Location-Request",
                  5: "Local-Time-Zone-Request", 6: "Remove-SMS-Registration", 7: "RAT-Type-Requested",
                  8: "P-CSCF-Restoration-Request"},
    "IDA-Flags": {0: "Network-Node-area-restricted"},
    "DSR-Flags": {0: "Regional-Subscription-Withdrawal", 1: "Complete-APN-Configuration-Profile-Withdrawal",
                  2: "Subscribed-Charging-Characteristics-Withdrawal", 3: "PDN-subscription-contexts-Withdrawal",
                  4: "STN-SR", 5: "Complete-PDP-context-list-Withdrawal", 6: "PDP-contexts-Withdrawal",
                  7: "Roaming-Restricted-due-to-unsupported-feature", 8: "Trace-Data-Withdrawal",
                  9: "CSG-Deleted", 10: "APN-OI-Replacement", 11: "GMLC-List-Withdrawal", 12: "LCS-Withdrawal",
                  13: "SMS-Withdrawal", 14: "Subscribed-periodic-RAU-TAU-Timer-Withdrawal",
                  15: "Subscribed-VSRVCC-Withdrawal", 16: "A-MSISDN-Withdrawal", 17: "ProSe-Withdrawal",
                  18: "Reset-IDs", 19: "DL-Buffering-Suggested-Packet-Count-Withdrawal",
                  20: "Subscribed-IMSI-Group-Id-Withdrawal", 21: "Delete-monitoring-events",
                  22: "User-Plane-Integrity-Protection-Withdrawal", 23: "MSISDN-Withdrawal",
                  24: "UE-Usage-Type-Withdrawal", 25: "V2X-Withdrawal", 26: "External-Identifier-Withdrawal",
                  27: "Aerial-UE-Subscription-Withdrawal", 28: "Paging-Time-Window-Subscription-Withdrawal",
                  29: "Active-Time-Withdrawal", 30: "eDRX-Cycle-Length-Withdrawal",
                  31: "Service-Gap-Time-Withdrawal"},
    "NOR-Flags": {0: "Single-Registration-Indication", 1: "SGSN-area-restricted", 2: "Ready-for-SM-from-SGSN",
                  3: "UE-Reachable-from-MME", 4: "Reserved", 5: "UE-Reachable-from-SGSN",
                  6: "Ready-for-SM-from-MME", 7: "Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions",
                  8: "S6a/S6d-Indicator", 9: "Removal-of-MME-Registration-for-SMS"},
    "AIR-Flags": {0: "Send-UE-Usage-Type"},
    "Access-Restriction-Data": {0: "UTRAN-Not-Allowed", 1: "GERAN-Not-Allowed", 2: "GAN-Not-Allowed",
                                3: "I-HSPA-Evolution-Not-Allowed", 4: "WB-E-UTRAN-Not-Allowed",
                                5: "HO-To-Non-3GPP-Access-Not-Allowed", 6: "NB-IoT-Not-Allowed",
                                7: "Enhanced-Coverage-Not-Allowed", 8: "NR-as-Secondary-RAT-in-E-UTRAN-Not-Allowed",
                                9: "Unlicensed-Spectrum-as-Secondary-RAT-Not-Allowed", 10: "NR-in-5GS-Not-Allowed",
                                11: "LTE-M-Not-Allowed", 12: "WB-E-UTRAN-Except-LTE-M-Not-Allowed",
                                13: "NR-U-in-5GS-Not-Allowed"},
    "Operator-Determined-Barring": {0: "All-Packet-Oriented-Services-Barred",
                                    1: "Roamer-Access-HPLMN-AP-Barred", 2: "Roamer-Access-to-VPLMN-AP-Barred",
                                    3: "Barring-of-all-outgoing-calls",
                                    4: "Barring-of-all-outgoing-international-calls",
                                    5: "Barring-of-all-outgoing-international-calls-except-to-HPLMN",
                                    6: "Barring-of-all-outgoing-inter-zonal-calls",
                                    7: "Barring-of-all-outgoing-inter-zonal-calls-except-to-HPLMN",
                                    8: "Barring-of-all-outgoing-international-and-inter-zonal-calls-except-to-HPLMN"},
}

# Digit strings that are identities, not numbers: kept as text so leading zeros survive.
STRING_AVPS = frozenset({
    "User-Name", "IMEI", "IMEISV", "Software-Version", "MSISDN", "A-MSISDN", "C-MSISDN", "Service-Selection",
    "Called-Station-Id", "Calling-Station-Id", "Subscription-Id-Data", "Public-Identity", "Session-Id",
    "Charging-Rule-Name", "3GPP-SGSN-MCC-MNC", "3GPP-IMSI-MCC-MNC", "3GPP-GGSN-MCC-MNC", "Visited-PLMN-Id",
    "Origin-Host", "Origin-Realm", "Destination-Host", "Destination-Realm", "Route-Record", "External-Identifier",
})

# OctetString AVPs that carry text; tshark prints them as hex.
TEXT_OCTETS = frozenset({"Charging-Rule-Name", "Charging-Rule-Base-Name", "TDF-Application-Identifier",
                         "AF-Charging-Identifier", "Media-Component-Status", "Presence-Reporting-Area-Identifier"})

HARD_MAX_AVPS = 2000
MAX_VALUE_CHARS = 200
_HEADER = ("diameter.version", "diameter.length", "diameter.flags", "diameter.cmd.code", "diameter.applicationId",
           "diameter.hopbyhopid", "diameter.endtoendid", "diameter.answer_to", "diameter.answer_in",
           "diameter.resp_time", "diameter.vendorId")


class _Budget:
    def __init__(self, leaves: int) -> None:
        self.left = leaves
        self.dropped = 0


def avp_tree(message: Json, max_avps: int = 200) -> tuple[dict[str, Any], int]:
    """Nested AVPs of one Diameter message and the number of AVPs left out by the cap."""
    budget = _Budget(max(1, min(int(max_avps), HARD_MAX_AVPS)))
    tree = _group(message.get("diameter.avp_tree"), budget, depth=0)
    return tree, budget.dropped


def _as_list(value: Any) -> list[Json]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _group(avps: Any, budget: _Budget, depth: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for avp in _as_list(avps):
        name, value = _one(avp, budget, depth)
        if name is None:
            continue
        if name in out:
            prev = out[name]
            out[name] = (prev if isinstance(prev, list) else [prev]) + [value]
        else:
            out[name] = value
    return out


def _name_key(avp: Json) -> str | None:
    for key in avp:
        if not key.startswith("diameter.") or key.endswith("_tree") or key in _HEADER:
            continue
        rest = key[len("diameter."):]
        if rest.startswith(("avp", "flags", "3gpp.")) or "." in rest:
            continue
        return key
    return None


def _one(avp: Json, budget: _Budget, depth: int) -> tuple[str | None, Any]:
    key = _name_key(avp)
    code = avp.get("diameter.avp.code")
    if key is None:
        if code is None:
            return None, None
        key = f"diameter.avp-{code}"
    name = key[len("diameter."):]
    subtree = avp.get(key + "_tree")
    if isinstance(subtree, dict) and "diameter.avp_tree" in subtree and depth < 8:
        members = _group(subtree["diameter.avp_tree"], budget, depth + 1)
        if not members and budget.left <= 0:
            return None, None  # every member fell to the cap; counted in dropped
        return name, members
    if budget.left <= 0:
        budget.dropped += 1
        return None, None
    budget.left -= 1
    return name, _leaf(name, avp.get(key), avp, key)


def _leaf(name: str, raw: Any, avp: Json, key: str) -> Any:
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if raw is None:
        return None
    text = str(raw)
    number = to_int(text) if text.lstrip("-").isdigit() and name not in STRING_AVPS else None
    if number is not None and name in ENUMS:
        label = ENUMS[name].get(number)
        return f"{label} ({number})" if label else number
    if number is not None and name in FLAGS:
        bits = [FLAGS[name].get(b, f"bit{b}") for b in range(32) if number >> b & 1]
        return f"{number} [{', '.join(bits)}]" if bits else f"{number} [none]"
    if name in TEXT_OCTETS:
        text = _hex_text(text)
    decoded = _decoded(name, avp, key)
    if decoded is not None:
        return decoded
    if number is not None:
        return number
    if len(text) > MAX_VALUE_CHARS:
        return text[:MAX_VALUE_CHARS] + "..."
    return text


def _hex_text(text: str) -> str:
    """``72:75:6c:65`` -> ``rule`` when every byte is printable ASCII, else unchanged."""
    try:
        data = bytes.fromhex(text.replace(":", ""))
    except ValueError:
        return text
    return data.decode("ascii") if data and all(32 <= b < 127 for b in data) else text


def _decoded(name: str, avp: Json, key: str) -> str | None:
    """Human values tshark adds beside some raw AVPs (TBCD numbers, PLMN ids, addresses)."""
    flat: dict[str, str] = {}
    _flatten(avp, flat)
    if name in ("MSISDN", "A-MSISDN", "C-MSISDN") and flat.get("e164.msisdn"):
        return flat["e164.msisdn"]
    if name in ("Visited-PLMN-Id", "Serving-PLMN") and flat.get("e212.mcc"):
        return f'{flat["e212.mcc"]}-{flat.get("e212.mnc", "")}'
    for suffix in (".IPv4", ".IPv6", ".addr_ipv4", ".addr_ipv6"):
        if flat.get(key + suffix):
            return flat[key + suffix]
    return None


def _flatten(obj: Any, out: dict[str, str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _flatten(v, out)
            elif k not in out:
                out[k] = str(v)
    elif isinstance(obj, list):
        for item in obj:
            _flatten(item, out)


# ----------------------------------------------------------------- key view
def find(tree: Any, name: str) -> list[Any]:
    """Every value of AVP ``name`` at any depth, in order."""
    found: list[Any] = []
    if isinstance(tree, dict):
        for k, v in tree.items():
            if k == name:
                found.extend(v if isinstance(v, list) else [v])
            else:
                found.extend(find(v, name))
    elif isinstance(tree, list):
        for item in tree:
            found.extend(find(item, name))
    return found


def _one_of(tree: Any, name: str) -> Any:
    values = find(tree, name)
    if not values:
        return None
    return values[0] if len(values) == 1 else values


# AVPs worth a line of their own, wherever they sit in the message.
KEY_AVPS = (
    "User-Name", "Visited-PLMN-Id", "RAT-Type", "ULR-Flags", "ULA-Flags", "CLR-Flags", "Cancellation-Type",
    "PUR-Flags", "PUA-Flags", "IDR-Flags", "IDA-Flags", "DSR-Flags", "NOR-Flags", "AIR-Flags",
    "Number-Of-Requested-Vectors", "Immediate-Response-Preferred", "Re-Synchronization-Info", "Context-Identifier",
    "Error-Message", "Error-Reporting-Host", "Failed-AVP", "Termination-Cause", "Disconnect-Cause",
    "CC-Request-Type", "CC-Request-Number", "Called-Station-Id", "Framed-IP-Address", "Framed-IPv6-Prefix",
    "IP-CAN-Type", "Bearer-Identifier", "Event-Trigger", "Rule-Failure-Code", "Charging-Rule-Name",
    "3GPP-SGSN-MCC-MNC", "Server-Assignment-Type", "Public-Identity", "Server-Name", "Reason-Code",
    "IMEI", "Software-Version", "UE-SRVCC-Capability", "Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions",
)


def key_view(tree: dict[str, Any]) -> dict[str, Any]:
    """The AVPs read first: result codes, procedure flags and types, identities, Gx
    request and rule outcomes, and a digest of any Subscription-Data."""
    out: dict[str, Any] = {}
    rc = tree.get("Result-Code")
    if rc is not None:
        out["Result-Code"] = rc
    for er in find(tree, "Experimental-Result"):
        if isinstance(er, dict):
            out.setdefault("Experimental-Result", []).append(
                {k: er[k] for k in ("Vendor-Id", "Experimental-Result-Code") if k in er})
    for name in KEY_AVPS:
        if name in ("Context-Identifier",):
            continue  # reported inside the subscription digest
        value = _one_of(tree, name) if name not in ("Charging-Rule-Name", "Event-Trigger") else (find(tree, name) or None)
        if value is not None and not (isinstance(value, list) and not value):
            out[name] = value
    auth = find(tree, "E-UTRAN-Vector") + find(tree, "UTRAN-Vector") + find(tree, "GERAN-Vector")
    if auth:
        out["authentication_vectors"] = len(auth)
    rule_reports = find(tree, "Charging-Rule-Report")
    if rule_reports:
        out["Charging-Rule-Report"] = rule_reports
    qos = find(tree, "QoS-Information") + find(tree, "Default-EPS-Bearer-QoS")
    if qos:
        out["QoS"] = qos[:4]
    for sd in find(tree, "Subscription-Data"):
        if isinstance(sd, dict):
            out.setdefault("subscription", []).append(subscription_digest(sd))
    if "subscription" in out and len(out["subscription"]) == 1:
        out["subscription"] = out["subscription"][0]
    return out


def subscription_digest(sd: dict[str, Any]) -> dict[str, Any]:
    """MSISDN, status, barring, access mode, AMBR and one line per APN configuration."""
    out: dict[str, Any] = {}
    for name in ("MSISDN", "A-MSISDN", "Subscriber-Status", "Operator-Determined-Barring", "Network-Access-Mode",
                 "Access-Restriction-Data", "Subscribed-Periodic-RAU-TAU-Timer", "Charging-Characteristics",
                 "UE-Usage-Type", "APN-OI-Replacement", "Roaming-Restricted-Due-To-Unsupported-Feature"):
        if name in sd:
            out[name] = sd[name]
    ambr = sd.get("AMBR")
    if isinstance(ambr, dict):
        out["AMBR"] = _ambr(ambr)
    profile = sd.get("APN-Configuration-Profile")
    if isinstance(profile, dict):
        out["default_context"] = profile.get("Context-Identifier")
        out["All-APN-Configurations-Included-Indicator"] = profile.get("All-APN-Configurations-Included-Indicator")
        configs = profile.get("APN-Configuration")
        configs = configs if isinstance(configs, list) else ([configs] if configs else [])
        out["apns"] = [_apn(c) for c in configs if isinstance(c, dict)]
    gprs = sd.get("GPRS-Subscription-Data")
    if isinstance(gprs, dict):
        pdp = gprs.get("PDP-Context")
        pdp = pdp if isinstance(pdp, list) else ([pdp] if pdp else [])
        out["gprs_pdp_contexts"] = [{k: c.get(k) for k in ("Context-Identifier", "Service-Selection", "PDP-Type")
                                     if c.get(k) is not None} for c in pdp if isinstance(c, dict)]
    return {k: v for k, v in out.items() if v is not None}


def _ambr(ambr: dict[str, Any]) -> dict[str, Any]:
    return {"ul": ambr.get("Max-Requested-Bandwidth-UL"), "dl": ambr.get("Max-Requested-Bandwidth-DL")}


def _apn(cfg: dict[str, Any]) -> dict[str, Any]:
    qos = cfg.get("EPS-Subscribed-QoS-Profile") if isinstance(cfg.get("EPS-Subscribed-QoS-Profile"), dict) else {}
    arp = qos.get("Allocation-Retention-Priority") if isinstance(qos.get("Allocation-Retention-Priority"), dict) else {}
    row: dict[str, Any] = {
        "context": cfg.get("Context-Identifier"),
        "apn": cfg.get("Service-Selection"),
        "pdn_type": cfg.get("PDN-Type"),
        "qci": qos.get("QoS-Class-Identifier"),
        "arp_priority": arp.get("Priority-Level"),
        "vplmn_dynamic_address": cfg.get("VPLMN-Dynamic-Address-Allowed"),
        "pdn_gw_allocation": cfg.get("PDN-GW-Allocation-Type"),
        "served_party_ip": cfg.get("Served-Party-IP-Address"),
    }
    if isinstance(cfg.get("AMBR"), dict):
        row["ambr"] = _ambr(cfg["AMBR"])
    mip6 = cfg.get("MIP6-Agent-Info")
    if isinstance(mip6, dict):
        row["pgw"] = {k: v for k, v in (("address", _one_of(mip6, "MIP-Home-Agent-Address")),
                                        ("host", _one_of(mip6, "Destination-Host")),
                                        ("realm", _one_of(mip6, "Destination-Realm"))) if v is not None}
    return {k: v for k, v in row.items() if v is not None}
