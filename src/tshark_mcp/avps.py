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

import re
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
    # Gy/Ro (RFC 4006, TS 32.299)
    "Final-Unit-Action": {0: "TERMINATE", 1: "REDIRECT", 2: "RESTRICT_ACCESS"},
    "Redirect-Address-Type": {0: "IPv4 Address", 1: "IPv6 Address", 2: "URL", 3: "SIP URI"},
    "Reporting-Reason": {0: "THRESHOLD", 1: "QHT", 2: "FINAL", 3: "QUOTA_EXHAUSTED", 4: "VALIDITY_TIME",
                         5: "OTHER_QUOTA_TYPE", 6: "RATING_CONDITION_CHANGE", 7: "FORCED_REAUTHORISATION",
                         8: "POOL_EXHAUSTED", 9: "UNUSED_QUOTA_TIMER"},
    "Subscription-Id-Type": {0: "END_USER_E164", 1: "END_USER_IMSI", 2: "END_USER_SIP_URI", 3: "END_USER_NAI",
                             4: "END_USER_PRIVATE"},
    # Rx (TS 29.214)
    "Rx-Request-Type": {0: "INITIAL_REQUEST", 1: "UPDATE_REQUEST", 2: "PCSCF_RESTORATION"},
    "Media-Type": {0: "AUDIO", 1: "VIDEO", 2: "DATA", 3: "APPLICATION", 4: "CONTROL", 5: "TEXT", 6: "MESSAGE",
                   4294967295: "OTHER"},
    "Flow-Status": {0: "ENABLED-UPLINK", 1: "ENABLED-DOWNLINK", 2: "ENABLED", 3: "DISABLED", 4: "REMOVED"},
    "Specific-Action": {1: "CHARGING_CORRELATION_EXCHANGE", 2: "INDICATION_OF_LOSS_OF_BEARER",
                        3: "INDICATION_OF_RECOVERY_OF_BEARER", 4: "INDICATION_OF_RELEASE_OF_BEARER",
                        6: "IP-CAN_CHANGE", 7: "INDICATION_OF_OUT_OF_CREDIT",
                        8: "INDICATION_OF_SUCCESSFUL_RESOURCES_ALLOCATION",
                        9: "INDICATION_OF_FAILED_RESOURCES_ALLOCATION", 10: "INDICATION_OF_LIMITED_PCC_DEPLOYMENT",
                        11: "USAGE_REPORT", 12: "ACCESS_NETWORK_INFO_REPORT",
                        13: "INDICATION_OF_RECOVERY_FROM_LIMITED_PCC_DEPLOYMENT",
                        14: "INDICATION_OF_ACCESS_NETWORK_INFO_REPORTING_FAILURE",
                        15: "INDICATION_OF_TRANSFER_POLICY_EXPIRED", 16: "PLMN_CHANGE", 17: "EPS_FALLBACK",
                        18: "INDICATION_OF_REALLOCATION_OF_CREDIT", 19: "SUCCESSFUL_QOS_UPDATE",
                        20: "FAILED_QOS_UPDATE"},
    "Abort-Cause": {0: "BEARER_RELEASED", 1: "INSUFFICIENT_SERVER_RESOURCES", 2: "INSUFFICIENT_BEARER_RESOURCES",
                    3: "PS_TO_CS_HANDOVER", 4: "SPONSORED_DATA_CONNECTIVITY_DISALLOWED"},
    # Cx (TS 29.229) and Sh (TS 29.329)
    "User-Authorization-Type": {0: "REGISTRATION", 1: "DE_REGISTRATION", 2: "REGISTRATION_AND_CAPABILITIES"},
    "Data-Reference": {0: "RepositoryData", 10: "IMSPublicIdentity", 11: "IMSUserState", 12: "S-CSCFName",
                       13: "InitialFilterCriteria", 14: "LocationInformation", 15: "UserState",
                       16: "ChargingInformation", 17: "MSISDN", 18: "PSIActivation", 19: "DSAI",
                       21: "ServiceLevelTraceInfo", 22: "IPAddressSecureBindingInformation",
                       23: "ServicePriorityLevel", 24: "SMSRegistrationInfo", 25: "UEReachabilityForIP",
                       26: "TADSinformation", 27: "STN-SR", 28: "UE-SRVCC-Capability", 29: "ExtendedPriority",
                       30: "CSRN", 31: "ReferenceLocationInformation", 32: "IMSI", 33: "IMSPrivateUserIdentity",
                       34: "IMEISV", 35: "UE-5G-SRVCC-Capability"},
    "Requested-Domain": {0: "CS-Domain", 1: "PS-Domain"},
    "Current-Location": {0: "DoNotNeedInitiateActiveLocationRetrieval", 1: "InitiateActiveLocationRetrieval"},
    "Identity-Set": {0: "ALL_IDENTITIES", 1: "REGISTERED_IDENTITIES", 2: "IMPLICIT_IDENTITIES",
                     3: "ALIAS_IDENTITIES"},
    # S13 (TS 29.272 7.3.51)
    "Equipment-Status": {0: "WHITELISTED", 1: "BLACKLISTED", 2: "GREYLISTED"},
}

# Authentication material: never returned, in any view. The AVP is kept with this marker so
# its presence still shows (TS 29.272 7.3.18 vectors, TS 29.229 6.3.13 SIP-Auth-Data-Item).
SECRET_AVPS = frozenset({"RAND", "XRES", "AUTN", "KASME", "SRES", "Kc", "CK", "IK", "SIP-Authenticate",
                         "SIP-Authorization", "Confidentiality-Key", "Integrity-Key",
                         # the same AVPs when the dictionary has no name for them
                         "avp-609", "avp-610", "avp-625", "avp-626", "avp-1447", "avp-1448", "avp-1449",
                         "avp-1450", "avp-1453", "avp-1454"})
WITHHELD = "withheld (authentication material)"

# AVPs some tshark dictionaries name with a "3GPP-" prefix or leave unnamed; the digests
# read them by their spec name.
AVP_CODES = {"avp-872": "Reporting-Reason", "avp-437": "Requested-Service-Unit", "avp-702": "Sh-User-Data", "avp-612": "SIP-Auth-Data-Item",
             "avp-608": "SIP-Authentication-Scheme", "avp-607": "SIP-Number-Auth-Items", "avp-1445": "Equipment-Status"}


def bare(name: str) -> str:
    """An AVP name as the spec spells it: without a dictionary's "3GPP-" prefix."""
    if name.startswith("3GPP-") and not name.startswith(("3GPP-SGSN", "3GPP-GGSN", "3GPP-IMSI", "3GPP-Charging",
                                                          "3GPP-PDP", "3GPP-RAT", "3GPP-User-Location",
                                                          "3GPP-MS-TimeZone", "3GPP-Selection", "3GPP-NSAPI",
                                                          "3GPP-CG", "3GPP-GPRS", "3GPP-Session-Stop",
                                                          "3GPP-Negotiated", "3GPP-Allocate", "3GPP-Packet",
                                                          "3GPP-IPv6", "3GPP-Camel", "3GPP-IMEISV", "3GPP-QoS")):
        return name[5:]
    return AVP_CODES.get(name, name)


def spec_names(tree: Any) -> Any:
    """A copy of an AVP tree with :func:`bare` names, for the application digests."""
    if isinstance(tree, dict):
        return {bare(k): spec_names(v) for k, v in tree.items()}
    if isinstance(tree, list):
        return [spec_names(v) for v in tree]
    return tree

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
                         "AF-Charging-Identifier", "AF-Application-Identifier", "Service-Indication",
                         "Visited-Network-Identifier", "Media-Component-Status", "Presence-Reporting-Area-Identifier"})

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
    if bare(name) in SECRET_AVPS or name in SECRET_AVPS:
        return name, WITHHELD
    if bare(name) == "Sh-User-Data":
        return name, sh_user_data(avp.get(key))
    return name, _leaf(name, avp.get(key), avp, key)


def _leaf(name: str, raw: Any, avp: Json, key: str) -> Any:
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if raw is None:
        return None
    text = str(raw)
    spec = bare(name)
    number = to_int(text) if text.lstrip("-").isdigit() and spec not in STRING_AVPS else None
    if number is not None and spec in ENUMS:
        label = ENUMS[spec].get(number)
        return f"{label} ({number})" if label else number
    if number is not None and spec in FLAGS:
        bits = [FLAGS[spec].get(b, f"bit{b}") for b in range(32) if number >> b & 1]
        return f"{number} [{', '.join(bits)}]" if bits else f"{number} [none]"
    if spec in TEXT_OCTETS:
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


def key_view(tree: dict[str, Any], application_id: int | None = None) -> dict[str, Any]:
    """The AVPs read first: result codes, procedure flags and types, identities, Gx
    request and rule outcomes, a digest of any Subscription-Data and, for Gy/Ro, Rx, Cx,
    Sh and S13, the application digest of :data:`DIGESTS` under its own key."""
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
    if application_id in DIGESTS:
        key, build = DIGESTS[application_id]
        digest = build(spec_names(tree))
        if digest:
            out[key] = digest
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


# ----------------------------------------------------------------- application digests
def _code(value: Any) -> int | None:
    """The number of an AVP value, also from a named enum ("FOO (3)")."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        m = re.search(r"\((\d+)\)$", value) or re.fullmatch(r"(\d+)", value.strip())
        if m:
            return int(m.group(1))
    return None


def _named_result(code: Any, experimental: bool) -> dict[str, Any] | None:
    from .diameter import EXPERIMENTAL_RESULT_CODES, RESULT_CODES
    n = _code(code)
    if n is None:
        return None
    name = (EXPERIMENTAL_RESULT_CODES if experimental else RESULT_CODES).get(n)
    out: dict[str, Any] = {"code": n, "avp": "Experimental-Result-Code" if experimental else "Result-Code"}
    if name:
        out["name"] = name
    return out


def results(tree: dict[str, Any]) -> list[dict[str, Any]]:
    """The message's own Result-Code and Experimental-Result-Code, named (not the ones
    inside a Multiple-Services-Credit-Control, which the Gy digest reports per MSCC)."""
    out = []
    if tree.get("Result-Code") is not None:
        r = _named_result(tree["Result-Code"], False)
        if r:
            out.append(r)
    ers = tree.get("Experimental-Result")
    for er in ers if isinstance(ers, list) else [ers]:
        if isinstance(er, dict) and er.get("Experimental-Result-Code") is not None:
            r = _named_result(er["Experimental-Result-Code"], True)
            if r:
                out.append(r)
    return out


def _listed(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value is None else [value])


def _first(tree: Any, name: str) -> Any:
    values = find(tree, name)
    return values[0] if values else None


def _units(unit: Any) -> dict[str, Any] | None:
    if not isinstance(unit, dict):
        return None
    out = {k: unit[name] for name, k in (("CC-Total-Octets", "total_octets"), ("CC-Input-Octets", "input_octets"),
                                          ("CC-Output-Octets", "output_octets"), ("CC-Time", "time_s"),
                                          ("CC-Service-Specific-Units", "service_units")) if name in unit}
    reasons = _listed(unit.get("Reporting-Reason"))
    if reasons:
        out["reporting_reason"] = reasons if len(reasons) > 1 else reasons[0]
    return out


def _mscc(m: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for name, key in (("Rating-Group", "rating_group"), ("Service-Identifier", "service_identifier"),
                      ("Validity-Time", "validity_time_s"), ("Quota-Holding-Time", "quota_holding_time_s"),
                      ("Volume-Quota-Threshold", "volume_quota_threshold"), ("Time-Quota-Threshold", "time_quota_threshold_s")):
        if name in m:
            row[key] = m[name]
    if "Requested-Service-Unit" in m:
        row["requested"] = _units(m["Requested-Service-Unit"]) or {}
    if "Granted-Service-Unit" in m:
        row["granted"] = _units(m["Granted-Service-Unit"]) or {}
    used = [u for u in (_units(x) for x in _listed(m.get("Used-Service-Unit"))) if u is not None]
    if used:
        row["used"] = used if len(used) > 1 else used[0]
    reasons = _listed(m.get("Reporting-Reason"))
    if reasons:
        row["reporting_reason"] = reasons if len(reasons) > 1 else reasons[0]
    fui = m.get("Final-Unit-Indication")
    if isinstance(fui, dict):
        final = {"action": fui.get("Final-Unit-Action")}
        server = fui.get("Redirect-Server")
        if isinstance(server, dict):
            final["redirect_address_type"] = server.get("Redirect-Address-Type")
            final["redirect_server_address"] = server.get("Redirect-Server-Address")
        filters = _listed(fui.get("Filter-Id")) + _listed(fui.get("Restriction-Filter-Rule"))
        if filters:
            final["restriction_filters"] = len(filters)
        row["final_unit"] = {k: v for k, v in final.items() if v is not None}
    if m.get("Result-Code") is not None:
        row["result"] = _named_result(m["Result-Code"], False)
    return row


def gy_digest(tree: dict[str, Any]) -> dict[str, Any]:
    """Gy/Ro (RFC 4006, TS 32.299): request type and number, Service-Context-Id, the
    subscriber's Subscription-Id, and per Multiple-Services-Credit-Control the rating
    group, service id, requested, granted and used units, validity and quota holding
    time, thresholds, reporting reason, Final-Unit-Indication and the MSCC Result-Code."""
    out: dict[str, Any] = {}
    for name, key in (("CC-Request-Type", "request_type"), ("CC-Request-Number", "request_number"),
                      ("Service-Context-Id", "service_context_id"), ("Termination-Cause", "termination_cause"),
                      ("Multiple-Services-Indicator", "multiple_services_indicator")):
        if tree.get(name) is not None:
            out[key] = tree[name]
    subs = [s for s in _listed(tree.get("Subscription-Id")) if isinstance(s, dict)]
    if subs:
        out["subscription_ids"] = [{"type": s.get("Subscription-Id-Type"), "data": s.get("Subscription-Id-Data")}
                                   for s in subs]
    msccs = [m for m in _listed(tree.get("Multiple-Services-Credit-Control")) if isinstance(m, dict)]
    if msccs:
        out["mscc"] = [_mscc(m) for m in msccs]
    if out or results(tree):
        out["results"] = results(tree) or None
    return {k: v for k, v in out.items() if v is not None}


def _codec_first_line(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.replace("\\n", "\n").replace("\r", "")
    return text.split("\n", 1)[0].strip()[:40] or None


def rx_digest(tree: dict[str, Any]) -> dict[str, Any]:
    """Rx (TS 29.214): Rx-Request-Type, UE address, AF identifiers, per
    Media-Component-Description the media type, flow status, the first line of each
    Codec-Data, bandwidths and the number of flows, Specific-Action and Abort-Cause."""
    out: dict[str, Any] = {}
    for name, key in (("Rx-Request-Type", "request_type"), ("Framed-IP-Address", "framed_ip_address"),
                      ("Framed-IPv6-Prefix", "framed_ipv6_prefix"), ("AF-Charging-Identifier", "af_charging_identifier"),
                      ("AF-Application-Identifier", "af_application_identifier"), ("Abort-Cause", "abort_cause"),
                      ("Service-URN", "service_urn")):
        if tree.get(name) is not None:
            out[key] = tree[name]
    media = []
    for mcd in (m for m in _listed(tree.get("Media-Component-Description")) if isinstance(m, dict)):
        row = {key: mcd[name] for name, key in (
            ("Media-Component-Number", "number"), ("Media-Type", "media_type"), ("Flow-Status", "flow_status"),
            ("Max-Requested-Bandwidth-UL", "max_requested_bandwidth_ul"),
            ("Max-Requested-Bandwidth-DL", "max_requested_bandwidth_dl"),
            ("RR-Bandwidth", "rr_bandwidth"), ("RS-Bandwidth", "rs_bandwidth")) if name in mcd}
        codecs = [c for c in (_codec_first_line(v) for v in _listed(mcd.get("Codec-Data"))) if c]
        if codecs:
            row["codec_data"] = codecs
        subs = [s for s in _listed(mcd.get("Media-Sub-Component")) if isinstance(s, dict)]
        if subs:
            row["sub_components"] = len(subs)
            row["flow_descriptions"] = sum(len(_listed(s.get("Flow-Description"))) for s in subs)
        media.append(row)
    if media:
        out["media_components"] = media
    actions = find(tree, "Specific-Action")
    if actions:
        out["specific_actions"] = actions
    if out or results(tree):
        out["results"] = results(tree) or None
    return {k: v for k, v in out.items() if v is not None}


def cx_digest(tree: dict[str, Any]) -> dict[str, Any]:
    """Cx/Dx (TS 29.229): authorization and assignment types, identities, the S-CSCF
    name or capability counts, the authentication scheme and item count (never RAND,
    AUTN, XRES, CK or IK), associated identities and the deregistration reason."""
    out: dict[str, Any] = {}
    for name, key in (("User-Authorization-Type", "user_authorization_type"),
                      ("Server-Assignment-Type", "server_assignment_type"), ("User-Name", "impi"),
                      ("Server-Name", "server_name"), ("SIP-Number-Auth-Items", "sip_number_auth_items"),
                      ("Visited-Network-Identifier", "visited_network")):
        if tree.get(name) is not None:
            out[key] = tree[name]
    publics = _listed(tree.get("Public-Identity"))
    if publics:
        out["public_identities"] = publics
    caps = tree.get("Server-Capabilities")
    if isinstance(caps, dict):
        out["server_capabilities"] = {"mandatory": len(_listed(caps.get("Mandatory-Capability"))),
                                      "optional": len(_listed(caps.get("Optional-Capability"))),
                                      "server_names": len(_listed(caps.get("Server-Name")))}
    items = [i for i in _listed(tree.get("SIP-Auth-Data-Item")) if isinstance(i, dict)]
    if items:
        schemes = sorted({str(i.get("SIP-Authentication-Scheme")) for i in items
                          if i.get("SIP-Authentication-Scheme") is not None})
        out["auth_items"] = {"count": len(items), "schemes": schemes}
    assoc = tree.get("Associated-Identities")
    if isinstance(assoc, dict):
        out["associated_identities"] = len(_listed(assoc.get("User-Name")))
    dereg = tree.get("Deregistration-Reason")
    if isinstance(dereg, dict):
        out["deregistration_reason"] = {k: v for k, v in (("code", dereg.get("Reason-Code")),
                                                          ("info", dereg.get("Reason-Info"))) if v is not None}
    if out or results(tree):
        out["results"] = results(tree) or None
    return {k: v for k, v in out.items() if v is not None}


def sh_digest(tree: dict[str, Any]) -> dict[str, Any]:
    """Sh (TS 29.329): the identities asked about, Data-Reference names, requested
    domain, Current-Location, Identity-Set, Service-Indication count and Sh-User-Data
    as size and element names only (the body is never returned)."""
    out: dict[str, Any] = {}
    identity = tree.get("User-Identity")
    if isinstance(identity, dict):
        out["user_identity"] = {k: v for k, v in (("public_identity", identity.get("Public-Identity")),
                                                  ("msisdn", identity.get("MSISDN"))) if v is not None}
    for name, key in (("Data-Reference", "data_reference"), ("Requested-Domain", "requested_domain"),
                      ("Identity-Set", "identity_set")):
        values = _listed(tree.get(name))
        if values:
            out[key] = values
    if tree.get("Current-Location") is not None:
        out["current_location"] = tree["Current-Location"]
    indications = _listed(tree.get("Service-Indication"))
    if indications:
        out["service_indications"] = len(indications)
    if tree.get("Sh-User-Data") is not None:
        out["user_data"] = tree["Sh-User-Data"]
    if out or results(tree):
        out["results"] = results(tree) or None
    return {k: v for k, v in out.items() if v is not None}


def s13_digest(tree: dict[str, Any]) -> dict[str, Any]:
    """S13 (TS 29.272 5.3): the IMEI and software version checked and the
    Equipment-Status (WHITELISTED, BLACKLISTED, GREYLISTED)."""
    out: dict[str, Any] = {}
    term = tree.get("Terminal-Information")
    if isinstance(term, dict):
        out["imei"] = term.get("IMEI")
        out["software_version"] = term.get("Software-Version")
    if tree.get("Equipment-Status") is not None:
        out["equipment_status"] = tree["Equipment-Status"]
    if any(v is not None for v in out.values()) or results(tree):
        out["results"] = results(tree) or None
    return {k: v for k, v in out.items() if v is not None}


DIGESTS: dict[int, tuple[str, Any]] = {
    4: ("gy", gy_digest),
    16777236: ("rx", rx_digest),
    16777216: ("cx", cx_digest),
    16777217: ("sh", sh_digest),
    16777252: ("s13", s13_digest),
}
"""Application id -> (key in the key view, digest builder)."""

_TAG = re.compile(r"<\s*(/?)\s*([A-Za-z_][\w.:-]*)[^>]*?(/?)>")
MAX_SH_ELEMENTS = 30


def sh_user_data(raw: Any) -> dict[str, Any]:
    """Sh-User-Data reduced to its size and the names of the root's child elements: the
    body (service data, IFCs, location) is never returned."""
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    text = "" if raw is None else str(raw)
    try:
        data = bytes.fromhex(text.replace(":", "")) if text and re.fullmatch(r"[0-9a-fA-F:]+", text) else text.encode()
    except ValueError:
        data = text.encode()
    xml = data.decode("utf-8", "replace")
    xml = re.sub(r"<\?.*?\?>|<!--.*?-->|<!\[CDATA\[.*?\]\]>", "", xml, flags=re.S)
    depth = 0
    root = None
    children: list[str] = []
    for m in _TAG.finditer(xml):
        closing, name, empty = m.group(1), m.group(2), m.group(3)
        if closing:
            depth -= 1
            continue
        if depth == 0 and root is None:
            root = name
        elif depth == 1 and name not in children and len(children) < MAX_SH_ELEMENTS:
            children.append(name)
        if not empty:
            depth += 1
    out: dict[str, Any] = {"bytes": len(data)}
    if root:
        out["root"] = root
    if children:
        out["elements"] = children
    return out
