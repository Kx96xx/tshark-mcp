"""GTPv2-C information elements in a key view: what the MME or SGW asked for and why
the gateway said no (TS 29.274 section 8).

The input is tshark's ``-T json`` tree of one GTPv2-C message, where every IE is a
subtree keyed by its display text ("PDN Type: IPv4/IPv6") holding ``gtpv2.ie_type``
and the IE's fields. IE names and enumerated values (RAT type, selection mode, PDN
type, cause) are read from that display text, so they are tshark's own names.

Content-free: Protocol Configuration Options are reported by option name only;
PAP and CHAP payloads (user names, passwords, challenges) are never returned.
"""

from __future__ import annotations

from typing import Any

from .fields import Json, compact, first, to_int
from .gtp import CAUSES, FTEID_INTERFACES

HARD_MAX_IES = 2000

# TS 24.008 10.5.6.3: Protocol Configuration Options container identifiers.
PCO_IDS: dict[int, str] = {
    0xC021: "LCP", 0xC023: "PAP (credentials not shown)", 0xC223: "CHAP (credentials not shown)",
    0x8021: "IPCP", 0x0001: "P-CSCF IPv6 Address Request", 0x0002: "IM CN Subsystem Signaling Flag",
    0x0003: "DNS Server IPv6 Address Request", 0x0004: "Policy Control rejection code",
    0x0005: "Selected Bearer Control Mode / MS Support of Network Requested Bearer Control indicator",
    0x0007: "DSMIPv6 Home Agent Address", 0x000A: "IP address allocation via NAS signalling",
    0x000B: "IPv4 address allocation via DHCPv4", 0x000C: "P-CSCF IPv4 Address Request",
    0x000D: "DNS Server IPv4 Address Request", 0x000E: "MSISDN Request", 0x0010: "IPv4 Link MTU Request",
    0x0011: "MS support of Local address in TFT indicator", 0x0012: "P-CSCF Re-selection support",
    0x0013: "NBIFOM request indicator", 0x0015: "Non-IP Link MTU Request", 0x0016: "APN rate control support",
    0x001A: "PDU session ID", 0x0023: "QoS rules with the length of two octets support indicator",
}
# Containers whose payload carries credentials: never copied, even in the full view.
_SECRET_PCO_LAYERS = ("pap", "chap", "lcp", "ipcp")

RAN_NAS_LOOKUP = {1: "s1ap", 2: "nas_emm", 3: "nas_esm", 4: "diameter"}
_RAN_NAS_FIELDS = (
    ("gtpv2.ran_nas.emm_cause", "nas_emm"), ("gtpv2.ran_nas.esm_cause", "nas_esm"),
    ("gtpv2.ran_nas.diameter_cause", "diameter"), ("gtpv2.ran_nas.s1ap_cause", "s1ap"),
    ("gtpv2.ran_nas.ikev2_cause", None),
)
_PDN_TYPES = {1: "IPv4", 2: "IPv6", 3: "IPv4v6", 4: "Non-IP", 5: "Ethernet"}

# IEs the key view reads into named keys; anything else is listed in other_ies by name.
_HANDLED = {1, 2, 3, 71, 72, 73, 75, 76, 77, 78, 79, 80, 82, 83, 86, 87, 93, 94, 95, 99, 114, 127, 128, 172}


# ----------------------------------------------------------------- walking the tree
def ies(tree: Json) -> list[tuple[str, Json]]:
    """The IEs at one level of a message or grouped IE: (display text, subtree), in order.
    tshark keys repeated IEs with identical text once, holding a list."""
    out: list[tuple[str, Json]] = []
    for key, value in tree.items():
        for item in (value if isinstance(value, list) else [value]):
            if isinstance(item, dict) and "gtpv2.ie_type" in item:
                out.append((key, item))
    return out


def ie_name(text: str) -> str:
    """"PDN Type: IPv4/IPv6" -> "PDN Type"."""
    return text.split(":", 1)[0].strip()


def ie_value_text(text: str) -> str | None:
    """"RAT Type: EUTRAN (6)" -> "EUTRAN (6)"; None when the display text has no value."""
    if ":" not in text:
        return None
    value = text.split(":", 1)[1].strip()
    return value or None


def _named(text: str, code: Any) -> str | None:
    value = ie_value_text(text)
    if value is None:
        return None if code is None else str(code)
    return value if code is None or f"({code})" in value else f"{value} ({code})"


def _plmn(ie: Json, prefix: str) -> str | None:
    mcc, mnc = first(ie, f"{prefix}.mcc"), first(ie, f"{prefix}.mnc")
    return f"{mcc}-{mnc}" if mcc and mnc else None


def _fteid(ie: Json) -> dict[str, Any]:
    iface = to_int(ie.get("gtpv2.f_teid_interface_type"))
    teid = to_int(ie.get("gtpv2.f_teid_gre_key"))
    return compact({
        "interface": FTEID_INTERFACES.get(iface if iface is not None else -1, f"interface-{iface}"),
        "instance": to_int(ie.get("gtpv2.instance")),
        "teid": f"0x{teid:08x}" if teid is not None else None,
        "ipv4": ie.get("gtpv2.f_teid_ipv4"),
        "ipv6": ie.get("gtpv2.f_teid_ipv6"),
    })


def _uli(ie: Json) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, sub in ie.items():
        if not isinstance(sub, dict):
            continue
        if key.startswith("Tracking Area Identity"):
            out["tai"] = compact({"plmn": _plmn(sub, "e212.tai"), "tac": first(sub, "gtpv2.tai_tac")})
        elif key.startswith("E-UTRAN Cell Global Identifier"):
            out["ecgi"] = compact({"plmn": _plmn(sub, "e212.ecgi"), "eci": to_int(first(sub, "gtpv2.ecgi_eci")),
                                   "enb_id": to_int(first(sub, "gtpv2.enodebid")),
                                   "cell_id": to_int(first(sub, "gtpv2.cellid"))})
        elif key.startswith("Cell Global Identity"):
            out["cgi"] = compact({"plmn": _plmn(sub, "e212.cgi"), "lac": first(sub, "gtpv2.uli_cgi_lac"),
                                  "ci": first(sub, "gtpv2.uli_cgi_ci")})
        elif key.startswith("Service Area Identity"):
            out["sai"] = compact({"plmn": _plmn(sub, "e212.sai"), "lac": first(sub, "gtpv2.sai_lac"),
                                  "sac": first(sub, "gtpv2.sai_sac")})
        elif key.startswith("Routeing Area Identity") or key.startswith("Routing Area Identity"):
            out["rai"] = compact({"plmn": _plmn(sub, "e212.rai"), "lac": first(sub, "gtpv2.rai_lac"),
                                  "rac": first(sub, "gtpv2.rai_rac")})
        elif key.startswith("Location Area Identity"):
            out["lai"] = compact({"plmn": _plmn(sub, "e212.lai"), "lac": first(sub, "gtpv2.uli_lai_lac")})
    return out


def _qos(ie: Json) -> dict[str, Any]:
    def kbps(name: str) -> int | None:
        return to_int(ie.get(f"gtpv2.bearer_qos_{name}"))
    return compact({
        "qci": to_int(ie.get("gtpv2.bearer_qos_label_qci")),
        "arp": compact({"pl": to_int(ie.get("gtpv2.bearer_qos_pl")), "pci": to_int(ie.get("gtpv2.bearer_qos_pci")),
                        "pvi": to_int(ie.get("gtpv2.bearer_qos_pvi"))}),
        "mbr_up_kbps": kbps("mbr_up"), "mbr_down_kbps": kbps("mbr_down"),
        "gbr_up_kbps": kbps("gbr_up"), "gbr_down_kbps": kbps("gbr_down"),
    })


def _pco(ie: Json) -> list[str]:
    ids: list[Any] = []
    pid = ie.get("gsm_a.gm.sm.pco_pid")
    for value in (pid if isinstance(pid, list) else [pid]):
        if value is not None:
            ids.append(value)
    out = []
    for value in ids:
        code = to_int(value)
        out.append(PCO_IDS.get(code, f"container 0x{code:04x}") if code is not None else str(value))
    return out


def _cause(ie: Json, text: str, request: Json | None) -> dict[str, Any]:
    value = to_int(ie.get("gtpv2.cause"))
    out: dict[str, Any] = {"value": value,
                           "name": CAUSES.get(value, None) if value is not None else None}
    shown = ie_value_text(text)
    if shown and value is not None and f"({value})" in shown:
        out["name"] = shown.rsplit("(", 1)[0].strip() or out["name"]
    cs = to_int(ie.get("gtpv2.cs"))
    if cs is not None:
        out["source"] = ("remote node: the sender relays an error from the node behind it (CS=1)" if cs
                         else "the node that sent this message (CS=0)")
    if to_int(ie.get("gtpv2.pce")):
        out["pdn_connection_ie_error"] = True
    if to_int(ie.get("gtpv2.bce")):
        out["bearer_context_ie_error"] = True
    off = to_int(ie.get("gtpv2.cause_off_ie_t"))
    if off is not None:
        named = next((ie_name(t) for t, sub in (ies(request) if request else [])
                      if to_int(sub.get("gtpv2.ie_type")) == off), None)
        out["offending_ie"] = f"{named} ({off})" if named else f"IE type {off}"
    return compact(out)


def _ran_nas(ie: Json) -> dict[str, Any]:
    proto = to_int(ie.get("gtpv2.ran_nas.protocol_type"))
    names = {1: "S1AP", 2: "EMM", 3: "ESM", 4: "Diameter", 5: "IKEv2"}
    out: dict[str, Any] = {"protocol": names.get(proto, f"type {proto}") if proto is not None else None}
    for fld, lookup in _RAN_NAS_FIELDS:
        value = to_int(ie.get(fld))
        if value is not None:
            out["cause"] = value
            if lookup:
                out["cause_lookup"] = f"cause_lookup(protocol='{lookup}', code={value})"
            break
    return compact(out)


def key_view(tree: Json, request: Json | None = None, depth: int = 0) -> dict[str, Any]:
    """The IEs worth reading first, named; ``request`` (the paired request's tree) names
    the offending IE of a cause."""
    out: dict[str, Any] = {}
    fteids: list[dict[str, Any]] = []
    bearers: list[dict[str, Any]] = []
    other: list[str] = []
    for text, ie in ies(tree):
        t = to_int(ie.get("gtpv2.ie_type"))
        if t == 1:
            out["imsi"] = first(ie, "e212.imsi")
        elif t == 76:
            out["msisdn"] = first(ie, "e164.msisdn")
        elif t == 75:
            out["mei"] = ie.get("gtpv2.mei")
        elif t == 71:
            out["apn"] = ie.get("gtpv2.apn")
        elif t == 128:
            out["selection_mode"] = _named(text, to_int(ie.get("gtpv2.selec_mode")))
        elif t == 99:
            code = to_int(ie.get("gtpv2.pdn_type"))
            out["pdn_type"] = f"{_PDN_TYPES.get(code, 'type')} ({code})" if code is not None else _named(text, None)
        elif t == 79:
            code = to_int(ie.get("gtpv2.pdn_type"))
            out["paa"] = compact({"pdn_type": _PDN_TYPES.get(code) if code is not None else None,
                                  "ipv4": ie.get("gtpv2.pdn_addr_and_prefix.ipv4"),
                                  "ipv6": ie.get("gtpv2.pdn_addr_and_prefix.ipv6")})
        elif t == 127:
            out["apn_restriction"] = _named(text, to_int(ie.get("gtpv2.apn_rest")))
        elif t == 83:
            # tshark 4.6 names these e212.serv_net.*; 4.2 and older use plain e212.mcc/mnc.
            out["serving_network"] = _plmn(ie, "e212.serv_net") or _plmn(ie, "e212")
        elif t == 82:
            out["rat_type"] = _named(text, to_int(ie.get("gtpv2.rat_type")))
        elif t == 86:
            out["uli"] = _uli(ie)
        elif t == 114:
            out["ue_time_zone"] = compact({"tz": ie.get("gsm_a.dtap.timezone"),
                                           "dst": to_int(ie.get("gtpv2.ue_time_zone_dst"))})
        elif t == 77:
            flags = [k.split(".", 1)[1].upper() for k, v in ie.items()
                     if k.startswith("gtpv2.") and k not in ("gtpv2.ie_type", "gtpv2.ie_len", "gtpv2.cr",
                                                             "gtpv2.instance") and str(v) == "1"]
            out["indication_flags"] = flags
        elif t == 95:
            out["charging_characteristics"] = ie.get("gtpv2.charging_characteristic")
        elif t == 94:
            out["charging_id"] = to_int(ie.get("gtpv2.charging_id"))
        elif t == 3:
            out["recovery"] = to_int(ie.get("gtpv2.rec"))
        elif t == 72:
            out["apn_ambr"] = compact({"up_kbps": to_int(ie.get("gtpv2.ambr_up")),
                                       "down_kbps": to_int(ie.get("gtpv2.ambr_down"))})
        elif t == 87:
            fteids.append(_fteid(ie))
        elif t == 78:
            out["pco"] = _pco(ie)
        elif t == 2:
            out["cause"] = _cause(ie, text, request)
        elif t == 172:
            out["ran_nas_cause"] = _ran_nas(ie)
        elif t == 73:
            out["ebi"] = to_int(ie.get("gtpv2.ebi"))
        elif t == 80:
            out["bearer_qos"] = _qos(ie)
        elif t == 93 and depth == 0:
            bearer = key_view(ie, None, depth + 1)
            # tshark 4.6 labels the context per message ("Bearer Contexts to be Created"); 4.2 does not.
            label = (ie_value_text(text) or "").split(":")[0].strip()
            bearer["context"] = label if label and not label.startswith("[") else None
            bearers.append(compact(bearer))
        else:
            other.append(f"{ie_name(text)} ({t})")
    if fteids:
        out["fteids"] = fteids
    if bearers:
        out["bearer_contexts"] = bearers
    if other:
        out["other_ies"] = other
    return compact(out)


def full_tree(tree: Json, max_ies: int) -> tuple[dict[str, Any], int]:
    """Every IE as a nested dict (fields without the gtpv2. prefix), at most ``max_ies``
    IEs; returns (tree, IEs dropped). PCO payloads are replaced by their option names."""
    budget = [max_ies, 0]

    def walk(node: Json) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in node.items():
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, dict) and "gtpv2.ie_type" in item:
                    if budget[0] <= 0:
                        budget[1] += 1
                        continue
                    budget[0] -= 1
                    t = to_int(item.get("gtpv2.ie_type"))
                    if t == 78:
                        entry: Any = {"options": _pco(item)}
                    else:
                        entry = walk(item)
                    name = key if key not in out else f"{key} #{sum(1 for k in out if k.startswith(key)) + 1}"
                    out[name] = entry
                elif key in ("gtpv2.ie_type", "gtpv2.ie_len", "gtpv2.cr") or key.startswith(_SECRET_PCO_LAYERS):
                    continue
                elif isinstance(item, dict):
                    sub = walk(item)
                    if sub:
                        out[key.removeprefix("gtpv2.")] = sub
                elif key not in out:
                    out[key.removeprefix("gtpv2.")] = item
        return out

    return walk(tree), budget[1]


# ----------------------------------------------------------------- why the reject
def likely_causes(request: dict[str, Any], response: dict[str, Any]) -> list[str]:
    """Plain-words reasons for a reject, built from what the request asked for."""
    cause = (response.get("cause") or {}).get("value")
    if cause is None or cause < 64 and cause not in (18, 19):
        return []
    apn = request.get("apn")
    pdn = request.get("pdn_type") or ""
    pco = request.get("pco") or []
    off = (response.get("cause") or {}).get("offending_ie")
    out: list[str] = []
    if cause in (18, 19):
        got = (response.get("paa") or {}).get("pdn_type")
        out.append(f"the UE asked for {pdn or 'a PDN type'} and the gateway allocated {got or 'another type'}: "
                   + ("operator preference" if cause == 18 else "the network supports single-address bearers only"))
    elif cause == 78:
        out.append(f"the gateway does not know the APN {apn!r}: check the APN configured on this PGW, the DNS "
                   "selection that chose it and the APN the subscription holds (diameter_avps on the ULA)")
    elif cause == 93:
        out.append(f"the subscriber has no subscription for {apn!r}: compare with the APNs in the ULA Subscription-Data")
    elif cause == 73:
        if "IPv4v6" in pdn or "IPv6" in pdn:
            out.append(f"{pdn} was requested: some gateways answer 73 when the APN is IPv4-only; "
                       "check the PDN types the APN serves")
        out.append("the gateway is out of resources (session capacity, IP pool or a backend)")
    elif cause == 84:
        out.append(f"the address pool of {apn!r} is exhausted (or held by stale sessions)")
    elif cause == 83:
        out.append(f"{pdn} is not supported for this APN")
    elif cause == 92:
        what = " (PAP/CHAP credentials in the PCO)" if any(p.startswith(("PAP", "CHAP")) for p in pco) else ""
        out.append(f"user authentication failed at the PGW{what}: look at the RADIUS or Gx exchange for the reason")
    elif cause == 125:
        out.append("the OCS or an external AAA did not authorise the UE: look at Gy or RADIUS")
    elif cause == 64:
        out.append("the receiver has no context for the header TEID: compare the Recovery IE with earlier "
                   "messages from the same peer (a restart), or the session was already deleted")
    elif cause in (69, 70, 103):
        out.append(f"the receiver rejected the message format{': it names ' + off if off else ''}")
    elif cause == 100:
        out.append("the next node did not answer the relaying node (e.g. the PGW behind the SGW)")
    elif cause in (110, 101):
        out.append("a procedure collision; a retry after the handover or the other request should succeed")
    elif cause in (113, 120):
        out.append("congestion at the gateway or for the APN: look for a back-off and for overload elsewhere")
    elif cause == 94:
        out.append("the gateway gave no reason: correlate with its logs or the Gx/RADIUS exchange at the same time")
    source = (response.get("cause") or {}).get("source", "")
    if source.startswith("remote node"):
        out.append("the cause was relayed (CS=1): it came from the node behind the one that answered")
    return out
