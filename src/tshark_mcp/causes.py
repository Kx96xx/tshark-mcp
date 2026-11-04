"""``cause_lookup``: what a telecom cause or result code means, with the spec reference.

No capture is read. Names come from tshark's own value strings (``tshark -G
values``, filtered while tshark writes and cached per binary), so they match what
every other tool prints; the meaning, reference, typical causes and next steps
come from :mod:`causedata`. Protocols tshark has no value table for (SIP, MAP
errors, CP, TP-Status, SBI causes) take their names from the curated table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from . import causedata as data
from .limits import ToolError
from .runner import Runner, check_result
from .sigtran import MAP_ERRORS


@dataclass(frozen=True)
class Table:
    protocol: str
    ref: str
    curated: dict[Any, Any]
    fields: tuple[str, ...] = ()
    """tshark fields whose value strings name the codes (several for S1AP/NGAP cause groups)."""
    names: dict[Any, str] = field(default_factory=dict)
    """Names when tshark has no value table."""
    next: tuple[str, ...] = ()


def _filter(fld: str) -> str:
    return f"filter_packets(path, display_filter='{fld} == {{code}}') to find the frames"


_S1AP_GROUPS = ("radioNetwork", "transport", "nas", "protocol", "misc")

TABLES: dict[str, Table] = {
    "diameter": Table("diameter", "RFC 6733 7.1 (Result-Code); RFC 4006 9.1 for credit control",
                      data.DIAMETER_BASE, ("diameter.Result-Code",),
                      next=("diameter_transactions(path, filter='diameter.Result-Code == {code}') for the transactions",
                            "diameter_avps(path, imsi=..., detail='key') for Failed-AVP and Error-Diagnostic")),
    "diameter_experimental": Table("diameter", "3GPP Experimental-Result-Code of the application",
                                   data.DIAMETER_EXPERIMENTAL, ("diameter.Experimental-Result-Code",),
                                   next=("diameter_transactions(path, filter='diameter.Experimental-Result-Code == {code}')",
                                         "diameter_avps(path, imsi=..., detail='key') for Error-Diagnostic and the "
                                         "Subscription-Data the HSS did send")),
    "gtpv2": Table("gtpv2", "TS 29.274 8.4 (Table 8.4-1)", data.GTPV2, ("gtpv2.cause",),
                   next=("gtp_sessions(path, filter='gtpv2.cause == {code}') for the transactions, IMSI and APN",
                         "packet_detail(path, frame, layers=['gtpv2']) for the Offending IE and Recovery")),
    "gtpv1": Table("gtpv1", "TS 29.060 7.7.1", data.GTPV1, ("gtp.cause",),
                   next=("gtpv1_sessions(path, filter='gtp.cause == {code}')",)),
    "pfcp": Table("pfcp", "TS 29.244 8.2.1", data.PFCP, ("pfcp.cause",),
                  next=("pfcp_sessions(path, view='transactions', filter='pfcp.cause == {code}')",
                        "pfcp_sessions(path, view='nodes') for association loss and peer restarts")),
    "nas_emm": Table("nas_emm", "TS 24.301 9.9.3.9 and Annex A", data.EMM, ("nas-eps.emm.cause",),
                     next=(_filter("nas-eps.emm.cause"),
                           "diameter_sessions(path, imsi=...) for the HSS answer behind the reject")),
    "nas_esm": Table("nas_esm", "TS 24.301 9.9.4.4 and Annex B", data.ESM, ("nas-eps.esm.cause",),
                     next=(_filter("nas-eps.esm.cause"), "gtp_sessions(path, imsi=...) for the gateway's cause")),
    "nas_5gmm": Table("nas_5gmm", "TS 24.501 9.11.3.2 and Annex A", data.FIVEG_MM, ("nas-5gs.mm.5gmm_cause",),
                      next=(_filter("nas-5gs.mm.5gmm_cause"),)),
    "nas_5gsm": Table("nas_5gsm", "TS 24.501 9.11.4.2 and Annex B", data.FIVEG_SM, ("nas-5gs.sm.5gsm_cause",),
                      next=(_filter("nas-5gs.sm.5gsm_cause"), "pfcp_sessions(path) for the N4 side")),
    "s1ap": Table("s1ap", "TS 36.413 9.2.1.3", data.S1AP, tuple(f"s1ap.{g}" for g in _S1AP_GROUPS),
                  next=("filter_packets(path, display_filter='s1ap.{group} == {value}')",)),
    "ngap": Table("ngap", "TS 38.413 9.3.1.2", data.NGAP, tuple(f"ngap.{g}" for g in _S1AP_GROUPS),
                  next=("filter_packets(path, display_filter='ngap.{group} == {value}')",)),
    "sip": Table("sip", "RFC 3261 21 (and the RFC that defines the code)", data.SIP,
                 next=("sip_dialogs(path, filter='sip.Status-Code == {code}') for the calls",
                       "sip_call_detail(path, call_id) for Reason and Warning headers")),
    "q850": Table("q850", "ITU-T Q.850 Table 1", data.Q850, ("q931.cause_value",),
                  next=("sip_call_detail(path, call_id): the Reason header carries the Q.850 cause",)),
    "isup": Table("isup", "ITU-T Q.850 Table 1 (ISUP Cause indicators, Q.763 3.12)", data.Q850,
                  ("isup.cause_indicator",), next=(_filter("isup.cause_indicator"),)),
    "camel_release": Table("camel_release", "ITU-T Q.850 Table 1 (CAMEL ReleaseCall cause, TS 29.078)", data.Q850,
                           ("camel.cause_indicator",), next=("sigtran_messages(path)",)),
    "map": Table("map", "TS 29.002 17.6.6", data.MAP, names=MAP_ERRORS,
                 next=("sigtran_messages(path) for the returnError and its operation",)),
    "tcap_abort": Table("tcap_abort", "ITU-T Q.773 (P-AbortCause)", data.TCAP_ABORT, ("tcap.p_abortCause",),
                        next=("sigtran_messages(path)",)),
    "sccp_return": Table("sccp_return", "ITU-T Q.713 3.12", data.SCCP_RETURN, ("sccp.return_cause",),
                         next=("sigtran_messages(path) for the UDTS/XUDTS and the called GT",)),
    "sgsap": Table("sgsap", "TS 29.118 9.4.18", data.SGSAP, ("sgsap.sgs_cause",), next=(_filter("sgsap.sgs_cause"),)),
    "rp": Table("rp", "TS 24.011 8.2.5.4", data.RP, ("gsm_a.rp.cause",),
                next=("sms_over_ims(path) for SMS over IMS", _filter("gsm_a.rp.cause"))),
    "cp": Table("cp", "TS 24.011 8.1.4.2", data.CP, next=("sms_over_ims(path)",)),
    "tp_status": Table("tp_status", "TS 23.040 9.2.3.15", data.TP_STATUS, next=("sms_over_ims(path) for the status report",)),
    "http_sbi": Table("http_sbi", "TS 29.500 5.2.7 and the service's own ProblemDetails table", data.HTTP_SBI,
                      next=("response_times(path, filter='http2') for the SBI exchange",)),
}

PROTOCOLS: tuple[str, ...] = tuple(k for k in TABLES if k != "diameter_experimental")
NOT_CODES: dict[str, str] = {
    "rtcp_xr": "RTCP XR carries quality metrics, not cause codes: use rtp_streams for loss, jitter and MOS",
}

# Diameter applications: the spec section where each defines its Experimental-Result-Codes.
APPLICATIONS: dict[str, str] = {
    "base": "RFC 6733 7.1", "s6a": "TS 29.272 7.4.3", "s6d": "TS 29.272 7.4.3", "s13": "TS 29.272 7.4.3",
    "gx": "TS 29.212 5.5.3", "gy": "TS 32.299 / RFC 4006 9.1", "ro": "TS 32.299 / RFC 4006 9.1",
    "rx": "TS 29.214 5.5.3", "cx": "TS 29.229 6.2.2", "dx": "TS 29.229 6.2.2", "sh": "TS 29.329 6.2.2",
    "swx": "TS 29.273 8.2.3", "s6b": "TS 29.273 9.2.3", "swm": "TS 29.273 7.2.3", "s6c": "TS 29.338 5.3.3",
    "sgd": "TS 29.338 6.3.3", "t6a": "TS 29.128 6.3.3",
}
_APP_ALIASES = {"s6d": "s6a", "s13": "s6a", "ro": "gy", "dx": "cx", "swm": "s6b"}

RESERVED = re.compile(r"^(reserved|spare|unused|shall not be used)\b|^unassigned$", re.IGNORECASE)
MAX_QUERY = 100
_PRINTABLE = re.compile(r"^[^\x00-\x1f\x7f]{1,64}$")


# ----------------------------------------------------------------- tshark value strings
_VALUES_CACHE: dict[str, dict[str, "Names"]] = {}


@dataclass
class Names:
    values: dict[int, str] = field(default_factory=dict)
    ranges: list[tuple[int, int, str]] = field(default_factory=list)

    def get(self, code: int) -> str | None:
        if code in self.values:
            return self.values[code]
        for low, high, name in self.ranges:
            if low <= code <= high:
                return name
        return None


def all_fields() -> frozenset[str]:
    return frozenset(f for t in TABLES.values() for f in t.fields)


def tshark_values(runner: Runner) -> dict[str, Names]:
    """Value strings of the cause fields, from ``tshark -G values``, read once per binary.
    Lines are ``V<TAB>field<TAB>value<TAB>name`` and ``R<TAB>field<TAB>low<TAB>high<TAB>name``."""
    cached = _VALUES_CACHE.get(runner.tshark)
    if cached is not None:
        return cached
    wanted = {f.encode() for f in all_fields()}

    def keep(line: bytes) -> bool:
        parts = line.split(b"\t", 2)
        return len(parts) == 3 and parts[0] in (b"V", b"R") and parts[1] in wanted

    out = parse_values(check_result(runner.list_values(keep)).stdout)
    _VALUES_CACHE[runner.tshark] = out
    return out


def parse_values(text: str) -> dict[str, Names]:
    out: dict[str, Names] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        try:
            if parts[0] == "V" and len(parts) >= 4:
                value = int(parts[2], 0)
                out.setdefault(parts[1], Names()).values.setdefault(value, parts[3].strip())
            elif parts[0] == "R" and len(parts) >= 5:
                low, high = int(parts[2], 0), int(parts[3], 0)
                out.setdefault(parts[1], Names()).ranges.append((low, high, parts[4].strip()))
        except ValueError:
            continue
    return out


# ----------------------------------------------------------------- argument parsing
def _entry(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    meaning, typical, related = raw
    return {"meaning": meaning, "typical": typical, "related": related}


def _int_code(code: Any) -> int:
    if isinstance(code, bool):
        raise ToolError("invalid_argument", f"code must be a number, got {code!r}")
    if isinstance(code, int):
        value = code
    else:
        text = str(code).strip()
        try:
            value = int(text, 0) if text.lower().startswith("0x") else int(text)
        except ValueError:
            raise ToolError("invalid_argument", f"code must be a number such as 78 or 0x4e, got {code!r}") from None
    if value < 0 or value > 0xFFFFFFFF:
        raise ToolError("invalid_argument", f"code {value} is out of range")
    return value


def _group_code(protocol: str, code: Any) -> tuple[str, int]:
    text = str(code).strip()
    m = re.fullmatch(r"([A-Za-z]+)\s*[:/ ]\s*(\d+)", text)
    if not m:
        raise ToolError("invalid_argument", f"{protocol} causes are a group and a value, such as 'radioNetwork:21' "
                                            f"or 'nas:2'; groups: {', '.join(_S1AP_GROUPS)}")
    group = next((g for g in _S1AP_GROUPS if g.lower() == m.group(1).lower()), None)
    if group is None:
        raise ToolError("invalid_argument", f"unknown {protocol} cause group {m.group(1)!r}; groups: {', '.join(_S1AP_GROUPS)}")
    return group, int(m.group(2))


def check_protocol(protocol: Any) -> str:
    if not isinstance(protocol, str) or not protocol.strip():
        raise ToolError("invalid_argument", f"protocol is required; one of: {', '.join(PROTOCOLS)}")
    key = protocol.strip().lower().replace("-", "_")
    key = {"nas_eps_emm": "nas_emm", "emm": "nas_emm", "esm": "nas_esm", "5gmm": "nas_5gmm", "5gsm": "nas_5gsm",
           "gtp": "gtpv2", "gtpc": "gtpv2", "q.850": "q850", "sccp": "sccp_return", "tcap": "tcap_abort",
           "sbi": "http_sbi", "tp": "tp_status", "camel": "camel_release"}.get(key, key)
    if key in NOT_CODES:
        raise ToolError("invalid_argument", f"{NOT_CODES[key]}. cause_lookup protocols: {', '.join(PROTOCOLS)}")
    if key not in PROTOCOLS:
        raise ToolError("invalid_argument", f"unknown protocol {protocol!r}; one of: {', '.join(PROTOCOLS)}")
    return key


def check_application(application: Any) -> str | None:
    if application is None:
        return None
    key = str(application).strip().lower()
    if key not in APPLICATIONS:
        raise ToolError("invalid_argument", f"unknown Diameter application {application!r}; one of: {', '.join(APPLICATIONS)}")
    return key


def _check_message(message: Any) -> str | None:
    if message is None:
        return None
    text = str(message).strip()
    if not _PRINTABLE.match(text):
        raise ToolError("invalid_argument", "message must be at most 64 printable characters, e.g. INVITE or attach_reject")
    return text


# ----------------------------------------------------------------- lookup
def _name(table: Table, values: dict[str, Names], code: Any, group: str | None = None) -> tuple[str | None, str | None, str | None]:
    """(name, source, tshark field) of a code."""
    fields = (f"{table.protocol}.{group}",) if group else table.fields
    for fld in fields:
        names = values.get(fld)
        if names is not None:
            name = names.get(code)
            if name is not None:
                return name, "tshark", fld
    curated = _entry(table.curated.get(f"{group}:{code}" if group else code))
    if curated.get("name"):
        return curated["name"], "curated", None
    if code in table.names:
        return table.names[code], "curated", None
    if table.protocol == "http_sbi" and code in table.curated:
        return code, "curated", None
    return None, None, (fields[0] if fields else None)


def lookup(runner: Runner, protocol: str, code: Any, application: str | None = None,
           message: str | None = None) -> dict[str, Any]:
    proto = check_protocol(protocol)
    app = check_application(application)
    if app is not None and proto != "diameter":
        raise ToolError("invalid_argument", "application applies to protocol='diameter' only")
    msg = _check_message(message)
    values = tshark_values(runner) if TABLES[proto].fields else {}
    group = None
    key: Any
    if proto in ("s1ap", "ngap"):
        group, value = _group_code(proto, code)
        key = f"{group}:{value}"
        code_out: Any = key
    elif proto == "http_sbi":
        key = str(code).strip().upper()
        if not re.fullmatch(r"[A-Z0-9_]{2,64}", key):
            raise ToolError("invalid_argument", "http_sbi codes are ProblemDetails cause strings such as USER_NOT_FOUND")
        value = key
        code_out = key
    else:
        value = key = code_out = _int_code(code)

    table = TABLES[proto]
    out: dict[str, Any] = {"protocol": proto, "code": code_out}
    if proto == "diameter":
        base = TABLES["diameter"]
        exp = TABLES["diameter_experimental"]
        base_name = _name(base, values, value)
        exp_name = _name(exp, values, value)
        if app == "base":
            use_exp = False
        elif app is not None:
            use_exp = exp_name[0] is not None
        else:
            use_exp = base_name[0] is None and exp_name[0] is not None
        if use_exp:
            table, (name, source, fld) = exp, exp_name
            out["avp"] = "Experimental-Result-Code"
        else:
            table, (name, source, fld) = base, base_name
            out["avp"] = "Result-Code"
            if app not in (None, "base"):
                out["note"] = (f"{value} is not an Experimental-Result-Code tshark knows; this is the base Result-Code "
                               "meaning, which every application shares")
        if app in (None, "base") and exp_name[0] is not None and out["avp"] == "Result-Code":
            out["also"] = {"avp": "Experimental-Result-Code", "name": exp_name[0],
                           "note": "the same number inside Experimental-Result means something else: pass "
                                   "application (s6a, cx, gx, rx, sh, ...) to look it up there"}
        if app is not None:
            out["application"] = app
    else:
        name, source, fld = _name(table, values, value, group)

    entry = _entry(table.curated.get(key))
    reserved = bool(name and RESERVED.match(name))
    out.update({"name": name, "name_source": source, "known": name is not None and not reserved,
                "explained": bool(entry.get("meaning"))})
    if fld:
        out["tshark_field"] = fld
    if reserved:
        out["note"] = "tshark marks this value reserved or spare: a sender using it is out of spec or on a newer release"
    elif name is None:
        out["note"] = ("this tshark does not name this code; it may be vendor-specific or newer than the dissector. "
                       f"Use cause_lookup(protocol='{proto}', query=...) to search by name")
    ref = entry.get("ref") or table.ref
    if out.get("avp") == "Experimental-Result-Code" and not entry.get("ref"):
        owner = app if app not in (None, "base") else _owner(entry.get("meaning", ""))
        if owner:
            ref = f"{APPLICATIONS[owner]} (Experimental-Result-Code)"
    out["ref"] = ref
    if entry.get("meaning"):
        out["meaning"] = entry["meaning"]
    by_app = entry.get("by_application") or {}
    if app is not None and _APP_ALIASES.get(app, app) in by_app:
        out["application_note"] = by_app[_APP_ALIASES.get(app, app)]
    elif by_app and app in (None, "base") and out.get("avp") != "Result-Code":
        out["by_application"] = by_app
    by_msg = entry.get("by_message") or {}
    if msg is not None:
        hit = next((text for k, text in by_msg.items() if k.lower() == msg.lower().replace(" ", "_")), None)
        if hit is None:
            hit = next((text for k, text in by_msg.items() if k.lower() == msg.lower()), None)
        if hit is not None:
            out["message"] = msg
            out["message_note"] = hit
    elif by_msg:
        out["by_message"] = by_msg
    if entry.get("typical"):
        out["typical_causes"] = list(entry["typical"])
    if entry.get("related"):
        out["related"] = list(entry["related"])
    steps = entry.get("next") or table.next
    fmt = {"code": code_out, "group": group or "", "value": value}
    out["check_next"] = [s.format(**fmt) for s in steps]
    return out


def _owner(meaning: str) -> str | None:
    """The application a curated Experimental-Result-Code text starts with ("S6a: ...")."""
    m = re.match(r"([A-Za-z0-9]+)[:/]", meaning)
    return m.group(1).lower() if m and m.group(1).lower() in APPLICATIONS else None


def _codes(table: Table, values: dict[str, Names]) -> list[Any]:
    """Every code of one table: tshark's value strings (not reserved) and the curated ones."""
    codes: list[Any] = []
    for fld in table.fields:
        names = values.get(fld)
        if names is None:
            continue
        group = fld.split(".", 1)[1]
        for code, name in names.values.items():
            if not RESERVED.match(name):
                codes.append(f"{group}:{code}" if table.protocol in ("s1ap", "ngap") else code)
    codes += list(table.names) + list(table.curated)
    return list(dict.fromkeys(codes))


def search(runner: Runner, protocol: str, query: str, application: str | None = None) -> list[dict[str, Any]]:
    """Codes of ``protocol`` whose code, name, meaning or typical causes hold every word of ``query``."""
    proto = check_protocol(protocol)
    check_application(application)
    if not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY or re.search(r"[\x00-\x1f\x7f]", query):
        raise ToolError("invalid_argument", f"query must be 1 to {MAX_QUERY} printable characters")
    words = [w.lower() for w in query.split()[:5]]
    sources = [("diameter", "Result-Code"), ("diameter_experimental", "Experimental-Result-Code")] \
        if proto == "diameter" else [(proto, None)]
    values = tshark_values(runner) if any(TABLES[k].fields for k, _ in sources) else {}
    rows: list[dict[str, Any]] = []
    for key, avp in sources:
        table = TABLES[key]
        for code in _codes(table, values):
            group, value = (code.split(":")[0], int(code.split(":")[1])) if proto in ("s1ap", "ngap") else (None, code)
            name = _name(table, values, value, group)[0]
            if name is None or RESERVED.match(name):
                continue
            entry = _entry(table.curated.get(code))
            text = " ".join([str(code), name, entry.get("meaning", ""), " ".join(entry.get("typical", ()))]).lower()
            if not all(w in text for w in words):
                continue
            row: dict[str, Any] = {"code": code, "name": name, "explained": bool(entry.get("meaning"))}
            if avp:
                row["avp"] = avp
            if entry.get("meaning"):
                row["meaning"] = entry["meaning"]
            rows.append(row)
    rows.sort(key=lambda r: (0 if all(w in r["name"].lower() for w in words) else 1, r.get("avp", ""),
                             (0, r["code"], "") if isinstance(r["code"], int) else (1, 0, str(r["code"]))))
    return rows
