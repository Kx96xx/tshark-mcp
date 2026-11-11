"""Why can this roamer not attach or get a bearer: one subscriber's attach and PDN
attempts with the subscription held against what the visited network asked for.

The server collects the subscriber's steps (S6a AIR/ULR, MAP sendAuthenticationInfo,
updateLocation and updateGprsLocation, GTPv2-C Create Session and Modify Bearer, Gx
CCR-I, PFCP Session Establishment) and hands them here as plain dicts. This module
groups them into attempts, reads the ULA subscription against the Create Session
request (APN, PDN type, OI and home routing, RAT, ODB, AMBR) and names the first
failure with its reference.

Content-free: steps carry names, codes, identities, timings and frame numbers.
Authentication vectors are never read (an AIA is a result code and a vector count),
and no SMS, USSD or Sh content is touched.
"""

from __future__ import annotations

import re
from typing import Any

from . import causes
from .avps import find

# MCCs whose networks use three-digit MNCs (ITU-T E.212 list); the home PLMN read from
# an IMSI under these takes six digits, any other five. home_plmn overrides the guess.
THREE_DIGIT_MNC_MCCS = frozenset({
    "302", "310", "311", "312", "313", "314", "315", "316", "334", "338", "342", "344", "346", "348", "352",
    "354", "356", "358", "360", "365", "366", "376", "405", "708", "722", "732", "750",
})

# The references cause_lookup gives, so a verdict and a cause_lookup call quote the same section.
REFS = {
    "diameter": causes.TABLES["diameter"].ref,
    "s6a": f'{causes.APPLICATIONS["s6a"]} (S6a/S6d result codes)',
    "gx": f'{causes.APPLICATIONS["gx"]} (Gx result codes)',
    "gy": f'{causes.APPLICATIONS["gy"]} (Gy/Ro result codes)',
    "gtpv2": causes.TABLES["gtpv2"].ref,
    "pfcp": causes.TABLES["pfcp"].ref,
    "map": causes.TABLES["map"].ref,
}

ERROR_DIAGNOSTIC = {0: "GPRS_DATA_SUBSCRIBED", 1: "NO_GPRS_DATA_SUBSCRIBED", 2: "ODB-ALL-APN",
                    3: "ODB-HPLMN-APN", 4: "ODB-VPLMN-APN"}

# Diameter RAT-Type -> the Access-Restriction-Data bit that forbids it (TS 29.272 7.3.31).
RAT_RESTRICTION = {1000: "UTRAN-Not-Allowed", 1001: "GERAN-Not-Allowed", 1002: "GAN-Not-Allowed",
                   1003: "I-HSPA-Evolution-Not-Allowed", 1004: "WB-E-UTRAN-Not-Allowed",
                   1005: "NB-IoT-Not-Allowed", 1007: "LTE-M-Not-Allowed", 1006: "NR-in-5GS-Not-Allowed"}
# GTPv2 RAT Type (TS 29.274 8.17) -> Diameter RAT-Type.
GTP_RAT_TO_DIAMETER = {1: 1000, 2: 1001, 6: 1004, 8: 1005, 9: 1007, 10: 1006}

# GTPv2 PDN Type (8.34) -> name; Diameter PDN-Type (TS 29.272 7.3.62) -> name.
GTP_PDN = {1: "IPv4", 2: "IPv6", 3: "IPv4v6", 4: "Non-IP", 5: "Ethernet"}
DIAMETER_PDN = {0: "IPv4", 1: "IPv6", 2: "IPv4v6", 3: "IPv4_OR_IPv6", 4: "Non-IP", 5: "Ethernet"}

_OI = re.compile(r"\.mnc([0-9]{3})\.mcc([0-9]{3})\.gprs$", re.IGNORECASE)
_CODE = re.compile(r"\((\d+)\)\s*$")
_BITS = re.compile(r"\[(.*)\]\s*$")

PHASES = {"auth": "authentication", "location": "location update", "pdn": "PDN connection"}


# ----------------------------------------------------------------- PLMN helpers
def parse_plmn(text: str | None) -> tuple[str, str] | None:
    """"001-01", "001/01", "00101" or "001001" -> ("001", "01"); None when not a PLMN."""
    if not text:
        return None
    s = str(text).strip()
    m = re.fullmatch(r"(\d{3})[-/ ](\d{2,3})", s)
    if m:
        return m.group(1), m.group(2)
    if re.fullmatch(r"\d{5,6}", s):
        return s[:3], s[3:]
    return None


def plmn_text(plmn: tuple[str, str] | None) -> str | None:
    return f"{plmn[0]}-{plmn[1]}" if plmn else None


def home_from_imsi(imsi: str) -> tuple[str, str]:
    mcc = imsi[:3]
    return (mcc, imsi[3:6]) if mcc in THREE_DIGIT_MNC_MCCS else (mcc, imsi[3:5])


def apn_operator(apn: str | None) -> tuple[str | None, tuple[str, str] | None]:
    """Network identifier and the PLMN named by the operator identifier, if any."""
    if not apn:
        return None, None
    m = _OI.search(apn)
    if not m:
        return apn.lower(), None
    mnc, mcc = m.group(1), m.group(2)
    return apn[:m.start()].lower(), (mcc, mnc)


def oi_matches(oi: tuple[str, str], plmn: tuple[str, str]) -> bool:
    """The OI always writes a three-digit MNC (a two-digit MNC gets a leading zero)."""
    return oi[0] == plmn[0] and oi[1] == plmn[1].zfill(3)


def code_of(text: Any) -> int | None:
    """"IPv4v6 (2)" -> 2, an int -> itself."""
    if isinstance(text, int):
        return text
    if isinstance(text, str):
        m = _CODE.search(text)
        if m:
            return int(m.group(1))
        if text.isdigit():
            return int(text)
    return None


def bits_of(text: Any) -> list[str]:
    """"33 [UTRAN-Not-Allowed, HO-To-Non-3GPP-Access-Not-Allowed]" -> the names."""
    if not isinstance(text, str):
        return []
    m = _BITS.search(text)
    if not m or m.group(1).strip() in ("", "none"):
        return []
    return [b.strip() for b in m.group(1).split(",") if b.strip()]


def error_diagnostic(tree: dict[str, Any]) -> str | None:
    values = find(tree, "Error-Diagnostic")
    if not values:
        return None
    code = code_of(values[0])
    return f"{ERROR_DIAGNOSTIC.get(code, 'value')} ({code})" if code is not None else str(values[0])


# ----------------------------------------------------------------- attempts
def group_attempts(steps: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Steps in time order -> attempts. A new attempt starts when authentication follows
    a location update or a PDN step, when a second location update arrives, or when a
    Create Session repeats the APN of one already in the attempt (a retry)."""
    attempts: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []

    def has(phase: str, kind: str | None = None) -> bool:
        return any(s["phase"] == phase and (kind is None or s.get("kind") == kind) for s in current)

    for step in steps:
        phase, kind = step["phase"], step.get("kind")
        new = False
        if current:
            if phase == "auth" and (has("location") or has("pdn")):
                new = True
            elif phase == "location" and (has("location") or has("pdn")):
                new = True
            elif kind == "create_session":
                apn = (step.get("apn") or "").lower()
                new = any(s.get("kind") == "create_session" and (s.get("apn") or "").lower() == apn for s in current)
        if new:
            attempts.append(current)
            current = []
        current.append(step)
    if current:
        attempts.append(current)
    return attempts


def _check(name: str, result: str, detail: str, frames: list[int | None] | None = None,
           ref: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"check": name, "result": result, "detail": detail}
    fr = [f for f in (frames or []) if f]
    if fr:
        out["frames"] = fr
    if ref:
        out["ref"] = ref
    return out


def _sub_apn(subscription: dict[str, Any], ni: str | None) -> tuple[dict[str, Any] | None, bool]:
    """The APN configuration matching a network identifier; (config, via wildcard)."""
    apns = subscription.get("apns") or []
    for cfg in apns:
        if ni and str(cfg.get("apn") or "").lower() == ni:
            return cfg, False
    for cfg in apns:
        if cfg.get("apn") == "*":
            return cfg, True
    return None, False


def pdn_type_check(requested: int | None, subscribed: int | None) -> tuple[str, str]:
    req, sub = GTP_PDN.get(requested or -1), DIAMETER_PDN.get(subscribed if subscribed is not None else -1)
    if req is None or sub is None:
        return "unknown", "PDN type requested or subscribed not seen"
    if sub == req or sub == "IPv4v6" and req in ("IPv4", "IPv6"):
        return "pass", f"{req} requested, {sub} subscribed"
    if req == "IPv4v6" and sub in ("IPv4", "IPv6", "IPv4_OR_IPv6"):
        return "warn", (f"IPv4v6 requested, {sub} subscribed: the gateway should allocate a single address type "
                        "and answer cause 18 or 19; a gateway that answers 83 or 73 instead rejects the bearer")
    if sub == "IPv4_OR_IPv6" and req in ("IPv4", "IPv6"):
        return "pass", f"{req} requested, IPv4_OR_IPv6 subscribed"
    return "fail", f"{req} requested but the subscription allows {sub} only (expect cause 83 Preferred PDN type not supported)"


def evaluate(attempt: list[dict[str, Any]], *, home: tuple[str, str], imsi: str,
             earlier_subscription: tuple[dict[str, Any], int | None] | None) -> dict[str, Any]:
    """One attempt: visited PLMN, access, steps, subscription, request, checks,
    first_failure and a one-sentence verdict."""
    ulr = next((s for s in attempt if s.get("kind") == "ulr"), None)
    csr = next((s for s in attempt if s.get("kind") == "create_session"), None)
    request = (csr or {}).get("request") or {}

    visited, visited_source = None, None
    if ulr and ulr.get("visited_plmn"):
        visited, visited_source = parse_plmn(ulr["visited_plmn"]), "ULR Visited-PLMN-Id"
    elif request.get("serving_network"):
        visited, visited_source = parse_plmn(request["serving_network"]), "GTPv2 Serving Network"
    map_gt = next((s.get("peer_gt") for s in attempt if s["protocol"] == "map" and s.get("peer_gt")), None)

    roaming = None if visited is None else not (visited[0] == home[0] and visited[1] == home[1])

    rat_d = code_of(ulr.get("rat_type")) if ulr and ulr.get("rat_type") else None
    rat_text = ulr.get("rat_type") if ulr else None
    if rat_d is None and request.get("rat_type"):
        rat_d = GTP_RAT_TO_DIAMETER.get(code_of(request["rat_type"]) or -1)
        rat_text = request["rat_type"]
    uli = request.get("uli") or {}
    access = {k: v for k, v in (("rat", rat_text), ("tai", uli.get("tai")), ("ecgi", uli.get("ecgi"))) if v}

    sub_step = next((s for s in attempt if s.get("subscription")), None)
    subscription, sub_frame, carried = None, None, False
    if sub_step:
        subscription, sub_frame = sub_step["subscription"], sub_step.get("answer_frame")
    elif earlier_subscription:
        subscription, sub_frame = earlier_subscription
        carried = True

    checks: list[dict[str, Any]] = []
    for step in attempt:
        if step["phase"] == "pdn" and step.get("kind") not in ("create_session",):
            continue
        name = {"auth": "authentication", "location": "location_update", "pdn": "create_session"}[step["phase"]]
        if step.get("unanswered"):
            checks.append(_check(name, "fail", f'{step["step"]} was not answered',
                                 [step.get("request_frame")]))
        elif step.get("success") is False:
            checks.append(_check(name, "fail", f'{step["step"]}: {step.get("result")}',
                                 [step.get("answer_frame")], step.get("ref")))
        elif step.get("success"):
            checks.append(_check(name, "pass", f'{step["step"]}: {step.get("result") or "success"}',
                                 [step.get("answer_frame")]))

    if subscription:
        status = subscription.get("Subscriber-Status")
        odb = bits_of(subscription.get("Operator-Determined-Barring"))
        ni, oi = apn_operator(request.get("apn"))
        home_routed = None
        if oi is not None:
            if oi_matches(oi, home):
                home_routed = True
            elif visited is not None and oi_matches(oi, visited):
                home_routed = False
        barred = []
        if "All-Packet-Oriented-Services-Barred" in odb:
            barred.append("all packet services barred")
        if roaming and "Roamer-Access-to-VPLMN-AP-Barred" in odb and home_routed is not True:
            barred.append("roamer access to VPLMN APNs barred")
        if roaming and "Roamer-Access-HPLMN-AP-Barred" in odb and home_routed is not False:
            barred.append("roamer access to HPLMN APNs barred")
        if barred:
            checks.append(_check("odb", "fail", "operator determined barring: " + "; ".join(barred),
                                 [sub_frame], "TS 29.272 7.3.30"))
        elif odb or (code_of(status) == 1):
            checks.append(_check("odb", "warn", f"Subscriber-Status {status}, ODB {', '.join(odb) or 'none'}",
                                 [sub_frame], "TS 29.272 7.3.30"))
        else:
            checks.append(_check("odb", "pass", "no packet-service barring", [sub_frame]))

        ard = bits_of(subscription.get("Access-Restriction-Data"))
        if rat_d is not None:
            forbidden = RAT_RESTRICTION.get(rat_d)
            if forbidden and forbidden in ard:
                checks.append(_check("rat_allowed", "fail", f"{rat_text} used but Access-Restriction-Data has {forbidden}",
                                     [sub_frame], "TS 29.272 7.3.31"))
            else:
                checks.append(_check("rat_allowed", "pass", f"{rat_text} not restricted", [sub_frame]))

        if csr is not None:
            cfg, wildcard = _sub_apn(subscription, ni)
            apns = [a.get("apn") for a in subscription.get("apns") or [] if a.get("apn")]
            if cfg is None:
                checks.append(_check("apn_subscribed", "fail",
                                     f"{request.get('apn')!r} requested but the subscription holds {apns}",
                                     [csr.get("request_frame"), sub_frame]))
            else:
                checks.append(_check("apn_subscribed", "pass",
                                     f"{ni!r} " + ("matched by the wildcard APN" if wildcard else "is subscribed"),
                                     [csr.get("request_frame"), sub_frame]))
                result, detail = pdn_type_check(code_of(request.get("pdn_type")), code_of(cfg.get("pdn_type")))
                checks.append(_check("pdn_type_allowed", result, detail, [csr.get("request_frame"), sub_frame]))
                vplmn = code_of(cfg.get("vplmn_dynamic_address"))
                if roaming and home_routed is False:
                    if vplmn == 1:
                        checks.append(_check("routing", "pass", "local breakout: the OI names the visited PLMN and "
                                             "VPLMN-Dynamic-Address-Allowed is ALLOWED", [csr.get("request_frame")]))
                    else:
                        checks.append(_check("routing", "fail", "local breakout requested (the OI names the visited "
                                             "PLMN) but VPLMN-Dynamic-Address-Allowed is not ALLOWED for this APN",
                                             [csr.get("request_frame"), sub_frame], "TS 29.272 7.3.38"))
                elif roaming and home_routed:
                    checks.append(_check("routing", "pass", "home routed: the OI names the home PLMN, so S8 to the "
                                         "home PGW is expected", [csr.get("request_frame")]))
                elif roaming:
                    checks.append(_check("routing", "unknown", "the APN carries no operator identifier; "
                                         "home routing or local breakout cannot be told from the request",
                                         [csr.get("request_frame")]))
                sub_ambr = cfg.get("ambr") or {}
                req_ambr = request.get("apn_ambr") or {}
                over = [d for d, sk, rk in (("uplink", "ul", "up_kbps"), ("downlink", "dl", "down_kbps"))
                        if isinstance(sub_ambr.get(sk), int) and isinstance(req_ambr.get(rk), int)
                        and req_ambr[rk] * 1000 > sub_ambr[sk]]
                if req_ambr and sub_ambr:
                    checks.append(_check("ambr_within_subscription", "warn" if over else "pass",
                                         (f"APN-AMBR {' and '.join(over)} above the subscribed AMBR" if over else
                                          "APN-AMBR within the subscribed AMBR"), [csr.get("request_frame"), sub_frame]))
    elif csr is not None or ulr is not None:
        checks.append(_check("subscription", "unknown", "no ULA subscription data in the capture for this subscriber; "
                             "APN, PDN type, ODB and RAT checks need the ULA (capture S6a at the MME or DRA)"))

    steps_out = [{k: v for k, v in s.items() if k not in ("phase", "kind", "subscription", "request", "visited_plmn",
                                                           "peer_gt", "apn", "rat_type")}
                 for s in attempt]
    first = _first_failure(attempt, checks)
    out: dict[str, Any] = {
        "time": attempt[0].get("time"),
        "visited_plmn": plmn_text(visited) or (f"GT {map_gt}" if map_gt else None),
        "visited_source": visited_source or ("MAP peer global title" if map_gt else None),
        "roaming": roaming,
        "access": access or None,
        "steps": steps_out,
        "subscription": subscription,
        "subscription_frame": sub_frame,
        "subscription_from_earlier_attempt": carried or None,
        "request": {k: request.get(k) for k in ("apn", "pdn_type", "selection_mode", "rat_type", "serving_network",
                                                "indication_flags", "apn_ambr") if request.get(k)} or None,
        "checks": checks,
        "first_failure": first,
        "verdict": _verdict(attempt, checks, first),
    }
    return {k: v for k, v in out.items() if v is not None}


def _first_failure(attempt: list[dict[str, Any]], checks: list[dict[str, Any]]) -> dict[str, Any] | None:
    for step in attempt:
        if step.get("unanswered") or step.get("success") is False:
            out = {"step": step["step"], "result": "no answer" if step.get("unanswered") else step.get("result"),
                   "frame": step.get("answer_frame") or step.get("request_frame")}
            for k in ("code", "ref", "error_diagnostic", "cause_lookup", "offending_ie"):
                if step.get(k) is not None:
                    out[k] = step[k]
            return out
    bad = next((c for c in checks if c["result"] == "fail"), None)
    if bad:
        return {"check": bad["check"], "result": bad["detail"], **({"ref": bad["ref"]} if bad.get("ref") else {}),
                **({"frame": bad["frames"][0]} if bad.get("frames") else {})}
    return None


def _verdict(attempt: list[dict[str, Any]], checks: list[dict[str, Any]], first: dict[str, Any] | None) -> str:
    fails = [c for c in checks if c["result"] == "fail" and c["check"] not in
             ("authentication", "location_update", "create_session")]
    because = ""
    if fails:
        because = ": " + "; ".join(c["detail"] for c in fails[:2])
    if first and "step" in first:
        ref = f' ({first["ref"]})' if first.get("ref") else ""
        diag = f' with Error-Diagnostic {first["error_diagnostic"]}' if first.get("error_diagnostic") else ""
        return f'{first["step"]} failed: {first["result"]}{diag}{ref}{because}'
    if first:
        return f'no step was rejected, but {first["check"]} fails: {first["result"]}'
    phases = {s["phase"] for s in attempt}
    pdn_ok = any(s.get("kind") == "create_session" and s.get("success") for s in attempt)
    if pdn_ok:
        warn = next((c for c in checks if c["result"] == "warn"), None)
        return "attach and PDN connection succeeded" + (f'; note: {warn["detail"]}' if warn else "")
    missing = [PHASES[p] for p in ("auth", "location", "pdn") if p not in phases]
    return ("no failure seen; the capture holds no " + ", ".join(missing) + " for this attempt") if missing else \
        "no failure seen"


def evaluate_all(steps: list[dict[str, Any]], *, imsi: str, home: tuple[str, str]) -> list[dict[str, Any]]:
    out = []
    last_sub: tuple[dict[str, Any], int | None] | None = None
    for attempt in group_attempts(sorted(steps, key=lambda s: (s.get("time") or "", s.get("request_frame") or 0))):
        row = evaluate(attempt, home=home, imsi=imsi, earlier_subscription=last_sub)
        if row.get("subscription") and not row.get("subscription_from_earlier_attempt"):
            last_sub = (row["subscription"], row.get("subscription_frame"))
        out.append(row)
    return out
