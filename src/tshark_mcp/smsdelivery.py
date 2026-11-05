"""sms_delivery: SMS submit, delivery and report chains over MAP and SGsAP, one row per attempt.

One ``-T fields`` pass over ``gsm_map || sgsap`` gives a row per packet. MAP rows are paired
into TCAP dialogues by transaction id (Begin otid, End/Continue/Abort dtid), and the
dialogues of one short message are joined into one attempt: sendRoutingInfoForSM for an
MSISDN, the mt-forwardSM to the IMSI it returned, and reportSM-DeliveryStatus for the
same MSISDN. SGsAP rows are grouped per IMSI: PAGING-REQUEST for SMS, SERVICE-REQUEST or
PAGING-REJECT, DOWNLINK and UPLINK UNITDATA with the CP and RP layer. Each attempt ends in
a verdict with the cause named. Content-free: operations, codes, message references,
identities (redactable) and frames; never the TPDU text or the other party's number.
"""

from __future__ import annotations

from typing import Any, Callable

from .fields import iso, parse_time, split_fields_line, to_int

FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
    "tcap.otid", "tcap.dtid", "tcap.p_abortCause", "gsm_map.old.Component", "gsm_old.localValue",
    "gsm_map.er.sm_EnumeratedDeliveryFailureCause", "gsm_map.er.absentSubscriberDiagnosticSM",
    "e212.imsi", "e164.msisdn",
    "sgsap.msg_type", "sgsap.service_indicator", "sgsap.sgs_cause",
    "gsm_a.dtap.msg_sms_type", "gsm_a.dtap.cp_cause", "gsm_a.rp.msg_type", "gsm_a.rp.rp_message_reference",
    "gsm_a.rp.cause", "gsm_sms.tp-mti", "gsm_sms.tp-mr",
]
_IX = {name: i for i, name in enumerate(FIELDS)}
DISPLAY_FILTER = "gsm_map || sgsap"
JOIN_WINDOW_S = 60.0
ANSWER_WINDOW_S = 10.0

MAP_SMS_OPS = {45: "sendRoutingInfoForSM", 44: "mt-forwardSM", 46: "mo-forwardSM", 47: "reportSM-DeliveryStatus",
               63: "informServiceCentre", 64: "alertServiceCentre", 66: "readyForSM"}
DELIVERY_FAILURE = {0: "memoryCapacityExceeded", 1: "equipmentProtocolError", 2: "equipmentNotSM-Equipped",
                    3: "unknownServiceCentre", 4: "sc-Congestion", 5: "invalidSME-Address",
                    6: "subscriberNotSC-Subscriber"}
ABSENT_ERRORS = {6, 27}  # absentSubscriberSM, absentSubscriber
SGS_MESSAGES = {0x01: "PAGING-REQUEST", 0x02: "PAGING-REJECT", 0x06: "SERVICE-REQUEST", 0x07: "DOWNLINK-UNITDATA",
                0x08: "UPLINK-UNITDATA", 0x0A: "LOCATION-UPDATE-ACCEPT", 0x0F: "UE-UNREACHABLE",
                0x11: "EPS-DETACH-INDICATION", 0x14: "IMSI-DETACH-INDICATION", 0x1B: "RELEASE-REQUEST",
                0x1C: "SERVICE-ABORT-REQUEST", 0x1D: "MO-CSFB-INDICATION"}
CP_TYPES = {1: "CP-DATA", 4: "CP-ACK", 16: "CP-ERROR"}
RP_TYPES = {0: "RP-DATA (MS to network)", 1: "RP-DATA (network to MS)", 2: "RP-ACK (MS to network)",
            3: "RP-ACK (network to MS)", 4: "RP-ERROR (MS to network)", 5: "RP-ERROR (network to MS)",
            6: "RP-SMMA"}
VERDICTS = ("delivered", "rejected", "absent_subscriber", "paging_failed", "no_response", "in_progress")

METHOD = {
    "map": "TCAP dialogues paired by transaction id; sendRoutingInfoForSM, the mt-forwardSM to the IMSI it "
           f"returned and reportSM-DeliveryStatus for the same MSISDN within {JOIN_WINDOW_S:g} s are one attempt",
    "sgs": "per IMSI: PAGING-REQUEST (service indicator SMS) or the first CP-DATA starts an attempt; RP-ACK "
           "delivers it, RP-ERROR or CP-ERROR rejects it, PAGING-REJECT fails the paging",
    "verdict": f"delivered, rejected, absent_subscriber, paging_failed, no_response (no answer within "
               f"{ANSWER_WINDOW_S:g} s), in_progress (the capture ended sooner)",
    "content": "content-free: never the TPDU text, never TP-OA or TP-DA",
}


def _ints(cell: str) -> list[int]:
    return [v for v in (to_int(p.strip()) for p in (cell or "").split(",")) if v is not None]


def _int(cell: str) -> int | None:
    vals = _ints(cell)
    return vals[0] if vals else None


def _str(cell: str) -> str | None:
    first = (cell or "").split(",")[0].strip()
    return first or None


def parse(stdout: str) -> list[dict[str, Any]]:
    rows = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        cells = split_fields_line(line)
        cells += [""] * (len(FIELDS) - len(cells))

        def c(name: str) -> str:
            return cells[_IX[name]]
        frame = _int(c("frame.number"))
        if frame is None:
            continue
        rows.append({
            "frame": frame, "time": parse_time(c("frame.time_epoch")), "src": _str(c("ip.src")), "dst": _str(c("ip.dst")),
            "otid": _str(c("tcap.otid")), "dtid": _str(c("tcap.dtid")), "p_abort": _int(c("tcap.p_abortCause")),
            "component": _int(c("gsm_map.old.Component")), "local": _int(c("gsm_old.localValue")),
            "failure_cause": _int(c("gsm_map.er.sm_EnumeratedDeliveryFailureCause")),
            "absent_diag": _int(c("gsm_map.er.absentSubscriberDiagnosticSM")),
            "imsi": _str(c("e212.imsi")), "msisdn": _str(c("e164.msisdn")),
            "sgs": _int(c("sgsap.msg_type")), "service_indicator": _int(c("sgsap.service_indicator")),
            "sgs_cause": _int(c("sgsap.sgs_cause")), "cp": _int(c("gsm_a.dtap.msg_sms_type")),
            "cp_cause": _int(c("gsm_a.dtap.cp_cause")), "rp": _int(c("gsm_a.rp.msg_type")),
            "rp_mr": _int(c("gsm_a.rp.rp_message_reference")), "rp_cause": _int(c("gsm_a.rp.cause")),
            "tp_mti": _int(c("gsm_sms.tp-mti")), "tp_mr": _int(c("gsm_sms.tp-mr")),
        })
    return rows


# ------------------------------------------------------------------ MAP
def _dialogues(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_tid: dict[str, dict[str, Any]] = {}
    out = []
    for r in rows:
        if r["sgs"] is not None:
            continue
        if r["otid"] and not r["dtid"]:  # Begin
            if r["component"] != 1 or r["local"] not in MAP_SMS_OPS:
                continue
            d = {"begin": r, "op": r["local"], "answer": None, "tid": r["otid"]}
            by_tid[r["otid"]] = d
            out.append(d)
        elif r["dtid"] and r["dtid"] in by_tid:
            d = by_tid[r["dtid"]]
            if d["answer"] is None:
                d["answer"] = r
    return out


def _map_step(d: dict[str, Any], explain: Callable[..., Any], capture_end: float | None) -> dict[str, Any]:
    b, a = d["begin"], d["answer"]
    step: dict[str, Any] = {"step": MAP_SMS_OPS[d["op"]], "frame": b["frame"], "time": iso(b["time"]),
                            "from": b["src"], "to": b["dst"]}
    if a is None:
        left = None if capture_end is None or b["time"] is None else capture_end - b["time"]
        step["result"] = "in_progress" if left is not None and left < ANSWER_WINDOW_S else "no_response"
        return step
    step["answer_frame"] = a["frame"]
    if a["time"] is not None and b["time"] is not None:
        step["rtt_ms"] = round((a["time"] - b["time"]) * 1000, 1)
    if a["p_abort"] is not None:
        step.update(result="tcap_abort", p_abort_cause=a["p_abort"], explained=explain("tcap_abort", a["p_abort"]))
    elif a["component"] == 3:
        step.update(result="error", error_code=a["local"], explained=explain("map", a["local"]))
        if a["failure_cause"] is not None:
            step["delivery_failure_cause"] = DELIVERY_FAILURE.get(a["failure_cause"], a["failure_cause"])
        if a["absent_diag"] is not None:
            step["absent_subscriber_diagnostic"] = a["absent_diag"]
    elif a["component"] == 4:
        step["result"] = "reject"
    else:
        step["result"] = "ok"
        if d["op"] == 45 and a["imsi"]:
            step["routed_to_imsi"] = a["imsi"]
    return step


def map_attempts(rows: list[dict[str, Any]], explain: Callable[..., Any], capture_end: float | None) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    open_by_msisdn: dict[str, dict[str, Any]] = {}
    open_by_imsi: dict[str, dict[str, Any]] = {}
    for d in _dialogues(rows):
        b = d["begin"]
        t = b["time"] or 0.0
        step = _map_step(d, explain, capture_end)
        attempt = None
        if d["op"] in (44, 63, 64, 66) and b["imsi"] and b["imsi"] in open_by_imsi:
            attempt = open_by_imsi[b["imsi"]]
        elif d["op"] in (47, 64) and b["msisdn"] and b["msisdn"] in open_by_msisdn:
            attempt = open_by_msisdn[b["msisdn"]]
        if attempt is not None and t - attempt["_t"] > JOIN_WINDOW_S:
            attempt = None
        if attempt is None:
            attempt = {"path": "map", "direction": "mo" if d["op"] == 46 else "mt", "first_frame": b["frame"],
                       "time": iso(b["time"]), "imsi": b["imsi"], "msisdn": b["msisdn"] if d["op"] in (45, 47) else None,
                       "steps": [], "_t": t}
            attempts.append(attempt)
        attempt["steps"].append(step)
        if step.get("routed_to_imsi"):
            attempt["imsi"] = attempt["imsi"] or step["routed_to_imsi"]
        if attempt["msisdn"]:
            open_by_msisdn[attempt["msisdn"]] = attempt
        if attempt["imsi"]:
            open_by_imsi[attempt["imsi"]] = attempt
    for a in attempts:
        a.pop("_t", None)
        a.update(_map_verdict(a["steps"]))
    return attempts


def _map_verdict(steps: list[dict[str, Any]]) -> dict[str, Any]:
    forward = [s for s in steps if s["step"] in ("mt-forwardSM", "mo-forwardSM")]
    sri = next((s for s in steps if s["step"] == "sendRoutingInfoForSM"), None)
    failed = next((s for s in steps if s["result"] in ("error", "tcap_abort", "reject")), None)
    out: dict[str, Any] = {}
    if forward and forward[-1]["result"] == "ok":
        out["verdict"] = "delivered"
    elif failed is not None:
        code = failed.get("error_code")
        out["verdict"] = "absent_subscriber" if code in ABSENT_ERRORS else "rejected"
        name = (failed.get("explained") or {}).get("name")
        why = f"{failed['step']} answered " + (f"error {code}" + (f" {name}" if name else "") if code is not None
                                                else failed["result"].replace("_", " "))
        if failed.get("delivery_failure_cause") is not None:
            why += f" ({failed['delivery_failure_cause']})"
        out["reasons"] = [f"{why} at frame {failed['answer_frame']}"]
        out["ref"] = (failed.get("explained") or {}).get("ref")
    else:
        last = steps[-1]
        out["verdict"] = "in_progress" if last["result"] == "in_progress" else "no_response"
        out["reasons"] = [f"{last['step']} at frame {last['frame']} got no answer"]
    if sri is not None and sri["result"] == "ok" and not forward:
        out.setdefault("reasons", []).append("routing info returned but no forwardSM followed in the capture")
    if any(s["step"] == "reportSM-DeliveryStatus" for s in steps):
        out.setdefault("reasons", []).append("the SMSC reported the delivery status to the HLR (message waiting)")
    return {k: v for k, v in out.items() if v is not None}


# ------------------------------------------------------------------ SGs
def _sgs_step(r: dict[str, Any], explain: Callable[..., Any]) -> dict[str, Any]:
    step: dict[str, Any] = {"step": SGS_MESSAGES.get(r["sgs"], f"SGsAP 0x{r['sgs']:02x}"), "frame": r["frame"],
                            "time": iso(r["time"]), "from": r["src"], "to": r["dst"]}
    if r["service_indicator"] is not None:
        step["service_indicator"] = {1: "CS call", 2: "SMS"}.get(r["service_indicator"], r["service_indicator"])
    if r["sgs_cause"] is not None:
        step.update(sgs_cause=r["sgs_cause"], explained=explain("sgsap", r["sgs_cause"]))
    if r["cp"] is not None:
        step["cp"] = CP_TYPES.get(r["cp"], r["cp"])
        if r["cp_cause"] is not None:
            step.update(cp_cause=r["cp_cause"], explained=explain("cp", r["cp_cause"]))
    if r["rp"] is not None:
        step["rp"] = RP_TYPES.get(r["rp"], r["rp"])
        if r["rp_mr"] is not None:
            step["rp_mr"] = r["rp_mr"]
        if r["rp_cause"] is not None:
            step.update(rp_cause=r["rp_cause"], explained=explain("rp", r["rp_cause"]))
    if r["tp_mti"] is not None:
        mo = r["rp"] in (0, 2, 4)
        names = {0: "SMS-DELIVER-REPORT", 1: "SMS-SUBMIT", 2: "SMS-COMMAND"} if mo else \
            {0: "SMS-DELIVER", 1: "SMS-SUBMIT-REPORT", 2: "SMS-STATUS-REPORT"}
        step["tpdu"] = names.get(r["tp_mti"], r["tp_mti"])
        if r["tp_mr"] is not None:
            step["tp_mr"] = r["tp_mr"]
    return step


def sgs_attempts(rows: list[dict[str, Any]], explain: Callable[..., Any], capture_end: float | None) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    current: dict[str, dict[str, Any]] = {}
    for r in rows:
        if r["sgs"] is None or not r["imsi"]:
            continue
        sms_paging = r["sgs"] == 0x01 and r["service_indicator"] == 2
        starts_data = r["cp"] == 1 and r["rp"] in (0, 1)
        att = current.get(r["imsi"])
        if att is not None and att.get("_done") and (sms_paging or starts_data):
            att = None
        if att is None and (sms_paging or starts_data):
            att = {"path": "sgs", "direction": "mo" if r["rp"] == 0 else "mt", "first_frame": r["frame"],
                   "time": iso(r["time"]), "imsi": r["imsi"], "steps": [], "_t": r["time"]}
            attempts.append(att)
            current[r["imsi"]] = att
        if att is None:
            continue
        att["steps"].append(_sgs_step(r, explain))
        if r["rp"] in (2, 3, 4, 5) or r["sgs"] == 0x02 or r["cp"] == 16:
            att["_done"] = True
    for a in attempts:
        a.update(_sgs_verdict(a, capture_end))
        a.pop("_t", None)
        a.pop("_done", None)
    return attempts


def _sgs_verdict(att: dict[str, Any], capture_end: float | None) -> dict[str, Any]:
    steps = att["steps"]
    for s in steps:
        if s["step"] == "PAGING-REJECT":
            name = (s.get("explained") or {}).get("name")
            return {"verdict": "paging_failed", "reasons": [f"PAGING-REJECT SGs cause {s.get('sgs_cause')}"
                                                             + (f" {name}" if name else "") + f" at frame {s['frame']}"],
                    "ref": (s.get("explained") or {}).get("ref")}
        if s.get("rp", "").startswith("RP-ERROR") or s.get("cp") == "CP-ERROR":
            cause = s.get("rp_cause", s.get("cp_cause"))
            name = (s.get("explained") or {}).get("name")
            layer = "RP-ERROR" if "rp_cause" in s else "CP-ERROR"
            return {"verdict": "rejected", "reasons": [f"{layer} cause {cause}" + (f" {name}" if name else "")
                                                       + f" at frame {s['frame']}"],
                    "ref": (s.get("explained") or {}).get("ref")}
        if s.get("rp", "").startswith("RP-ACK"):
            return {"verdict": "delivered"}
    last_t = att.get("_t")
    left = None if capture_end is None or last_t is None else capture_end - last_t
    last = steps[-1]
    verdict = "in_progress" if left is not None and left < ANSWER_WINDOW_S else "no_response"
    what = "paging got no service request" if last["step"] == "PAGING-REQUEST" else f"no RP-ACK after frame {last['frame']}"
    return {"verdict": verdict, "reasons": [what]}


def select(attempts: list[dict[str, Any]], imsi: str | None, msisdn: str | None, path: str | None
           ) -> list[dict[str, Any]]:
    out = []
    for a in attempts:
        if imsi and a.get("imsi") != imsi:
            continue
        if msisdn and (a.get("msisdn") or "").lstrip("+") != msisdn.lstrip("+"):
            continue
        if path and a["path"] != path:
            continue
        out.append({k: v for k, v in a.items() if v is not None})
    return out


def summary(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    verdicts: dict[str, int] = {}
    paths: dict[str, int] = {}
    for a in attempts:
        verdicts[a["verdict"]] = verdicts.get(a["verdict"], 0) + 1
        paths[a["path"]] = paths.get(a["path"], 0) + 1
    return {"attempts": len(attempts), "verdicts": verdicts, "paths": paths}
