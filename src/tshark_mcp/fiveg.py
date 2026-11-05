"""5G SA registration and PDU sessions per UE across N1/N2 (NGAP + NAS-5GS), N4 (PFCP), N3
(GTP-U) and, when readable, the SBI calls (:mod:`tshark_mcp.sbi`).

A UE is one NGAP UE association: the RAN-UE-NGAP-ID the gNB gave it in the Initial UE
Message, joined with the AMF-UE-NGAP-ID of the first downlink message. Per UE:

* ``registration``: Registration Request attempts, authentication (request, response,
  failure with its 5GMM cause, reject), Registration Accept or Reject with the 5GMM cause
  explained, and the time from the first request to the outcome;
* ``pdu_sessions`` keyed by PDU session id: the NAS PDU Session Establishment Request (DNN
  from the UL NAS Transport), Accept or Reject with the 5GSM cause; the NGAP PDU Session
  Resource Setup Request (QoS flows with QFI and 5QI, the UPF's N3 F-TEID) and Response (the
  gNB's N3 F-TEID); the PFCP Session Establishment that created the UPF F-TEID (paired by
  sequence number, matched to the session by that TEID, else by DNN and time) with its cause;
  ``n3_consistent`` (PFCP and NGAP name the same UPF TEID and address); GTP-U packets and
  bytes on both TEIDs; and ``first_failure``;
* ``vonr`` when a PDU session's DNN starts with "ims": IMS session established, a 5QI 5
  flow (IMS signalling), a 5QI 1 flow (voice) and what a missing one means.

NAS with a security header (integrity protected and ciphered, types 2 and 4) is counted in
``ciphered_nas`` and never guessed. The SUCI keeps its MCC, MNC, routing indicator and
protection scheme; with the null scheme the SUPI (MCC, MNC, MSIN) is returned under ``supi``,
which redaction treats as an IMSI.

Limits: one PDU session per NGAP PDU Session Resource Setup message is read (several in one
message are attributed to the first); PDU Session Resource Modify (a 5QI 1 flow added during
a call) and handovers are not read yet.
"""

from __future__ import annotations

from typing import Any, Callable

from .fields import iso, to_float, to_int

AGGREGATOR = "|"
NG_FILTER = "ngap"
NG_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ngap.NGAP_PDU", "ngap.procedureCode",
    "ngap.AMF_UE_NGAP_ID", "ngap.RAN_UE_NGAP_ID", "nas-5gs.security_header_type", "nas-5gs.mm.message_type",
    "nas-5gs.sm.message_type", "nas-5gs.mm.5gmm_cause", "nas-5gs.sm.5gsm_cause", "nas-5gs.pdu_session_id",
    "nas-5gs.cmn.dnn", "ngap.pDUSessionID", "ngap.qosFlowIdentifier", "ngap.fiveQI", "ngap.gTP_TEID",
    "ngap.TransportLayerAddressIPv4", "ngap.radioNetwork", "nas-5gs.mm.suci.msin", "e212.mcc", "e212.mnc",
    "nas-5gs.mm.suci.routing_indicator", "nas-5gs.mm.suci.scheme_id",
]
PFCP_FILTER = "pfcp.msg_type == 50 || pfcp.msg_type == 51"
PFCP_FIELDS = ["frame.number", "frame.time_epoch", "pfcp.msg_type", "pfcp.seqno", "pfcp.cause", "pfcp.f_teid.teid",
               "pfcp.f_teid.ipv4_addr", "pfcp.apn_dnn", "pfcp.ue_ip_addr_ipv4"]
GTPU_FILTER = "gtp.message == 255"
GTPU_FIELDS = ["gtp.teid", "frame.len", "ip.src", "ip.dst"]

MM = {0x41: "Registration Request", 0x42: "Registration Accept", 0x43: "Registration Complete",
      0x44: "Registration Reject", 0x45: "Deregistration Request (UE)", 0x46: "Deregistration Accept (UE)",
      0x47: "Deregistration Request (network)", 0x48: "Deregistration Accept (network)",
      0x4C: "Service Request", 0x4D: "Service Reject", 0x4E: "Service Accept",
      0x56: "Authentication Request", 0x57: "Authentication Response", 0x58: "Authentication Reject",
      0x59: "Authentication Failure", 0x5B: "Identity Request", 0x5C: "Identity Response",
      0x5D: "Security Mode Command", 0x5E: "Security Mode Complete", 0x5F: "Security Mode Reject",
      0x64: "5GMM Status", 0x67: "UL NAS Transport", 0x68: "DL NAS Transport"}
SM = {0xC1: "PDU Session Establishment Request", 0xC2: "PDU Session Establishment Accept",
      0xC3: "PDU Session Establishment Reject", 0xC9: "PDU Session Modification Request",
      0xCB: "PDU Session Modification Command", 0xD1: "PDU Session Release Request",
      0xD3: "PDU Session Release Command", 0xD6: "5GSM Status"}
PFCP_CAUSES = {1: "Request accepted", 64: "Request rejected", 65: "Session context not found",
               66: "Mandatory IE missing", 67: "Conditional IE missing", 68: "Invalid length",
               69: "Mandatory IE incorrect", 70: "Invalid Forwarding Policy", 71: "Invalid F-TEID allocation option",
               72: "No established PFCP Association", 73: "Rule creation/modification Failure",
               74: "PFCP entity in congestion", 75: "No resources available", 76: "Service not supported",
               77: "System failure", 78: "Redirection Requested"}
SCHEMES = {"0": "null", "1": "profile A", "2": "profile B"}
IN_PROGRESS_S = 5.0


def _rows(stdout: str, fields: list[str]) -> list[dict[str, list[str]]]:
    out = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t") + [""] * len(fields)
        out.append({f: [v for v in parts[i].split(AGGREGATOR) if v != ""] for i, f in enumerate(fields)})
    return out


def _first(rec: dict[str, list[str]], field: str) -> str | None:
    vals = rec.get(field) or []
    return vals[0] if vals else None


def _hex_int(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") or any(c in "abcdef" for c in text) or len(text) == 8 else int(text)
    except ValueError:
        return None


def _code(value: str | None) -> int | None:
    return _hex_int(value) if value and value.lower().startswith("0x") else to_int(value)


def _teid(value: int | None) -> str | None:
    return None if value is None else f"0x{value:08x}"


def _new_ue(ran: int, gnb: str | None, frame: int, t: float | None) -> dict[str, Any]:
    return {"ran_ue_ngap_id": ran, "gnb": gnb, "first_frame": frame, "_t0": t, "amf_ue_ngap_id": None,
            "registration": {"attempts": 0, "authentication": None, "outcome": None},
            "_sessions": {}, "ciphered_nas": 0, "_events": []}


def _session(ue: dict[str, Any], psi: int) -> dict[str, Any]:
    return ue["_sessions"].setdefault(psi, {"pdu_session_id": psi, "dnn": None, "outcome": None, "steps": []})


def parse_ngap(stdout: str, explain: Callable[[str, int], Any]) -> list[dict[str, Any]]:
    """UEs with registration and PDU session facts from NGAP and the NAS inside it."""
    ues: dict[tuple[str | None, int], dict[str, Any]] = {}
    by_amf: dict[int, tuple[str | None, int]] = {}
    for rec in _rows(stdout, NG_FIELDS):
        frame = to_int(_first(rec, "frame.number"))
        t = to_float(_first(rec, "frame.time_epoch"))
        proc = to_int(_first(rec, "ngap.procedureCode"))
        pdu = to_int(_first(rec, "ngap.NGAP_PDU"))
        ran = to_int(_first(rec, "ngap.RAN_UE_NGAP_ID"))
        amf = to_int(_first(rec, "ngap.AMF_UE_NGAP_ID"))
        src, dst = _first(rec, "ip.src"), _first(rec, "ip.dst")
        if frame is None or (ran is None and amf is None):
            continue
        uplink = proc in (15, 46) or (proc == 29 and pdu in (1, 2))
        gnb = src if uplink else dst
        key = (gnb, ran) if ran is not None else by_amf.get(amf)  # type: ignore[arg-type]
        if key is None:
            continue
        if key not in ues:
            if proc != 15 and ran is None:
                continue
            ues[key] = _new_ue(key[1], gnb, frame, t)
        ue = ues[key]
        if amf is not None:
            ue["amf_ue_ngap_id"] = ue["amf_ue_ngap_id"] if ue["amf_ue_ngap_id"] is not None else amf
            by_amf.setdefault(amf, key)
        ue["last_frame"] = frame
        # SUCI (Registration Request): routing parts, and the SUPI when the null scheme carries the MSIN.
        msin = _first(rec, "nas-5gs.mm.suci.msin")
        mcc, mnc = _first(rec, "e212.mcc"), _first(rec, "e212.mnc")
        if mcc and "suci" not in ue and (msin or _first(rec, "nas-5gs.mm.suci.routing_indicator")):
            scheme = _first(rec, "nas-5gs.mm.suci.scheme_id")
            ue["suci"] = {"mcc": mcc.zfill(3), "mnc": (mnc or "").zfill(2), "routing_indicator":
                          _first(rec, "nas-5gs.mm.suci.routing_indicator"),
                          "protection_scheme": SCHEMES.get(str(to_int(scheme) if scheme else 0), scheme)}
            if msin:
                ue["supi"] = f"{mcc.zfill(3)}{(mnc or '').zfill(2)}{msin}"
        sec = [to_int(x) for x in rec["nas-5gs.security_header_type"]]
        if any(s in (2, 4) for s in sec) and not rec["nas-5gs.mm.message_type"]:
            ue["ciphered_nas"] += 1
        mm = [_code(x) for x in rec["nas-5gs.mm.message_type"]]
        sm = [_code(x) for x in rec["nas-5gs.sm.message_type"]]
        mm_cause = to_int(_first(rec, "nas-5gs.mm.5gmm_cause"))
        sm_cause = to_int(_first(rec, "nas-5gs.sm.5gsm_cause"))
        psi = to_int(_first(rec, "nas-5gs.pdu_session_id"))
        dnn = _first(rec, "nas-5gs.cmn.dnn")
        reg = ue["registration"]
        for m in mm:
            name = MM.get(m)
            if name and m not in (0x67, 0x68):
                ue["_events"].append({"frame": frame, "time": t, "message": name})
            if m == 0x41:
                reg["attempts"] += 1
                reg.setdefault("first_request_frame", frame)
                reg.setdefault("_t", t)
            elif m == 0x56:
                reg["authentication"] = reg.get("authentication") or "challenged"
                reg.setdefault("auth_request_frame", frame)
            elif m == 0x57:
                reg["authentication"] = "answered"
            elif m == 0x59:
                reg["authentication"] = "failed"
                reg["auth_failure"] = {"frame": frame, "cause": mm_cause, "explained": explain("5gmm", mm_cause)
                                       if mm_cause is not None else None}
            elif m == 0x58:
                reg["authentication"] = "rejected by the network"
                reg["auth_reject_frame"] = frame
            elif m == 0x42:
                reg["outcome"] = "accepted"
                reg["outcome_frame"] = frame
            elif m == 0x44:
                reg["outcome"] = "rejected"
                reg["outcome_frame"] = frame
                reg["cause"] = mm_cause
                if mm_cause is not None:
                    reg["cause_explained"] = explain("5gmm", mm_cause)
            if m in (0x42, 0x44) and reg.get("_t") is not None and t is not None:
                reg["timing_ms"] = round((t - reg["_t"]) * 1000, 1)
        for m in sm:
            if psi is None:
                continue
            s = _session(ue, psi)
            s["steps"].append({"frame": frame, "message": SM.get(m, f"5GSM 0x{m:02x}" if m is not None else "5GSM")})
            if m == 0xC1:
                s.setdefault("request_frame", frame)
                s.setdefault("_t", t)
                if dnn:
                    s["dnn"] = s["dnn"] or dnn
            elif m == 0xC2:
                s["outcome"] = "accepted"
                s["accept_frame"] = frame
                if dnn and not s["dnn"]:
                    s["dnn"] = dnn
            elif m == 0xC3:
                s["outcome"] = "rejected"
                s["reject_frame"] = frame
                s["cause"] = sm_cause
                if sm_cause is not None:
                    s["cause_explained"] = explain("5gsm", sm_cause)
        if proc == 29:
            psis = [to_int(x) for x in rec["ngap.pDUSessionID"]]
            if not psis:
                continue
            s = _session(ue, psis[0])
            teids = [_hex_int(x) for x in rec["ngap.gTP_TEID"]]
            addrs = rec["ngap.TransportLayerAddressIPv4"]
            if pdu == 0:
                qfis = [to_int(x) for x in rec["ngap.qosFlowIdentifier"]]
                fives = [to_int(x) for x in rec["ngap.fiveQI"]]
                s["ngap_setup"] = {"request_frame": frame, "upf_teid": _teid(teids[0] if teids else None),
                                   "upf_address": addrs[0] if addrs else None,
                                   "qos_flows": [{"qfi": q, "five_qi": f} for q, f in zip(qfis, fives)]}
                s["_ngap_teid"] = teids[0] if teids else None
                s["steps"].append({"frame": frame, "message": "PDU Session Resource Setup Request"})
            else:
                setup = s.setdefault("ngap_setup", {})
                setup["response_frame"] = frame
                if pdu == 2 or rec["ngap.radioNetwork"]:
                    setup["failed"] = True
                    cause = to_int(_first(rec, "ngap.radioNetwork"))
                    if cause is not None:
                        setup["radio_network_cause"] = cause
                else:
                    setup["gnb_teid"] = _teid(teids[0] if teids else None)
                    setup["gnb_address"] = addrs[0] if addrs else None
                    s["_gnb_teid"] = teids[0] if teids else None
                s["steps"].append({"frame": frame, "message": "PDU Session Resource Setup "
                                                              + ("Failure" if setup.get("failed") else "Response")})
    return list(ues.values())


def parse_pfcp(stdout: str) -> list[dict[str, Any]]:
    """PFCP Session Establishments: request and response paired by sequence number."""
    reqs: dict[int, dict[str, Any]] = {}
    out: list[dict[str, Any]] = []
    for rec in _rows(stdout, PFCP_FIELDS):
        frame = to_int(_first(rec, "frame.number"))
        mtype = to_int(_first(rec, "pfcp.msg_type"))
        seq = to_int(_first(rec, "pfcp.seqno"))
        t = to_float(_first(rec, "frame.time_epoch"))
        if frame is None or seq is None:
            continue
        if mtype == 50:
            item = {"request_frame": frame, "_t": t, "seq": seq, "dnn": _first(rec, "pfcp.apn_dnn"),
                    "ue_ip": _first(rec, "pfcp.ue_ip_addr_ipv4"), "_used": False}
            reqs[seq] = item
            out.append(item)
        elif mtype == 51:
            item = reqs.get(seq)
            if item is None:
                continue
            cause = to_int(_first(rec, "pfcp.cause"))
            item.update(response_frame=frame, cause=cause, cause_name=PFCP_CAUSES.get(cause) if cause else None,
                        upf_teid=_hex_int(_first(rec, "pfcp.f_teid.teid")), upf_address=_first(rec, "pfcp.f_teid.ipv4_addr"))
            if item["ue_ip"] is None:
                item["ue_ip"] = _first(rec, "pfcp.ue_ip_addr_ipv4")
    return out


def parse_gtpu(stdout: str) -> dict[int, dict[str, int]]:
    counts: dict[int, dict[str, int]] = {}
    for rec in _rows(stdout, GTPU_FIELDS):
        teid = _hex_int(_first(rec, "gtp.teid"))
        if teid is None:
            continue
        c = counts.setdefault(teid, {"packets": 0, "bytes": 0})
        c["packets"] += 1
        c["bytes"] += to_int(_first(rec, "frame.len")) or 0
    return counts


def _match_pfcp(s: dict[str, Any], pfcp: list[dict[str, Any]]) -> dict[str, Any] | None:
    teid = s.get("_ngap_teid")
    if teid is not None:
        for p in pfcp:
            if not p["_used"] and p.get("upf_teid") == teid:
                return p
    t = s.get("_t")
    best = None
    for p in pfcp:
        if p["_used"] or t is None or p.get("_t") is None:
            continue
        if not (0 <= p["_t"] - t <= 10.0):
            continue
        if s.get("dnn") and p.get("dnn") and s["dnn"].lower() != p["dnn"].lower():
            continue
        if best is None or p["_t"] < best["_t"]:
            best = p
    return best


def assemble(ues: list[dict[str, Any]], pfcp: list[dict[str, Any]], gtpu: dict[int, dict[str, int]],
             capture_end: float | None, sbi_rows: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Join PFCP, GTP-U and SBI into the UEs and judge each UE."""
    out = []
    for ue in ues:
        sessions = []
        for psi in sorted(ue["_sessions"]):
            s = ue["_sessions"][psi]
            p = _match_pfcp(s, pfcp)
            if p is not None:
                p["_used"] = True
                s["pfcp"] = {k: v for k, v in {
                    "request_frame": p["request_frame"], "response_frame": p.get("response_frame"),
                    "cause": p.get("cause"), "cause_name": p.get("cause_name"),
                    "upf_teid": _teid(p.get("upf_teid")), "upf_address": p.get("upf_address"),
                    "ue_ip": p.get("ue_ip")}.items() if v is not None}
                s["steps"].append({"frame": p["request_frame"], "message": "PFCP Session Establishment Request"})
                if p.get("response_frame"):
                    s["steps"].append({"frame": p["response_frame"], "message": "PFCP Session Establishment Response"
                                       + (f" ({p.get('cause_name') or p.get('cause')})" if p.get("cause") != 1 else "")})
                ng = s.get("ngap_setup") or {}
                if p.get("upf_teid") is not None and s.get("_ngap_teid") is not None:
                    s["n3_consistent"] = (p["upf_teid"] == s["_ngap_teid"]
                                          and (not p.get("upf_address") or not ng.get("upf_address")
                                               or p["upf_address"] == ng["upf_address"]))
            ul, dl = s.get("_ngap_teid"), s.get("_gnb_teid")
            if ul is not None or dl is not None:
                s["n3_traffic"] = {"uplink": gtpu.get(ul, {"packets": 0, "bytes": 0}) if ul is not None else None,
                                   "downlink": gtpu.get(dl, {"packets": 0, "bytes": 0}) if dl is not None else None}
            if sbi_rows:
                calls = [r for r in sbi_rows if ue.get("supi") and r.get("supi") == ue["supi"]
                         and str(r.get("pdu_session_id", psi)) == str(psi)]
                if calls:
                    s["sbi_calls"] = [{k: r.get(k) for k in ("operation", "producer", "status", "cause", "request_frame",
                                                             "response_frame") if r.get(k) is not None} for r in calls]
            s["steps"].sort(key=lambda x: x["frame"])
            s["first_failure"] = _session_failure(s, capture_end)
            if s["outcome"] is None:
                s["outcome"] = "failed" if s["first_failure"] else ("in_progress" if capture_end is not None and s.get("_t") is not None
                                and capture_end - s["_t"] < IN_PROGRESS_S else "no_answer")
            sessions.append({k: v for k, v in s.items() if not k.startswith("_") and v is not None})
        row: dict[str, Any] = {k: ue.get(k) for k in ("ran_ue_ngap_id", "amf_ue_ngap_id", "gnb", "supi", "suci",
                                                     "first_frame", "last_frame")}
        reg = {k: v for k, v in ue["registration"].items() if not k.startswith("_") and v is not None}
        row["registration"] = reg
        row["pdu_sessions"] = sessions
        if ue["ciphered_nas"]:
            row["ciphered_nas"] = ue["ciphered_nas"]
        vonr = _vonr(sessions)
        if vonr:
            row["vonr"] = vonr
        row["first_failure"] = _ue_failure(reg, sessions)
        row["verdict"] = _verdict(row)
        out.append({k: v for k, v in row.items() if v is not None})
    return out


def _session_failure(s: dict[str, Any], capture_end: float | None) -> dict[str, Any] | None:
    p = s.get("pfcp") or {}
    if p.get("cause") not in (None, 1):
        return {"step": "pfcp_establishment", "frame": p.get("response_frame"), "cause": p.get("cause"),
                "cause_name": p.get("cause_name"),
                "meaning": "the UPF refused the session (N4); the SMF cannot build the user plane"}
    if s.get("outcome") == "rejected":
        return {"step": "pdu_session_establishment", "frame": s.get("reject_frame"), "cause": s.get("cause"),
                "explained": s.get("cause_explained")}
    ng = s.get("ngap_setup") or {}
    if ng.get("failed"):
        return {"step": "ngap_pdu_session_resource_setup", "frame": ng.get("response_frame"),
                "radio_network_cause": ng.get("radio_network_cause"), "meaning": "the gNB could not set up the resources"}
    if s.get("n3_consistent") is False:
        return {"step": "n3_tunnel", "frame": ng.get("request_frame"),
                "meaning": f"the AMF/SMF sent the gNB UPF TEID {ng.get('upf_teid')} but PFCP created "
                           f"{p.get('upf_teid')}: uplink user plane goes to a tunnel the UPF does not know"}
    if s.get("request_frame") and not s.get("outcome") and not ng:
        return {"step": "pdu_session_establishment", "frame": s.get("request_frame"),
                "meaning": "no PDU Session Establishment Accept or Reject in the capture"}
    return None


def _ue_failure(reg: dict[str, Any], sessions: list[dict[str, Any]]) -> dict[str, Any] | None:
    if reg.get("outcome") == "rejected":
        out = {"step": "registration", "frame": reg.get("outcome_frame"), "cause": reg.get("cause"),
               "explained": reg.get("cause_explained")}
        if reg.get("auth_failure"):
            out["after"] = {"step": "authentication_failure", **{k: v for k, v in reg["auth_failure"].items() if v is not None}}
        return out
    if reg.get("authentication") == "rejected by the network":
        return {"step": "authentication", "frame": reg.get("auth_reject_frame")}
    for s in sessions:
        if s.get("first_failure"):
            return {"pdu_session_id": s["pdu_session_id"], **s["first_failure"]}
    return None


def _vonr(sessions: list[dict[str, Any]]) -> dict[str, Any] | None:
    ims = [s for s in sessions if (s.get("dnn") or "").lower().startswith("ims")]
    if not ims:
        return None
    s = ims[0]
    fives = [f.get("five_qi") for f in (s.get("ngap_setup") or {}).get("qos_flows", [])]
    out = {"ims_pdu_session": s["pdu_session_id"], "ims_session_established": s.get("outcome") == "accepted",
           "five_qi_5": 5 in fives, "five_qi_1": 1 in fives}
    if not out["ims_session_established"]:
        out["assessment"] = "the IMS PDU session is not up: no VoNR (and no IMS registration) is possible"
    elif not out["five_qi_5"]:
        out["assessment"] = "the IMS PDU session has no 5QI 5 flow for IMS signalling: check the PCF/SMF policy"
    elif not out["five_qi_1"]:
        out["assessment"] = ("no 5QI 1 voice flow was set up in the capture. A VoNR call needs one, requested by the "
                             "PCF through the SMF when the call starts (PDU Session Resource Modify): if a call was "
                             "attempted, look at PCF/SMF policy, not the RAN; without a call this is expected")
    else:
        out["assessment"] = "IMS PDU session with 5QI 5 and a 5QI 1 voice flow"
    return out


def _verdict(row: dict[str, Any]) -> str:
    ff = row.get("first_failure")
    reg = row.get("registration") or {}
    if ff:
        if ff.get("step") == "registration":
            name = (ff.get("explained") or {}).get("name") or f"cause {ff.get('cause')}"
            after = ""
            if ff.get("after"):
                aname = ((ff["after"].get("explained") or {}).get("name")) or f"cause {ff['after'].get('cause')}"
                after = f" after Authentication Failure {aname} (frame {ff['after'].get('frame')})"
            return f"registration rejected: {name} (frame {ff.get('frame')}){after}"
        where = f"PDU session {ff.get('pdu_session_id')}: " if ff.get("pdu_session_id") is not None else ""
        if ff.get("step") == "pfcp_establishment":
            return f"{where}PFCP Session Establishment rejected, {ff.get('cause_name') or ff.get('cause')} (frame {ff.get('frame')})"
        if ff.get("step") == "pdu_session_establishment" and ff.get("cause") is not None:
            name = (ff.get("explained") or {}).get("name") or f"cause {ff.get('cause')}"
            return f"{where}PDU Session Establishment Reject {name} (frame {ff.get('frame')})"
        return f"{where}{ff.get('meaning')} (frame {ff.get('frame')})"
    if reg.get("outcome") == "accepted":
        up = [s for s in row.get("pdu_sessions", []) if s.get("outcome") == "accepted"]
        tail = f"; {len(up)} PDU session(s) up" if up else "; no PDU session"
        if row.get("vonr") and not row["vonr"].get("five_qi_1"):
            tail += "; IMS session without a 5QI 1 voice flow"
        return f"registered (frame {reg.get('outcome_frame')}){tail}"
    if reg.get("attempts"):
        return f"registration not completed in the capture ({reg['attempts']} attempt(s))"
    return "UE context without a Registration Request in the capture"


def summary(rows: list[dict[str, Any]], pfcp: list[dict[str, Any]]) -> dict[str, Any]:
    reg: dict[str, int] = {}
    sess: dict[str, int] = {}
    for r in rows:
        o = (r.get("registration") or {}).get("outcome") or "none"
        reg[o] = reg.get(o, 0) + 1
        for s in r.get("pdu_sessions", []):
            sess[s["outcome"]] = sess.get(s["outcome"], 0) + 1
    unmatched = [p["request_frame"] for p in pfcp if not p["_used"]]
    out: dict[str, Any] = {"ues": len(rows), "registrations": reg, "pdu_sessions": sess,
                           "n3_inconsistent": sum(1 for r in rows for s in r.get("pdu_sessions", [])
                                                  if s.get("n3_consistent") is False)}
    if unmatched:
        out["pfcp_unmatched_frames"] = unmatched[:20]
    return out


def capture_time(ts: float | None) -> str | None:
    return iso(ts)
