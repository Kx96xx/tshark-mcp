"""nas_procedures: EMM and ESM procedures per UE from S1AP and NAS EPS.

One ``-T fields`` pass over ``s1ap`` gives a row per S1AP message with the UE S1AP id
pair, the S1AP procedure and cause, and the NAS EPS message it carries (EMM and ESM
type, causes, security header, IMSI, GUTI M-TMSI). Messages are grouped into S1 UE
contexts (an InitialUEMessage opens one, the UE Context Release Complete closes it),
contexts into UEs (same IMSI, or the M-TMSI an Attach or TAU Accept assigned and a later
S-TMSI or GUTI names) and each UE's messages into procedures with an outcome, cause and
timing. Content-free: identities, codes, timings and frame numbers only; never the
authentication vectors, keys or the ESM APN and PCO contents.
"""

from __future__ import annotations

from typing import Any, Callable

from .fields import iso, parse_time, split_fields_line, to_int

FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "s1ap.S1AP_PDU", "s1ap.procedureCode", "s1ap.MME_UE_S1AP_ID", "s1ap.ENB_UE_S1AP_ID",
    "s1ap.radioNetwork", "s1ap.transport", "s1ap.nas", "s1ap.protocol", "s1ap.misc", "s1ap.HandoverType",
    "s1ap.m_TMSI", "s1ap.mMEC",
    "nas-eps.security_header_type", "nas-eps.nas_msg_emm_type", "nas-eps.nas_msg_esm_type",
    "nas-eps.emm.cause", "nas-eps.esm.cause", "e212.imsi", "nas-eps.emm.m_tmsi", "nas-eps.emm.mme_code",
    "nas-eps.emm.toc", "nas-eps.bearer_id", "nas-eps.emm.eps_att_type",
]
_IX = {name: i for i, name in enumerate(FIELDS)}
CAUSE_GROUPS = ("radioNetwork", "transport", "nas", "protocol", "misc")

PREF_NULL_DECIPHER_ON = "nas-eps.null_decipher:TRUE"
PREF_NULL_DECIPHER_OFF = "nas-eps.null_decipher:FALSE"

S1AP_PROCEDURES = {
    0: "handoverPreparation", 1: "handoverResourceAllocation", 2: "handoverNotification", 3: "pathSwitchRequest",
    4: "handoverCancel", 5: "E-RABSetup", 6: "E-RABModify", 7: "E-RABRelease", 8: "E-RABReleaseIndication",
    9: "initialContextSetup", 10: "paging", 11: "downlinkNASTransport", 12: "initialUEMessage",
    13: "uplinkNASTransport", 16: "NASNonDeliveryIndication", 18: "UEContextReleaseRequest",
    21: "UEContextModification", 22: "UECapabilityInfoIndication", 23: "UEContextRelease",
}
_PDU = {0: "initiating", 1: "successful", 2: "unsuccessful"}
_S1AP_MESSAGES = {
    (0, 0): "HandoverRequired", (0, 1): "HandoverCommand", (0, 2): "HandoverPreparationFailure",
    (2, 0): "HandoverNotify", (3, 0): "PathSwitchRequest", (3, 1): "PathSwitchRequestAcknowledge",
    (3, 2): "PathSwitchRequestFailure", (4, 0): "HandoverCancel", (4, 1): "HandoverCancelAcknowledge",
    (9, 0): "InitialContextSetupRequest", (9, 1): "InitialContextSetupResponse",
    (9, 2): "InitialContextSetupFailure", (10, 0): "Paging", (18, 0): "UEContextReleaseRequest",
    (23, 0): "UEContextReleaseCommand", (23, 1): "UEContextReleaseComplete",
    (16, 0): "NASNonDeliveryIndication", (11, 0): "DownlinkNASTransport", (12, 0): "InitialUEMessage",
    (13, 0): "UplinkNASTransport",
}

EMM_MESSAGES = {
    0x41: "Attach request", 0x42: "Attach accept", 0x43: "Attach complete", 0x44: "Attach reject",
    0x45: "Detach request", 0x46: "Detach accept", 0x48: "Tracking area update request",
    0x49: "Tracking area update accept", 0x4A: "Tracking area update complete",
    0x4B: "Tracking area update reject", 0x4C: "Extended service request", 0x4D: "Control plane service request",
    0x4E: "Service reject", 0x4F: "Service accept", 0x50: "GUTI reallocation command",
    0x51: "GUTI reallocation complete", 0x52: "Authentication request", 0x53: "Authentication response",
    0x54: "Authentication reject", 0x55: "Identity request", 0x56: "Identity response",
    0x5C: "Authentication failure", 0x5D: "Security mode command", 0x5E: "Security mode complete",
    0x5F: "Security mode reject", 0x60: "EMM status", 0x61: "EMM information",
    0x62: "Downlink NAS transport", 0x63: "Uplink NAS transport", 0x64: "CS service notification",
    0x68: "Downlink generic NAS transport", 0x69: "Uplink generic NAS transport",
}
ESM_MESSAGES = {
    0xC1: "Activate default EPS bearer context request", 0xC2: "Activate default EPS bearer context accept",
    0xC3: "Activate default EPS bearer context reject", 0xC5: "Activate dedicated EPS bearer context request",
    0xC6: "Activate dedicated EPS bearer context accept", 0xC7: "Activate dedicated EPS bearer context reject",
    0xC9: "Modify EPS bearer context request", 0xCA: "Modify EPS bearer context accept",
    0xCB: "Modify EPS bearer context reject", 0xCD: "Deactivate EPS bearer context request",
    0xCE: "Deactivate EPS bearer context accept", 0xD0: "PDN connectivity request",
    0xD1: "PDN connectivity reject", 0xD2: "PDN disconnect request", 0xD3: "PDN disconnect reject",
    0xD4: "Bearer resource allocation request", 0xD5: "Bearer resource allocation reject",
    0xD6: "Bearer resource modification request", 0xD7: "Bearer resource modification reject",
    0xD9: "ESM information request", 0xDA: "ESM information response", 0xDB: "Notification",
    0xE8: "ESM status",
}
SECURITY = {0: "plain", 1: "integrity", 2: "ciphered", 3: "integrity_new_context", 4: "ciphered_new_context",
            12: "service_request"}
_CIPHERED = (2, 4)

# EMM procedures: the message that starts one and the ones that end it.
_EMM_START = {0x41: "attach", 0x48: "tau", 0x4C: "service_request", 0x4D: "service_request"}
_EMM_ACCEPT = {0x42: "attach", 0x49: "tau", 0x4F: "service_request", 0x46: "detach"}
_EMM_COMPLETE = {0x43: "attach", 0x4A: "tau"}
_EMM_REJECT = {0x44: "attach", 0x4B: "tau", 0x4E: "service_request", 0x54: None, 0x5F: None}
_ESM_START = {0xD0: "pdn_connectivity", 0xC5: "dedicated_bearer_activation", 0xC9: "bearer_modification",
              0xCD: "bearer_deactivation", 0xD2: "pdn_disconnect", 0xD4: "bearer_resource_allocation",
              0xD6: "bearer_resource_modification"}
_ESM_ACCEPT = {0xC2, 0xC6, 0xCA, 0xCE}
_ESM_REJECT = {0xC3, 0xC7, 0xCB, 0xD1, 0xD3, 0xD5, 0xD7}

# Seconds a procedure may stay unanswered before the capture end makes it "in_progress"
# rather than "abandoned": T3410 and T3430 (15 s), T3417 (5 s), T3421 (15 s), T3480-T3492 (8 s).
TIMERS_S = {"attach": 15.0, "tau": 15.0, "service_request": 5.0, "detach": 15.0, "handover": 10.0}
ESM_TIMER_S = 8.0
PAGING_WINDOW_S = 10.0
KINDS = ("attach", "tau", "service_request", "detach", "pdn_connectivity", "dedicated_bearer_activation",
         "bearer_modification", "bearer_deactivation", "pdn_disconnect", "bearer_resource_allocation",
         "bearer_resource_modification", "handover", "ue_context_release", "paging_response")

METHOD = {
    "ue": "S1 UE contexts (an InitialUEMessage opens one on its S1 association and eNB-UE-S1AP-ID, the MME "
          "id joins on the first downlink message, UE Context Release Complete closes it) joined into one UE by "
          "IMSI or by the M-TMSI an Attach or TAU Accept assigned and a later S-TMSI or GUTI names",
    "outcome": "accepted on the Accept (and Complete) or, for a service request, the Initial Context Setup "
               "Response; rejected on a Reject, a Setup or Preparation Failure or an Authentication or Security "
               "mode reject; abandoned when another procedure or a release came first or the timer ran out "
               "with no answer; in_progress when the capture ended within the NAS timer",
    "ciphered": "messages with security header 2 or 4 that tshark could not read; they are counted, not "
                "guessed, so the absence of an answer under ciphering is not a conclusion",
    "pending_paging": f"a Paging naming the UE's S-TMSI with no service request from it within {PAGING_WINDOW_S:g} s",
}


def _first(cell: str) -> str:
    return cell.split(",")[0].strip() if cell else ""


def _ints(cell: str) -> list[int]:
    out = []
    for part in (cell or "").split(","):
        value = to_int(part.strip())
        if value is not None:
            out.append(value)
    return out


def _int(cell: str) -> int | None:
    vals = _ints(cell)
    return vals[0] if vals else None


def parse(stdout: str) -> list[dict[str, Any]]:
    """One record per S1AP message."""
    rows: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        cells = split_fields_line(line)
        cells += [""] * (len(FIELDS) - len(cells))

        def c(name: str) -> str:
            return cells[_IX[name]]
        frame = _int(c("frame.number"))
        proc = _int(c("s1ap.procedureCode"))
        if frame is None or proc is None:
            continue
        cause = None
        for group in CAUSE_GROUPS:
            value = _int(c(f"s1ap.{group}"))
            if value is not None:
                cause = (group, value)
                break
        headers = _ints(c("nas-eps.security_header_type"))
        rows.append({
            "frame": frame, "time": parse_time(c("frame.time_epoch")),
            "src": _first(c("ip.src")) or _first(c("ipv6.src")), "dst": _first(c("ip.dst")) or _first(c("ipv6.dst")),
            "pdu": _int(c("s1ap.S1AP_PDU")) or 0, "proc": proc,
            "mme": _int(c("s1ap.MME_UE_S1AP_ID")), "enb": _int(c("s1ap.ENB_UE_S1AP_ID")),
            "s1ap_cause": cause, "handover_type": _int(c("s1ap.HandoverType")),
            "s_tmsi": _int(c("s1ap.m_TMSI")), "mmec": _int(c("s1ap.mMEC")),
            "security": max(headers) if headers else None,
            "emm": _int(c("nas-eps.nas_msg_emm_type")), "esm": _int(c("nas-eps.nas_msg_esm_type")),
            "emm_cause": _int(c("nas-eps.emm.cause")), "esm_cause": _int(c("nas-eps.esm.cause")),
            "imsi": _first(c("e212.imsi")) or None, "m_tmsi": _int(c("nas-eps.emm.m_tmsi")),
            "mme_code": _int(c("nas-eps.emm.mme_code")), "toc": _int(c("nas-eps.emm.toc")),
            "ebi": _int(c("nas-eps.bearer_id")), "nas": bool(headers) or c("nas-eps.nas_msg_emm_type") != "",
        })
    return rows


def _uplink(row: dict[str, Any]) -> bool:
    return row["proc"] in (12, 13, 18, 2, 3) or (row["proc"] in (0, 4) and row["pdu"] == 0) or \
        (row["proc"] in (9, 23) and row["pdu"] in (1, 2))


def _message(row: dict[str, Any]) -> str:
    return _S1AP_MESSAGES.get((row["proc"], row["pdu"])) or \
        f"{S1AP_PROCEDURES.get(row['proc'], 'procedure %d' % row['proc'])} {_PDU.get(row['pdu'], '')}".strip()


class _Ctx:
    def __init__(self, row: dict[str, Any], assoc: tuple[str, str]) -> None:
        self.assoc = assoc
        self.enb_addr = row["src"] if _uplink(row) else row["dst"]
        self.mme: int | None = row["mme"]
        self.enb: int | None = row["enb"]
        self.rows: list[dict[str, Any]] = []
        self.release_cause: tuple[str, int] | None = None
        self.closed = False


def _contexts(rows: list[dict[str, Any]]) -> tuple[list[_Ctx], list[dict[str, Any]]]:
    contexts: list[_Ctx] = []
    by_enb: dict[tuple[tuple[str, str], int], _Ctx] = {}
    by_mme: dict[tuple[tuple[str, str], int], _Ctx] = {}
    pagings: list[dict[str, Any]] = []
    for row in rows:
        assoc = tuple(sorted((row["src"] or "", row["dst"] or "")))
        if row["proc"] == 10:
            pagings.append(row)
            continue
        ctx = None
        if row["proc"] == 12 and row["enb"] is not None:
            ctx = _Ctx(row, assoc)
            contexts.append(ctx)
            by_enb[(assoc, row["enb"])] = ctx
        else:
            if row["mme"] is not None:
                ctx = by_mme.get((assoc, row["mme"]))
            if ctx is None and row["enb"] is not None:
                ctx = by_enb.get((assoc, row["enb"]))
            if ctx is None and row["mme"] is None and row["enb"] is None:
                continue
            if ctx is None:  # the context started before the capture
                ctx = _Ctx(row, assoc)
                contexts.append(ctx)
                if row["enb"] is not None:
                    by_enb[(assoc, row["enb"])] = ctx
        if row["mme"] is not None and ctx.mme is None:
            ctx.mme = row["mme"]
        if ctx.mme is not None:
            by_mme[(assoc, ctx.mme)] = ctx
        ctx.rows.append(row)
        if row["proc"] in (18, 23) and row["pdu"] == 0 and row["s1ap_cause"]:
            ctx.release_cause = ctx.release_cause if row["proc"] == 23 and ctx.release_cause else row["s1ap_cause"]
        if row["proc"] == 23 and row["pdu"] == 1:
            ctx.closed = True
            if ctx.enb is not None and by_enb.get((assoc, ctx.enb)) is ctx:
                del by_enb[(assoc, ctx.enb)]
            if ctx.mme is not None and by_mme.get((assoc, ctx.mme)) is ctx:
                del by_mme[(assoc, ctx.mme)]
    return contexts, pagings


def _ue_groups(contexts: list[_Ctx]) -> list[list[_Ctx]]:
    """Union contexts that share an IMSI or an M-TMSI."""
    parent = list(range(len(contexts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    owner: dict[tuple[str, Any], int] = {}
    for i, ctx in enumerate(contexts):
        keys = set()
        for row in ctx.rows:
            if row["imsi"]:
                keys.add(("imsi", row["imsi"]))
            for tmsi in (row["m_tmsi"], row["s_tmsi"]):
                if tmsi is not None:
                    keys.add(("tmsi", tmsi))
        for key in keys:
            if key in owner:
                parent[find(i)] = find(owner[key])
            else:
                owner[key] = i
    groups: dict[int, list[_Ctx]] = {}
    for i, ctx in enumerate(contexts):
        groups.setdefault(find(i), []).append(ctx)
    return sorted(groups.values(), key=lambda g: g[0].rows[0]["frame"] if g[0].rows else 0)


def _step(row: dict[str, Any], ciphered: bool) -> dict[str, Any]:
    step: dict[str, Any] = {"frame": row["frame"], "time": iso(row["time"]), "dir": "ul" if _uplink(row) else "dl",
                            "s1ap": _message(row)}
    if ciphered:
        step["nas"] = "ciphered (not read)"
    else:
        names = [EMM_MESSAGES.get(row["emm"], f"EMM 0x{row['emm']:02x}")] if row["emm"] is not None else []
        if row["esm"] is not None:
            names.append(ESM_MESSAGES.get(row["esm"], f"ESM 0x{row['esm']:02x}"))
        if row["security"] == 12 and not names:
            names.append("Service request")
        if names:
            step["nas"] = " + ".join(names)
    if row["security"] is not None:
        step["security"] = SECURITY.get(row["security"], str(row["security"]))
    for key in ("emm_cause", "esm_cause"):
        if row[key] is not None and not ciphered:
            step[key] = row[key]
    if row["s1ap_cause"]:
        step["s1ap_cause"] = f"{row['s1ap_cause'][0]}:{row['s1ap_cause'][1]}"
    return step


class _Proc:
    def __init__(self, kind: str, row: dict[str, Any]) -> None:
        self.kind = kind
        self.start = row
        self.end: dict[str, Any] | None = None
        self.outcome: str | None = None
        self.cause: tuple[str, int] | None = None
        self.esm_cause: int | None = None
        self.s1ap_cause: tuple[str, int] | None = None
        self.steps: list[dict[str, Any]] = []
        self.accept_row: dict[str, Any] | None = None
        self.completed = False
        self.extra: dict[str, Any] = {}
        self.note: str | None = None
        self.ebi: int | None = None


def _readable(row: dict[str, Any], eea0: bool, null_cipher: bool) -> bool:
    if row["security"] in _CIPHERED:
        return null_cipher and eea0 and (row["emm"] is not None or row["esm"] is not None)
    return True


def build(rows: list[dict[str, Any]], capture_end: float | None, null_cipher: bool) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    contexts, pagings = _contexts(rows)
    ues: list[dict[str, Any]] = []
    for group in _ue_groups(contexts):
        ues.append(_ue(group, capture_end, null_cipher))
    _join_paging(ues, pagings, contexts)
    for i, ue in enumerate(ues):
        ue["ue"] = i
    return ues, {"pagings": len(pagings)}


def _ue(group: list[_Ctx], capture_end: float | None, null_cipher: bool) -> dict[str, Any]:
    procs: list[_Proc] = []
    emm: _Proc | None = None
    esm: dict[Any, _Proc] = {}
    handover: _Proc | None = None
    ciphered = 0
    imsi = None
    tmsis: list[int] = []
    mme_codes: dict[int, int] = {}
    eea0 = False
    ctx_rows = []
    for ctx in group:
        first = ctx.rows[0] if ctx.rows else None
        last = ctx.rows[-1] if ctx.rows else None
        entry: dict[str, Any] = {"mme_ue_s1ap_id": ctx.mme, "enb_ue_s1ap_id": ctx.enb, "enb": ctx.enb_addr,
                                 "first_frame": first["frame"] if first else None,
                                 "last_frame": last["frame"] if last else None, "released": ctx.closed}
        if ctx.release_cause:
            entry["release_cause"] = f"{ctx.release_cause[0]}:{ctx.release_cause[1]}"
        ctx_rows.append({k: v for k, v in entry.items() if v is not None})

    def close(proc: _Proc, outcome: str, row: dict[str, Any] | None, note: str | None = None) -> None:
        proc.outcome = outcome
        proc.end = row
        if note and not proc.note:
            proc.note = note

    def start_emm(kind: str, row: dict[str, Any]) -> _Proc:
        nonlocal emm
        if emm is not None and emm.outcome is None:
            close(emm, "abandoned", None, f"a {kind.replace('_', ' ')} started at frame {row['frame']} first")
        emm = _Proc(kind, row)
        procs.append(emm)
        return emm

    for ctx in group:
        for row in ctx.rows:
            if row["toc"] == 0 and row["emm"] == 0x5D:
                eea0 = True
            readable = _readable(row, eea0, null_cipher)
            if not readable:
                ciphered += 1
            step = _step(row, not readable)
            if readable:
                if row["imsi"] and not imsi:
                    imsi = row["imsi"]
                for t in (row["m_tmsi"], row["s_tmsi"]):
                    if t is not None and t not in tmsis:
                        tmsis.append(t)
                code = row["mme_code"] if row["mme_code"] is not None else row["mmec"]
                if code is not None:
                    for t in (row["m_tmsi"], row["s_tmsi"]):
                        if t is not None:
                            mme_codes[t] = code
            m, e = (row["emm"], row["esm"]) if readable else (None, None)
            owner: _Proc | None = None
            p, pdu = row["proc"], row["pdu"]
            # EMM
            if row["security"] == 12 and readable and m is None:
                owner = start_emm("service_request", row)
            elif m in _EMM_START:
                owner = start_emm(_EMM_START[m], row)
                if m == 0x41 and e == 0xD0:
                    owner.extra["pdn_connectivity"] = "piggybacked"
            elif m == 0x45 and _uplink(row):
                owner = start_emm("detach", row)
            elif m == 0x45:
                owner = start_emm("detach", row)
                owner.extra["initiated_by"] = "network"
                if row["emm_cause"] is not None:
                    owner.cause = ("nas_emm", row["emm_cause"])
            elif m is not None and emm is not None and emm.outcome is None:
                owner = emm
                if m in _EMM_REJECT and (_EMM_REJECT[m] in (None, emm.kind)):
                    if row["emm_cause"] is not None:
                        emm.cause = ("nas_emm", row["emm_cause"])
                    if row["esm_cause"] is not None:
                        emm.esm_cause = row["esm_cause"]
                    close(emm, "rejected", row, {0x54: "authentication rejected by the network",
                                                 0x5F: "the UE rejected the security mode command"}.get(m))
                elif m in _EMM_ACCEPT and _EMM_ACCEPT[m] == emm.kind:
                    emm.accept_row = row
                    if m == 0x46 or emm.kind == "service_request":
                        close(emm, "accepted", row)
                elif m in _EMM_COMPLETE and _EMM_COMPLETE[m] == emm.kind:
                    emm.completed = True
                    close(emm, "accepted", row)
                elif m == 0x5C and row["emm_cause"] is not None:
                    emm.extra["authentication_failure_cause"] = row["emm_cause"]
            elif m is not None and emm is not None and m in _EMM_COMPLETE:
                owner = emm
                emm.completed = True
            # S1AP procedures
            if p == 9 and emm is not None and emm.outcome is None and emm.kind in ("service_request", "attach", "tau"):
                owner = owner or emm
                if pdu == 1 and emm.kind == "service_request":
                    close(emm, "accepted", row)
                elif pdu == 2:
                    emm.s1ap_cause = row["s1ap_cause"]
                    close(emm, "rejected", row, "Initial Context Setup failed")
            elif p in (0, 3) and pdu == 0:
                handover = _Proc("handover", row)
                handover.extra["handover_type"] = {0: "intralte", 1: "ltetoutran", 2: "ltetogeran", 3: "utrantolte",
                                                   4: "gerantolte", 5: "eps_to_5gs", 6: "5gs_to_eps"}.get(
                    row["handover_type"], row["handover_type"]) if p == 0 else "x2_path_switch"
                handover.s1ap_cause = row["s1ap_cause"]
                procs.append(handover)
                owner = handover
            elif p in (0, 2, 3, 4) and handover is not None and handover.outcome is None:
                owner = handover
                if p == 0 and pdu == 2 or p == 3 and pdu == 2:
                    handover.s1ap_cause = row["s1ap_cause"] or handover.s1ap_cause
                    close(handover, "rejected", row, "handover preparation failed")
                elif p == 2 or (p == 3 and pdu == 1):
                    close(handover, "accepted", row)
                elif p == 4 and pdu == 0:
                    close(handover, "abandoned", row, "the source eNB cancelled the handover")
            elif p in (18, 23):
                if emm is not None and emm.outcome is None and not (p == 23 and pdu == 1):
                    if emm.accept_row is not None:
                        close(emm, "accepted", emm.accept_row, "no Complete before the release")
                    else:
                        close(emm, "abandoned", row, "the UE context was released first")
                        owner = emm
                if owner is None:
                    rel = procs[-1] if procs and procs[-1].kind == "ue_context_release" and procs[-1].outcome is None \
                        else None
                    if rel is None and pdu == 0:
                        rel = _Proc("ue_context_release", row)
                        rel.s1ap_cause = row["s1ap_cause"]
                        rel.extra["requested_by"] = "eNB" if p == 18 else "MME"
                        procs.append(rel)
                    if rel is not None:
                        owner = rel
                        if p == 23 and pdu == 1:
                            close(rel, "accepted", row)
            # ESM
            if e is not None:
                key = row["ebi"] if e not in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7) else "pti"
                if e in _ESM_START and not (e == 0xD0 and m == 0x41):
                    proc = _Proc(_ESM_START[e], row)
                    proc.ebi = row["ebi"] if e not in (0xD0, 0xD2, 0xD4, 0xD6) else None
                    esm[key] = proc
                    procs.append(proc)
                    owner = owner or proc
                elif e == 0xC1 and owner is None:
                    proc = esm.get("pti") or _Proc("pdn_connectivity", row)
                    if proc not in procs:
                        procs.append(proc)
                    esm.pop("pti", None)
                    proc.ebi = row["ebi"]
                    esm[row["ebi"]] = proc
                    owner = proc
                elif (e in _ESM_ACCEPT or e in _ESM_REJECT) and owner is None:
                    proc = esm.get(key) or esm.get(row["ebi"])
                    if proc is not None and proc.outcome is None:
                        owner = proc
                        if e in _ESM_REJECT:
                            proc.cause = ("nas_esm", row["esm_cause"]) if row["esm_cause"] is not None else None
                            close(proc, "rejected", row)
                        else:
                            close(proc, "accepted", row)
            if owner is None:
                owner = emm if emm is not None and emm.outcome is None else None
            if owner is None and procs:
                owner = procs[-1]
            if owner is not None:
                owner.steps.append(step)
    for proc in procs:
        if proc.outcome is None:
            if proc.accept_row is not None:
                proc.outcome, proc.end = "accepted", proc.accept_row
                proc.note = proc.note or "no Complete seen"
            else:
                timer = TIMERS_S.get(proc.kind, ESM_TIMER_S)
                t0 = proc.start["time"]
                left = (capture_end - t0) if (capture_end is not None and t0 is not None) else None
                if left is not None and left < timer:
                    proc.outcome = "in_progress"
                    proc.note = proc.note or f"the capture ended {left:.1f} s after the request, inside the {timer:g} s timer"
                else:
                    proc.outcome = "abandoned"
                    proc.note = proc.note or "no answer in the capture"
    out_procs = [_proc_row(p) for p in procs]
    guti = [{"mme_code": mme_codes.get(t), "m_tmsi": f"0x{t:08x}"} for t in tmsis]
    ue: dict[str, Any] = {"imsi": imsi, "guti": [{k: v for k, v in g.items() if v is not None} for g in guti],
                          "contexts": ctx_rows, "procedures": out_procs, "ciphered_count": ciphered,
                          "first_frame": min((c["first_frame"] for c in ctx_rows if "first_frame" in c), default=None)}
    if eea0:
        ue["null_ciphering"] = True
    ue["_tmsis"] = tmsis
    return ue


def _proc_row(proc: _Proc) -> dict[str, Any]:
    row: dict[str, Any] = {"kind": proc.kind, "outcome": proc.outcome, "start_frame": proc.start["frame"],
                           "time": iso(proc.start["time"])}
    if proc.end is not None:
        row["end_frame"] = proc.end["frame"]
        if proc.start["time"] is not None and proc.end["time"] is not None:
            row["timing_ms"] = round((proc.end["time"] - proc.start["time"]) * 1000, 1)
    if proc.cause:
        row["cause"] = {"protocol": proc.cause[0], "code": proc.cause[1]}
    if proc.esm_cause is not None:
        row["esm_cause"] = {"protocol": "nas_esm", "code": proc.esm_cause}
    if proc.s1ap_cause:
        row["s1ap_cause"] = {"group": proc.s1ap_cause[0], "value": proc.s1ap_cause[1]}
    if proc.ebi is not None:
        row["ebi"] = proc.ebi
    if proc.kind == "attach" and proc.outcome == "accepted":
        row["completed"] = proc.completed
    row.update(proc.extra)
    if proc.note:
        row["note"] = proc.note
    row["steps"] = proc.steps
    return row


def _join_paging(ues: list[dict[str, Any]], pagings: list[dict[str, Any]], contexts: list[_Ctx]) -> None:
    by_tmsi = {t: ue for ue in ues for t in ue["_tmsis"]}
    for page in pagings:
        ue = by_tmsi.get(page["s_tmsi"]) if page["s_tmsi"] is not None else None
        if ue is None:
            continue
        answered = None
        for ctx in contexts:
            first = ctx.rows[0] if ctx.rows else None
            if first is None or first["proc"] != 12 or first["time"] is None or page["time"] is None:
                continue
            if first["s_tmsi"] == page["s_tmsi"] and 0 <= first["time"] - page["time"] <= PAGING_WINDOW_S:
                answered = first
                break
        if answered is not None:
            for proc in ue["procedures"]:
                if proc["start_frame"] == answered["frame"]:
                    proc["paging_frame"] = page["frame"]
                    proc["paging_response"] = True
        else:
            ue.setdefault("pending_paging", []).append({"frame": page["frame"], "time": iso(page["time"]),
                                                        "m_tmsi": f"0x{page['s_tmsi']:08x}"})


def explain(ues: list[dict[str, Any]], lookup: Callable[[str, Any], Any]) -> None:
    """Name every cause with cause_lookup's tables and give each UE a one-line verdict."""
    for ue in ues:
        ue.pop("_tmsis", None)
        for proc in ue["procedures"]:
            for key in ("cause", "esm_cause"):
                if key in proc:
                    brief = lookup(proc[key]["protocol"], proc[key]["code"])
                    if brief:
                        proc[key].update(brief)
            if "s1ap_cause" in proc:
                c = proc["s1ap_cause"]
                brief = lookup("s1ap", f"{c['group']}:{c['value']}")
                if brief:
                    c.update(brief)
        ue["verdict"] = _verdict(ue)


def _cause_text(c: dict[str, Any] | None, label: str) -> str:
    if not c:
        return ""
    name = c.get("name")
    if "group" in c:
        return f"S1AP {c['group']} {c['value']}" + (f" {name}" if name else "")
    return f"{label} {c['code']}" + (f" {name}" if name else "")


def _verdict(ue: dict[str, Any]) -> str:
    procs = ue["procedures"]
    bad = [p for p in procs if p["outcome"] in ("rejected", "abandoned")]
    parts = []
    if bad:
        p = bad[-1]
        why = ", ".join(x for x in (_cause_text(p.get("cause"), "EMM" if p["kind"] in TIMERS_S else "ESM"),
                                    _cause_text(p.get("esm_cause"), "ESM"), _cause_text(p.get("s1ap_cause"), "")) if x)
        parts.append(f"{p['kind'].replace('_', ' ')} {p['outcome']}" + (f": {why}" if why else "")
                     + f" (frame {p.get('end_frame', p['start_frame'])})")
    elif procs:
        p = procs[-1]
        parts.append(f"last procedure {p['kind'].replace('_', ' ')} {p['outcome']} (frame {p['start_frame']})")
    else:
        parts.append("no NAS procedure seen")
    if ue.get("pending_paging"):
        parts.append(f"paged at frame {ue['pending_paging'][0]['frame']} without a service request")
    if ue.get("ciphered_count"):
        parts.append(f"{ue['ciphered_count']} ciphered messages not read")
    return "; ".join(parts)


def select(ues: list[dict[str, Any]], imsi: str | None, tmsi: int | None, ue_id: tuple[int, int] | None,
           procedure: str | None) -> list[dict[str, Any]]:
    out = []
    for ue in ues:
        if imsi and ue.get("imsi") != imsi:
            continue
        if tmsi is not None and f"0x{tmsi:08x}" not in {g["m_tmsi"] for g in ue["guti"]} and \
                tmsi not in {int(p["m_tmsi"], 16) for p in ue.get("pending_paging", [])}:
            continue
        if ue_id is not None and not any((c.get("mme_ue_s1ap_id"), c.get("enb_ue_s1ap_id")) == ue_id
                                         for c in ue["contexts"]):
            continue
        if procedure is not None:
            ue = {**ue, "procedures": [p for p in ue["procedures"] if p["kind"] == procedure]}
            if not ue["procedures"]:
                continue
        out.append(ue)
    return out


def summary(ues: list[dict[str, Any]], extra: dict[str, Any]) -> dict[str, Any]:
    by_kind: dict[str, dict[str, int]] = {}
    causes: dict[str, int] = {}
    for ue in ues:
        for p in ue["procedures"]:
            by_kind.setdefault(p["kind"], {}).setdefault(p["outcome"], 0)
            by_kind[p["kind"]][p["outcome"]] += 1
            for key, label in (("cause", None), ("esm_cause", "ESM")):
                c = p.get(key)
                if c:
                    tag = label or ("EMM" if c["protocol"] == "nas_emm" else "ESM")
                    text = f"{tag} {c['code']}" + (f" {c['name']}" if c.get("name") else "")
                    causes[text] = causes.get(text, 0) + 1
    return {"ues": len(ues), "procedures": by_kind, "reject_causes": causes,
            "ciphered_messages": sum(ue["ciphered_count"] for ue in ues),
            "pending_paging": sum(len(ue.get("pending_paging", [])) for ue in ues),
            "pagings": extra.get("pagings", 0)}
