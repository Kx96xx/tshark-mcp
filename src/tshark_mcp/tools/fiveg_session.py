"""fiveg_session: 5G SA registration and PDU sessions per UE (logic in :mod:`tshark_mcp.fiveg`)."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from typing_extensions import TypedDict

from .. import causes, fiveg, models
from ..fields import field_catalogue
from ..limits import ToolError, clamp_limit, echo, lint_digits
from ..server import READ_ONLY, _envelope, _fields_run, _filter, _guarded, _last_packet_time, _resolve, _tool, state


TOOLSET = "mobile"  # tools/list shows it with --toolsets mobile (or all)

Supi = Annotated[str | None, Field(description="SUPI digits (IMSI form)")]
PduSessionId = Annotated[int | None, Field(description="PDU session id, 0 to 255")]
Dnn = Annotated[str | None, Field(description="DNN, such as internet or ims")]


class FivegUe(TypedDict, total=False):
    """One UE (NGAP UE association) with its registration, PDU sessions, VoNR check and verdict."""
    __pydantic_config__ = models._EXTRA_OK
    ran_ue_ngap_id: int
    amf_ue_ngap_id: int
    gnb: str
    supi: str
    suci: dict[str, Any]
    first_frame: int
    last_frame: int
    registration: dict[str, Any]
    pdu_sessions: list[dict[str, Any]]
    ciphered_nas: int
    vonr: dict[str, Any]
    first_failure: dict[str, Any]
    verdict: str


class FivegSessionResult(models.RowsResult, total=False):
    ues: list[FivegUe]
    summary: dict[str, Any]
    capture_end: str


@_tool(title="5G SA registration and PDU sessions per UE", annotations=READ_ONLY)
def fiveg_session(path: str, supi: Supi = None, pdu_session_id: PduSessionId = None, dnn: Dnn = None,
                  filter: str | None = None, limit: int = 50, offset: int = 0) -> FivegSessionResult:
    """Why a 5G SA UE does not register, has no data or no VoNR: one row per UE (NGAP UE
    association) joining N1/N2 (NGAP and NAS-5GS), N4 (PFCP) and N3 (GTP-U).
    `registration` (attempts, authentication, Accept or Reject with the 5GMM cause
    explained, timing), `pdu_sessions` per PDU session id (DNN, 5GSM outcome and cause,
    NGAP QoS flows with QFI and 5QI, UPF and gNB N3 F-TEIDs, the PFCP establishment and its
    cause, `n3_consistent`, GTP-U packets on both TEIDs, `steps` with frames,
    `first_failure`), `vonr` for an IMS DNN (5QI 5 and 5QI 1 flows) and a one-sentence
    `verdict`. Narrow with `supi`, `pdu_session_id` or `dnn`.

    Details: SUPI comes from a null-scheme SUCI (the SUCI keeps MCC, MNC, routing indicator
    and scheme only); ciphered NAS is counted in `ciphered_nas`, never guessed. PFCP pairs by
    sequence number and joins the session by the UPF TEID NGAP relayed, else by DNN and time.
    PDU Session Resource Modify and handovers are not read yet. `filter` is ANDed with the
    NGAP pass."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        cap = clamp_limit(limit, st.limits.max_packets, 50)
        want_supi = lint_digits(supi, "supi") if supi else None
        want_psi = None
        if pdu_session_id is not None:
            try:
                want_psi = int(pdu_session_id)
            except (TypeError, ValueError):
                raise ToolError("invalid_argument", f"pdu_session_id must be 0 to 255, got {echo(pdu_session_id)}") from None
            if not 0 <= want_psi <= 255:
                raise ToolError("invalid_argument", "pdu_session_id must be 0 to 255")
        want_dnn = str(dnn).strip().lower() if dnn else None
        if want_dnn and (len(want_dnn) > 100 or not all(c.isalnum() or c in ".-_" for c in want_dnn)):
            raise ToolError("invalid_argument", f"dnn must be a DNN such as internet or ims, got {echo(dnn)}")
        known = field_catalogue(st.runner)
        ng_fields = [f for f in fiveg.NG_FIELDS if f in known]
        if "ngap.RAN_UE_NGAP_ID" not in ng_fields:
            raise ToolError("tshark_failed", "this tshark has no NGAP dissector")
        stdout, scan = _fields_run(capture, _filter(filter, base=fiveg.NG_FILTER), ng_fields,
                                   st.limits.max_scan_packets, aggregator=fiveg.AGGREGATOR)
        stdout = _pad(stdout, ng_fields, fiveg.NG_FIELDS)
        end, _ = _last_packet_time(capture, stdout)
        explained: dict[tuple[str, int], Any] = {}

        def explain(protocol: str, code: int) -> Any:
            if (protocol, code) not in explained:
                explained[(protocol, code)] = causes.brief(st.runner, protocol, code)
            return explained[(protocol, code)]
        ues = fiveg.parse_ngap(stdout, explain)
        pfcp_out, pscan = _fields_run(capture, fiveg.PFCP_FILTER, fiveg.PFCP_FIELDS, st.limits.max_scan_packets,
                                      aggregator=fiveg.AGGREGATOR)
        pfcp = fiveg.parse_pfcp(pfcp_out)
        gtpu_out, gscan = _fields_run(capture, fiveg.GTPU_FILTER, fiveg.GTPU_FIELDS, st.limits.max_scan_packets,
                                      aggregator=fiveg.AGGREGATOR)
        for other in (pscan, gscan):
            scan.hit_match_cap = scan.hit_match_cap or other.hit_match_cap
            scan.hit_read_cap = scan.hit_read_cap or other.hit_read_cap
        rows = fiveg.assemble(ues, pfcp, fiveg.parse_gtpu(gtpu_out), end)
        summary = fiveg.summary(rows, pfcp)
        if want_supi:
            rows = [r for r in rows if r.get("supi") == want_supi]
        if want_psi is not None or want_dnn:
            kept = []
            for r in rows:
                sessions = [s for s in r.get("pdu_sessions", [])
                            if (want_psi is None or s["pdu_session_id"] == want_psi)
                            and (not want_dnn or (s.get("dnn") or "").lower() == want_dnn)]
                if sessions:
                    kept.append({**r, "pdu_sessions": sessions})
            rows = kept
        extra: dict[str, Any] = {"summary": summary}
        if end is not None:
            extra["capture_end"] = fiveg.capture_time(end)
        return _envelope("ues", rows, cap, scan, offset=offset, **extra)
    return _guarded("fiveg_session", {"path": path, "supi": supi, "pdu_session_id": pdu_session_id, "dnn": dnn,
                                      "filter": filter, "limit": limit, "offset": offset}, run)


def _pad(stdout: str, have: list[str], want: list[str]) -> str:
    """Re-lay ``-T fields`` output onto ``want`` columns when this tshark lacks some fields."""
    if have == want:
        return stdout
    index = {f: i for i, f in enumerate(have)}
    out = []
    for line in stdout.splitlines():
        cols = line.split("\t")
        out.append("\t".join(cols[index[f]] if f in index and index[f] < len(cols) else "" for f in want))
    return "\n".join(out) + ("\n" if out else "")
