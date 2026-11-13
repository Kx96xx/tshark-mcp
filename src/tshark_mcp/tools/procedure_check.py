"""procedure_check: compare a capture with a reference procedure (logic in :mod:`tshark_mcp.procedure`)."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from typing_extensions import TypedDict

from pydantic import Field

from .. import models
from .. import procedure as flows
from .. import server as srv
from ..limits import ToolError
from ..server import READ_ONLY, _guarded, _resolve, _tool

TOOLSET = "mobile"  # which --toolsets lists this tool (see tshark_mcp/toolsets.py)

Procedure = Annotated[Literal["eps_attach", "location_update", "sip_register", "sip_call"], Field(
    description="Reference flow: eps_attach, location_update (2G/3G MAP), sip_register or sip_call")]
MAX_DIALOGS = 20


class ProcedureStep(TypedDict, total=False):
    __pydantic_config__ = models._EXTRA_OK
    step: str
    status: str
    required: bool
    frame: int
    answer_frame: int
    result: str
    near_capture_end: bool
    ref: str
    note: str


class ProcedureRun(TypedDict, total=False):
    __pydantic_config__ = models._EXTRA_OK
    subject: str
    procedure: str
    title: str
    ref: str
    steps: list[ProcedureStep]
    first_deviation: ProcedureStep | None
    conforms: bool
    verdict: str


class ProcedureCheckResult(models.ToolResult, total=False):
    path: str
    procedure: str
    checks: list[ProcedureRun]
    summary: dict[str, Any]
    verdict: str


@_tool(title="Procedure check against reference flows", annotations=READ_ONLY)
def procedure_check(path: str, procedure: Procedure, imsi: str | None = None, msisdn: str | None = None,
                    call_id: str | None = None) -> ProcedureCheckResult:
    """Does this capture follow the standard procedure, and if not, which step is the first to
    go wrong? Compares the messages seen with a reference flow and returns each step as ok,
    failed, unanswered, missing, out_of_order or not_seen (optional), with frames and the spec
    clause, plus `first_deviation` and a one-sentence `verdict`. Flows: `eps_attach` (S6a AIR
    optional, ULR, GTPv2 Create Session, Modify Bearer) and `location_update` (MAP) for the
    subscriber in `imsi` or `msisdn`; `sip_register` (REGISTER, optional 401/407 challenge,
    REGISTER with credentials, 200) and `sip_call` (INVITE, optional 100 and 180/183, 200, ACK)
    for one `call_id`, or every dialog of that method (up to 20). Use it when the question is
    "is this flow complete and in order"; for the raw timeline use trace_subscriber, for a
    working capture against a failing one use compare_captures."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        spec = flows.PROCEDURES[procedure]
        checks: list[dict[str, Any]] = []
        if spec["source"] == "trace":
            if not (imsi or msisdn):
                raise ToolError("invalid_argument", f"{procedure} needs imsi or msisdn: the subscriber whose flow to check")
            out = srv.trace_subscriber(str(capture), imsi=imsi, msisdn=msisdn, limit=300)
            if "error" in out:
                return out
            events = flows.events_from_trace(out.get("timeline") or [])
            run_ = flows.check(procedure, events)
            checks.append({"subject": f"imsi {imsi}" if imsi else f"msisdn {msisdn}", **run_})
        else:
            out = srv.sip_dialogs(str(capture), call_id=call_id, method=None if call_id else spec["method"],
                                  limit=MAX_DIALOGS)
            if "error" in out:
                return out
            dialogs = [d for d in out.get("dialogs") or [] if d.get("initial_method") == spec["method"]]
            if call_id and not dialogs:
                raise ToolError("not_found", f"no {spec['method']} dialog with Call-ID {call_id} in this capture")
            for d in dialogs[:MAX_DIALOGS]:
                run_ = flows.check(procedure, flows.events_from_dialog(d))
                checks.append({"subject": f"call-id {d.get('call_id')}", **run_})
        deviating = [c for c in checks if not c["conforms"]]
        by_status: dict[str, int] = {}
        for c in deviating:
            s = c["first_deviation"]["status"]
            by_status[s] = by_status.get(s, 0) + 1
        if not checks:
            verdict = f"No {spec['method']} dialog in this capture." if spec["source"] == "sip" else "Nothing to check."
        elif len(checks) == 1:
            verdict = checks[0]["verdict"]
        else:
            verdict = (f"{len(checks) - len(deviating)} of {len(checks)} {spec['method']} dialog(s) follow the "
                       f"{spec['title']} flow" + (f"; first deviating: {deviating[0]['subject']}" if deviating else ""))
        return {"path": str(capture), "procedure": procedure, "checks": checks,
                "summary": {"checked": len(checks), "conforming": len(checks) - len(deviating),
                            "first_deviation_by_status": by_status},
                "verdict": verdict}
    return _guarded("procedure_check", {"path": path, "procedure": procedure, "imsi": imsi, "msisdn": msisdn,
                                        "call_id": call_id}, run)
