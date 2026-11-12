"""call_ladder: a sequence diagram (Mermaid or text) of a subscriber or a call, every arrow
with its frame number (logic in :mod:`tshark_mcp.ladder`, viewer in :mod:`tshark_mcp.ladder_ui`)."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field
from typing_extensions import TypedDict

from .. import ladder, ladder_ui, models
from .. import server as srv
from ..limits import ToolError, echo
from ..server import READ_ONLY, _guarded, _resolve, _tool, app

Format = Annotated[Literal["mermaid", "text", "json"], Field(description="mermaid sequenceDiagram, fixed-width text, or arrows only")]
Source = Annotated[Literal["auto", "trace_subscriber", "call_legs"], Field(
    description="Row producer: auto picks call_legs for call_id, trace_subscriber for imsi/msisdn")]
MaxRows = Annotated[int, Field(description="Most arrows drawn (1 to 400)")]
MAX_ROWS_CAP = 400
TOOLSET = "voice"  # which --toolsets lists this tool (see tshark_mcp/toolsets.py)


class LadderArrow(TypedDict, total=False):
    __pydantic_config__ = models._EXTRA_OK
    frame: int
    time: str
    src: str
    dst: str
    protocol: str
    label: str
    kind: str
    leg: int
    failed: bool
    note: str


class LadderParticipant(TypedDict, total=False):
    __pydantic_config__ = models._EXTRA_OK
    id: str
    address: str
    role: str
    role_evidence: str


class CallLadderResult(models.ToolResult, total=False):
    path: str
    source: str
    format: str
    diagram: str
    participants: list[LadderParticipant]
    arrows: list[LadderArrow]
    rows_included: int
    rows_dropped: int
    failures: int
    verdict: str


@_tool(title="Message ladder (Mermaid sequence diagram)", annotations=READ_ONLY,
       meta={"ui": {"resourceUri": ladder_ui.URI}})
def call_ladder(path: str, call_id: str | None = None, imsi: str | None = None, msisdn: str | None = None,
                source: Source = "auto", format: Format = "mermaid", roles: bool = True,
                max_rows: MaxRows = 80) -> CallLadderResult:
    """A ladder diagram to paste into a ticket: the messages of one call (`call_id`, every SIP
    leg from call_legs) or one subscriber (`imsi` or `msisdn`, Diameter, GTP, PFCP, SIP, ...
    from trace_subscriber) as a Mermaid `sequenceDiagram` (or fixed-width text), every arrow
    labelled `#<frame>` so the diagram and `arrows` agree with packet_detail. Failing steps sit
    in a red `rect` with a Note. `participants` carry a role guessed from what they send
    (MME, HSS, SGW, PGW, PCRF, UPF, caller, SIP proxy, ...) and the `role_evidence`.

    Details: Same input, byte-identical diagram. Labels are packet text cut to 60 characters
    and stripped of characters Mermaid or HTML would interpret. `max_rows` caps the arrows;
    `rows_dropped` says how many were left out. Hosts with MCP Apps can show the result as an
    interactive SVG ladder (resource ui://tshark-mcp/ladder.html)."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        try:
            cap = int(max_rows)
        except (TypeError, ValueError):
            raise ToolError("invalid_argument", f"max_rows must be 1 to {MAX_ROWS_CAP}, got {echo(max_rows)}") from None
        if not 1 <= cap <= MAX_ROWS_CAP:
            raise ToolError("invalid_argument", f"max_rows must be 1 to {MAX_ROWS_CAP}")
        if format not in ("mermaid", "text", "json"):
            raise ToolError("invalid_argument", f"format must be mermaid, text or json, got {echo(format)}")
        use = source
        if use == "auto":
            use = "call_legs" if call_id else "trace_subscriber" if (imsi or msisdn) else None
        if use is None:
            raise ToolError("invalid_argument", "pass call_id (a SIP call) or imsi / msisdn (a subscriber)")
        verdict = None
        if use == "call_legs":
            if not call_id:
                raise ToolError("invalid_argument", "source='call_legs' needs call_id")
            out = srv.call_legs(str(capture), call_id=call_id, ladder=True, limit=1)
            _raise_nested(out)
            if not out.get("calls"):
                raise ToolError("not_found", f"no INVITE call with Call-ID {echo(call_id)} in this capture",
                                ) from None
            call = out["calls"][0]
            arrows, hints = ladder.from_call_legs(call)
            verdict = call.get("verdict") or _call_verdict(call)
        elif use == "trace_subscriber":
            if not (imsi or msisdn):
                raise ToolError("invalid_argument", "source='trace_subscriber' needs imsi or msisdn")
            out = srv.trace_subscriber(str(capture), imsi=imsi, msisdn=msisdn, limit=MAX_ROWS_CAP)
            _raise_nested(out)
            arrows, hints = ladder.from_trace(out.get("timeline") or [])
        else:
            raise ToolError("invalid_argument", f"unknown source {echo(source)}")
        arrows = [a for a in arrows if a.get("frame") is not None]
        dropped = max(0, len(arrows) - cap)
        arrows = [{k: v for k, v in a.items() if v is not None} for a in arrows[:cap]]
        parts = ladder.participants(arrows, hints, bool(roles))
        result: dict[str, Any] = {"path": str(capture), "source": use, "format": format}
        if format == "mermaid":
            result["diagram"] = ladder.mermaid(arrows, parts)
        elif format == "text":
            result["diagram"] = ladder.text(arrows, parts)
        result["participants"] = parts
        result["arrows"] = arrows
        result["rows_included"] = len(arrows)
        result["rows_dropped"] = dropped
        result["failures"] = sum(1 for a in arrows if a.get("failed"))
        if verdict:
            result["verdict"] = verdict
        if not arrows:
            result["verdict"] = "no messages for this call or subscriber in the capture"
        return result
    return _guarded("call_ladder", {"path": path, "call_id": call_id, "imsi": imsi, "msisdn": msisdn, "source": source,
                                    "format": format, "roles": roles, "max_rows": max_rows}, run)


def _raise_nested(out: dict[str, Any]) -> None:
    err = out.get("error")
    if isinstance(err, dict):
        raise ToolError(err.get("type", "internal_error"), err.get("message", "the row producer failed"))


def _call_verdict(call: dict[str, Any]) -> str | None:
    f = call.get("where_it_failed")
    if not f:
        return None
    sip = (f.get("sip") or {}).get("name")
    return f"failed on leg {f.get('leg')}: {f.get('status')} {sip or ''} from {f.get('responder')} (frame {f.get('frame')})"


async def _ladder_html() -> str:
    return ladder_ui.HTML


app.resource(ladder_ui.URI, name="call ladder viewer", title="Call ladder viewer (MCP Apps)",
             description="Static HTML view that draws a call_ladder result as an SVG ladder",
             mime_type=ladder_ui.MIME_TYPE)(_ladder_html)
