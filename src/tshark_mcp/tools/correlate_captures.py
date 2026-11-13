"""correlate_captures: the same traffic captured at two points, packet by packet (logic in :mod:`tshark_mcp.correlate`)."""

from __future__ import annotations

import time
from typing import Any

from typing_extensions import TypedDict

from .. import correlate, models
from ..fields import split_fields_line
from ..server import (READ_ONLY, _fields_run, _filter, _guarded, _now, _resolve, _tool, runner_deadline,
                      runner_deadline_reset, state)

TOOLSET = "network"  # which --toolsets lists this tool (see tshark_mcp/toolsets.py)
ROWS = 20  # rows per list (lost_flows, rewrites, dscp_changes, only_b_flows)


class CorrelateSummary(TypedDict, total=False):
    __pydantic_config__ = models._EXTRA_OK
    packets_a: int
    packets_b: int
    matched: int
    ambiguous: int
    clock_offset_ms: float
    delay_variation_ms: dict[str, float]
    lost_between: int
    only_a_outside_b_span: int
    only_b: int


class CorrelateCapturesResult(models.ToolResult, total=False):
    path_a: str
    path_b: str
    display_filter: str
    summary: CorrelateSummary
    lost_flows: list[dict[str, Any]]
    rewrites: list[dict[str, Any]]
    ttl_drop: dict[str, int]
    dscp_changes: list[dict[str, Any]]
    only_b_flows: list[dict[str, Any]]
    issues: list[str]
    verdict: str


@_tool(title="Correlate two capture points (loss, NAT, delay between them)", annotations=READ_ONLY)
def correlate_captures(path_a: str, path_b: str, filter: str | None = None) -> CorrelateCapturesResult:
    """Where between two capture points did packets disappear or change? `path_a` and `path_b`
    hold the same traffic captured at two places on its path (A upstream, B downstream: client
    side and server side, before and after a firewall, NAT or tunnel). Packets are matched by
    identity that survives NAT (IP protocol, ID and length plus TCP raw sequence and ack, or UDP
    length); keys seen twice on one side are counted as `ambiguous`, not matched. Returns
    `summary` (matched, `lost_between`: A packets inside B's capture span that never reached B,
    `only_b`, `clock_offset_ms`, `delay_variation_ms`), `lost_flows` (per flow as seen at A),
    `rewrites` (NAT address and port mappings), `ttl_drop` (hops between the points),
    `dscp_changes` (each list: the 20 largest), `issues` and a `verdict`. `filter` is ANDed with `ip && !icmp` on both
    sides. Use it for "the client sent it, did the server get it?"; for a before/after
    comparison of one point use diff_captures, for a working and a failing telecom procedure
    compare_captures."""
    def run() -> dict[str, Any]:
        a, b = _resolve(path_a), _resolve(path_b)
        st = state()
        flt = _filter(filter, base=correlate.DISPLAY_FILTER)
        deadline = _now() + st.limits.timeout_seconds
        token = runner_deadline(time.monotonic() + st.limits.timeout_seconds)
        try:
            sides = []
            for capture in (a, b):
                stdout, _scan = _fields_run(capture, flt, correlate.FIELDS, st.limits.max_scan_packets,
                                            timeout=max(1.0, deadline - _now()))
                sides.append(correlate.parse([split_fields_line(ln) for ln in stdout.splitlines() if ln]))
        finally:
            runner_deadline_reset(token)
        out = correlate.correlate(sides[0], sides[1], limit=ROWS)
        return {"path_a": str(a), "path_b": str(b), "display_filter": flt, **out}
    return _guarded("correlate_captures", {"path_a": path_a, "path_b": path_b, "filter": filter}, run)
