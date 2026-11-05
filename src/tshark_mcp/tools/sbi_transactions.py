"""sbi_transactions: 5G core SBI (HTTP/2 between NFs) per transaction (logic in :mod:`tshark_mcp.sbi`)."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field
from typing_extensions import TypedDict

from .. import causes, models, sbi
from ..limits import ToolError, clamp_limit, echo, lint_digits
from ..runner import check_decode_as
from ..server import READ_ONLY, _envelope, _fields_run, _filter, _guarded, _last_packet_time, _resolve, _tool, state

TOOLSET = "mobile"  # tools/list shows it with --toolsets mobile (or all)

Ports = Annotated[list[int] | None, Field(description="Extra TCP ports to read as HTTP/2 (SBI on non-standard ports)")]
Status = Annotated[str | None, Field(description="Keep rows with this status: 404, 4xx, 5xx, error (4xx, 5xx, reset, no answer)")]
Service = Annotated[str | None, Field(description="SBI service name or prefix: nudm-sdm, nsmf, ...")]
Supi = Annotated[str | None, Field(description="SUPI, GPSI or PEI digits")]
MAX_PORTS = 8


class SbiTransaction(TypedDict, total=False):
    """One HTTP/2 request between NFs and its answer (more keys: see docs/TOOLS.md)."""
    __pydantic_config__ = models._EXTRA_OK
    service: str
    operation: str
    uri: str
    status: int
    latency_ms: float
    outcome: str
    cause: str
    cause_explained: dict[str, Any]
    consumer: str
    producer: str
    supi: str
    request_frame: int
    response_frame: int
    reset: dict[str, Any]


class SbiTransactionsResult(models.RowsResult, total=False):
    transactions: list[SbiTransaction]
    verdict: str
    summary: dict[str, Any]


def _status_filter(value: str | None):
    if value is None:
        return None
    text = str(value).strip().lower()
    if text == "error":
        return lambda r: r.get("outcome") in ("client_error", "server_error", "no_response") or "reset" in r
    if len(text) == 3 and text[0] in "12345" and text[1:] == "xx":
        return lambda r: r.get("status_class") == text
    if text.isdigit() and 100 <= int(text) <= 599:
        return lambda r: r.get("status") == int(text)
    raise ToolError("invalid_argument", f"status must be a code (404), a class (4xx) or 'error', got {echo(value)}")


@_tool(title="5G SBI transactions (HTTP/2 between NFs)", annotations=READ_ONLY)
def sbi_transactions(path: str, service: Service = None, status: Status = None, supi: Supi = None,
                     ports: Ports = None, filter: str | None = None, limit: int = 100,
                     offset: int = 0) -> SbiTransactionsResult:
    """Which 5G core SBI call failed, and why: one row per HTTP/2 request between network
    functions (AMF, SMF, AUSF, UDM, PCF, NRF, ...) with `service` (nnrf-disc, nausf-auth,
    nudm-sdm, nsmf-pdusession, ...), `operation` (method plus path template), `consumer` and
    `producer` NF, `status`, `latency_ms`, the ProblemDetails `cause` explained through
    cause_lookup, `reset` (RST_STREAM error), `outcome`, identities (`supi`, `gpsi`, `pei`, a
    SUCI without its scheme output) and NRF `discovery` parameters with
    `nf_profiles_returned`. Narrow with `service` (prefix), `status` (404, 4xx, 5xx, error) or
    `supi`; `ports` reads more TCP ports as HTTP/2.

    Details: `summary.services`: per service and operation, calls, 4xx/5xx share, unanswered,
    resets, latency p50/p95/p99, causes. `summary.tls_unreadable` counts TLS connections that
    look like SBI (ALPN h2 or an SNI under 3gppnetwork.org): without keys their errors cannot
    be seen and the `verdict` says so. `hpack_state_missing` marks header blocks that refer
    to HPACK state from before the capture started. Bodies are never returned: only named
    members; authentication material (5gAuthData, kausf, rand, autn, hxresStar, ...) is
    withheld and only named in `withheld_keys`."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        cap = clamp_limit(limit, st.limits.max_packets, 100)
        want_service = None
        if service is not None:
            want_service = str(service).strip().lower()
            if not want_service or len(want_service) > 64 or not all(c.isalnum() or c in "-_" for c in want_service):
                raise ToolError("invalid_argument", f"service must be a service name such as nudm-sdm, got {echo(service)}")
        keep_status = _status_filter(status)
        want_supi = lint_digits(supi, "supi") if supi else None
        extra: list[str] = []
        port_set: set[int] = set()
        for p in ports or []:
            try:
                port = int(p)
            except (TypeError, ValueError):
                raise ToolError("invalid_argument", f"ports must be TCP port numbers, got {echo(p)}") from None
            rule = f"tcp.port=={port},http2"
            check_decode_as(rule)
            port_set.add(port)
            extra += ["-d", rule]
        if len(port_set) > MAX_PORTS:
            raise ToolError("invalid_argument", f"at most {MAX_PORTS} ports")
        stdout, scan = _fields_run(capture, _filter(filter, base=sbi.DISPLAY_FILTER), sbi.FIELDS,
                                   st.limits.max_scan_packets, aggregator=sbi.AGGREGATOR, extra_args=extra)
        end, _ = _last_packet_time(capture, stdout)
        txs, facts = sbi.parse(stdout)
        explained: dict[str, Any] = {}

        def explain(code: str) -> Any:
            if code not in explained:
                explained[code] = causes.brief(st.runner, "http_sbi", code)
            return explained[code]
        rows = sbi.build_rows(txs, explain, end)
        tls_out, _ = _fields_run(capture, sbi.TLS_FILTER, sbi.TLS_FIELDS, st.limits.max_scan_packets)
        tls = sbi.tls_unreadable(tls_out, port_set)
        goaways = [{"tcp_stream": c["tcp_stream"], **g} for c in facts["connections"].values() for g in c["goaway"]]
        summary: dict[str, Any] = {
            "transactions": len(rows),
            "by_outcome": {},
            "services": sbi.summary(rows),
            "tls_unreadable": tls["connections"],
            "hpack_state_missing": facts["hpack_state_missing"],
            "bodies_unattributed": facts["bodies_unattributed"],
        }
        for r in rows:
            summary["by_outcome"][r["outcome"]] = summary["by_outcome"].get(r["outcome"], 0) + 1
        discovery = [{"frame": r.get("request_frame"), **r["discovery"],
                      "nf_profiles_returned": r.get("nf_profiles_returned"), "status": r.get("status")}
                     for r in rows if r.get("discovery")]
        if discovery:
            summary["nrf_discovery"] = [{k: v for k, v in d.items() if v is not None} for d in discovery]
        if goaways:
            summary["goaway"] = goaways
        verdict = sbi.verdict(rows, tls["connections"], facts["hpack_state_missing"])
        if want_service:
            rows = [r for r in rows if (r.get("service") or "").startswith(want_service)]
        if keep_status:
            rows = [r for r in rows if keep_status(r)]
        if want_supi:
            rows = [r for r in rows if want_supi in (r.get("supi"), r.get("gpsi"), r.get("pei"))
                    or want_supi in (r.get("uri") or "")]
        return _envelope("transactions", rows, cap, scan, offset=offset, verdict=verdict, summary=summary)
    return _guarded("sbi_transactions", {"path": path, "service": service, "status": status, "supi": supi,
                                         "ports": ports, "filter": filter, "limit": limit, "offset": offset}, run)
