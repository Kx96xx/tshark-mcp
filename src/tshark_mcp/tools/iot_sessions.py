"""iot_sessions: MQTT connections, CoAP exchanges and LwM2M registrations (logic in :mod:`tshark_mcp.iot`)."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field
from typing_extensions import TypedDict

from .. import iot, models
from ..limits import ToolError, clamp_limit, echo, lint_quoted_value
from ..server import READ_ONLY, _envelope, _fields_run, _guarded, _last_packet_time, _resolve, _tool, state

TOOLSET = "network"  # which --toolsets lists this tool (see tshark_mcp/toolsets.py)

Protocol = Annotated[Literal["mqtt", "coap", "lwm2m"] | None, Field(description="Only this protocol's rows")]
Client = Annotated[str | None, Field(description="Part of a client address, MQTT client id or LwM2M endpoint")]


class IotSession(TypedDict, total=False):
    """One MQTT connection, CoAP client/server pair or LwM2M endpoint, with a verdict."""
    __pydantic_config__ = models._EXTRA_OK
    protocol: str
    client: str
    broker: str
    server: str
    client_id: str
    endpoint: str
    protocol_version: str
    keepalive_s: int
    connack: dict[str, Any]
    keepalive_violated: bool
    reconnect_loop: bool
    ended: dict[str, Any]
    exhausted: list[dict[str, Any]]
    registrations: list[dict[str, Any]]
    expired: bool
    gtpu_teid: str
    first_frame: int
    verdict: str


class IotSessionsResult(models.RowsResult, total=False):
    sessions: list[IotSession]
    summary: dict[str, Any]
    capture_end: str


@_tool(title="IoT sessions: MQTT, CoAP, LwM2M", annotations=READ_ONLY)
def iot_sessions(path: str, client: Client = None, protocol: Protocol = None, limit: int = 100,
                 offset: int = 0) -> IotSessionsResult:
    """Why IoT devices fail to stay connected: one row per MQTT connection (client id, protocol
    level, keepalive, CONNACK named, `keepalive_violated`, PUBLISH counts per topic, PUBACK
    latency, DISCONNECT reason, how it `ended`, `reconnect_loop`), per CoAP client and server
    (CON/NON/ACK/RST, retransmissions, response codes named, `exhausted` confirmable requests) and
    per LwM2M endpoint (Register with lifetime, Updates, De-register, `expired`), each with a
    `verdict`; traffic inside GTP-U names its `gtpu_teid`. Narrow with `client` or `protocol`.

    Details: keepalive_violated: the client was silent for more than 1.5 times its keepalive.
    reconnect_loop: three or more connections of one client id within ten minutes. exhausted:
    retransmitted four times (MAX_RETRANSMIT) without an ACK or RST. Payloads are never read;
    client ids and endpoint names are redactable identifiers; topics are packet text."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        cap = clamp_limit(limit, st.limits.max_packets, 100)
        if protocol not in (None, "mqtt", "coap", "lwm2m"):
            raise ToolError("invalid_argument", f"protocol must be mqtt, coap or lwm2m, got {echo(protocol)}")
        want = lint_quoted_value(client, "client") if client else None
        read = st.limits.max_scan_packets
        rows: list[dict[str, Any]] = []
        end = None
        scans = []
        if protocol in (None, "mqtt"):
            out, scan = _fields_run(capture, iot.MQTT_FILTER, iot.MQTT_FIELDS, read, aggregator=iot.AGGREGATOR)
            scans.append(scan)
            end, _ = _last_packet_time(capture, out)
            ends = ""
            if out:
                # FIN and RST of every TCP connection; only the MQTT ones are kept when parsing.
                ends, scan2 = _fields_run(capture, iot.END_FILTER, iot.END_FIELDS, read, aggregator=iot.AGGREGATOR)
                scans.append(scan2)
            rows += [{"protocol": "mqtt", **r} for r in iot.mqtt_connections(out, ends, end)]
        if protocol in (None, "coap", "lwm2m"):
            out, scan = _fields_run(capture, iot.COAP_FILTER, iot.COAP_FIELDS, read, aggregator=iot.AGGREGATOR)
            scans.append(scan)
            if end is None:
                end, _ = _last_packet_time(capture, out)
            pairs, endpoints = iot.coap_pairs(out, end)
            if protocol in (None, "coap"):
                rows += [{"protocol": "coap", **r} for r in pairs]
            if protocol in (None, "lwm2m"):
                rows += [{"protocol": "lwm2m", **r} for r in endpoints]
        if want:
            w = want.lower()
            rows = [r for r in rows if any(w in str(r.get(k) or "").lower() for k in ("client", "client_id", "endpoint"))]
        summary = _summary(rows)
        main = scans[0]
        for s in scans[1:]:
            main.hit_match_cap = main.hit_match_cap or s.hit_match_cap
            main.hit_read_cap = main.hit_read_cap or s.hit_read_cap
        extra: dict[str, Any] = {"summary": summary}
        if end is not None:
            from ..fields import iso
            extra["capture_end"] = iso(end)
        return _envelope("sessions", rows, cap, main, offset=offset, **extra)
    return _guarded("iot_sessions", {"path": path, "client": client, "protocol": protocol, "limit": limit,
                                     "offset": offset}, run)


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"by_protocol": {}, "unhealthy": 0}
    for r in rows:
        out["by_protocol"][r["protocol"]] = out["by_protocol"].get(r["protocol"], 0) + 1
        if r.get("verdict") not in ("healthy", "registered", "deregistered"):
            out["unhealthy"] += 1
    mqtt = [r for r in rows if r["protocol"] == "mqtt"]
    if mqtt:
        ids = {r.get("client_id") for r in mqtt if r.get("client_id")}
        out["mqtt"] = {"connections": len(mqtt), "clients": len(ids),
                       "refused": sum(1 for r in mqtt if r.get("connack") and not r["connack"]["accepted"]),
                       "reconnect_loops": len({r.get("client_id") for r in mqtt if r.get("reconnect_loop")}),
                       "keepalive_violations": sum(1 for r in mqtt if r.get("keepalive_violated"))}
    worst = [r for r in rows if r.get("verdict") not in ("healthy", "registered", "deregistered")][:5]
    if worst:
        out["worst"] = [{k: r[k] for k in ("protocol", "client", "client_id", "endpoint", "verdict") if r.get(k)}
                        for r in worst]
    return out
