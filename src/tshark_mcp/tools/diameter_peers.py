"""diameter_peers: the per-peer view of a DRA (logic in :mod:`tshark_mcp.diampeers`).

The first tool defined in its own module; a template for new ones. It registers itself with
``@_tool`` when :func:`tshark_mcp.tools.load` imports it.
"""

from __future__ import annotations

from typing import Any

from .. import causes, diampeers, models
from ..limits import ToolError, clamp_limit, echo, lint_hostname
from ..server import READ_ONLY, _envelope, _fields_run, _filter, _guarded, _last_packet_time, _resolve, _tool, state


@_tool(title="Diameter peers: capabilities, watchdog, KPIs", annotations=READ_ONLY)
def diameter_peers(path: str, host: str | None = None, realm: str | None = None, application: int | None = None,
                   filter: str | None = None, limit: int = 100, offset: int = 0) -> models.DiameterPeersResult:
    """Is the DRA or a peer unhealthy, and which realm is unroutable: one row per Diameter
    peer connection (the two IP addresses) with a `verdict` (healthy, degraded, restarted,
    down) and `issues`. Per peer: `hosts` (Origin-Host per address), `capabilities`
    (CER/CEA result, advertised Auth and Acct applications by name, Firmware-Revision,
    Inband-Security-Id, Origin-State-Id), `watchdog` (DWR/DWA counts, missed answers,
    cadence, longest gap), `disconnects` (DPR with Disconnect-Cause named, who sent it),
    `restarts` (Origin-State-Id changes), `applications` (requests, answers,
    `success_pct`, result classes, `routing_errors` 3002/3003/3004/3005/3006 with the
    Destination-Realm they named, errors explained, RTT p50/p95/max, unanswered),
    `failed_avps` (AVP names inside Failed-AVP), `error_messages` (untrusted text) and
    `routing`. Narrow with `host`, `realm` or `application` (an application id).

    Details: Answers pair with requests by command code and hop-by-hop id in the opposite
    direction. A restart is an Origin-State-Id that differs from the last one the same
    Origin-Host sent. down: the CER was refused, or a DPR with no later successful CER.
    `summary` counts peers per verdict, routing errors, missed watchdogs, restarts and
    disconnects. Per-transaction detail is diameter_transactions. Content-free: hosts,
    realms, codes, timings and frames."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        host_q = lint_hostname(host, "host") if host else None
        realm_q = lint_hostname(realm, "realm") if realm else None
        app = None
        if application is not None:
            try:
                app = int(application)
            except (TypeError, ValueError):
                raise ToolError("invalid_argument", f"application must be a Diameter application id, got {echo(application)}") from None
            if not 0 <= app <= 0xFFFFFFFF:
                raise ToolError("invalid_argument", "application must be 0 to 4294967295")
        cap = clamp_limit(limit, st.limits.max_packets, 100)
        stdout, scan = _fields_run(capture, _filter(filter, base=diampeers.DISPLAY_FILTER), diampeers.FIELDS,
                                   st.limits.max_scan_packets)
        end, _ = _last_packet_time(capture, stdout)
        explained: dict[tuple[str, int], Any] = {}

        def explain(protocol: str, code: int) -> Any:
            if (protocol, code) not in explained:
                explained[(protocol, code)] = causes.brief(st.runner, protocol, code)
            return explained[(protocol, code)]
        peers = diampeers.build(diampeers.parse(stdout), end, explain)
        summary = diampeers.summary(peers)
        peers = diampeers.select(peers, host_q, realm_q, app)
        return _envelope("peers", peers, cap, scan, offset=offset, summary=summary, method=diampeers.METHOD)
    return _guarded("diameter_peers", {"path": path, "host": host, "realm": realm, "application": application,
                                       "filter": filter, "limit": limit, "offset": offset}, run)
