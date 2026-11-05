---
order: 430
readme: Why an SS7-over-IP link flapped or a GT is unreachable: SCTP episodes, aborts and heartbeats, M3UA ASP state, DUNA/DAVA outages, SCCP returns and TCAP aborts per association, with a verdict
llms: SS7-over-IP link health per SCTP association: episodes (INIT, ABORT with the cause named, SHUTDOWN, the gap before re-INIT), heartbeat failures, M3UA ASP state transitions with ack times, ERR named, DUNA/DAVA outages per point code (ITU 3-8-3 and ANSI 8-8-8), SCCP UDTS/XUDTS return causes per GT and SSN, TCAP P-Abort causes; a `verdict` (healthy, degraded, flapping, down) and `issues`.
---

One row per SCTP association (the two address:port endpoints) with a `verdict` (healthy; degraded:
heartbeat failures, M3UA ERR, a point code unavailable, SCCP returns, TCAP aborts or an ASP not
active; flapping: two or more aborts or shutdowns; down: the last episode ended and none followed)
and `issues` in plain words. `episodes`: INIT, established (COOKIE_ACK), ended by ABORT (the SCTP
error cause named, RFC 9260 3.3.10), SHUTDOWN or a restart INIT, who ended it, `duration_s`,
`gap_before_s` before the next INIT; an association up before the capture starts with `started`.
`heartbeat`: sent, answered, failures (no HEARTBEAT_ACK in the other direction within 3 s). `m3ua`:
`asp_state` at the end and `transitions` (ASPUP, ASPAC, ASPIA, ASPDN acknowledged, with `ack_ms`;
down when SCTP ends; unacknowledged requests), routing contexts, NTFY status, ERR with the error
code named (RFC 4666 3.8.1), `point_code_outages` (DUNA to DAVA with `outage_s`, still unavailable
without a DAVA, SCON/DUPU/DRST), point codes as value, ITU 3-8-3 and ANSI 8-8-8. `sccp_returns`:
UDTS/XUDTS/LUDTS per unreachable GT and SSN (the UDTS calling address) with the return cause named
(Q.713 3.12) and count. `tcap_aborts`: P-Abort causes (Q.773) with counts. Filters: `peer` (an IP or
ip:port), `point_code` (associations with an outage for it), `gt` (digits in an SCCP return).
`summary`: associations per verdict, aborts, heartbeat failures, M3UA errors, SCCP returns, TCAP
aborts
