---
order: 200
readme: Per Diameter peer: CER/CEA capabilities, watchdog cadence and misses, DPR and restarts, success ratio, routing errors with the realm, Failed-AVP names and RTT per application, with a verdict
llms: per Diameter peer connection: CER/CEA result and advertised applications, DWR/DWA cadence and missed answers, DPR with Disconnect-Cause, restarts (Origin-State-Id changes), per-application success ratio, routing errors (3002 to 3006) with the Destination-Realm, Failed-AVP names, RTT p50/p95, and a `verdict` (healthy, degraded, restarted, down) with `issues`.
---

One row per Diameter peer connection (the two IP addresses) with a `verdict` (healthy, degraded:
routing errors, 5xxx, missed watchdogs or unanswered requests; restarted: an Origin-State-Id
changed; down: the CER refused, or a DPR with no later successful CER) and `issues`. `hosts`:
Origin-Host per address. `capabilities`: each CER with its CEA result (explained when refused),
advertised Auth and Acct applications by name, the peer's applications, Firmware-Revision,
Inband-Security-Id, Origin-State-Id. `watchdog`: DWR requests, answered, `missed` (no DWA),
`cadence_s` (median interval), `longest_gap_s`. `disconnects`: DPR with Disconnect-Cause named
(REBOOTING, BUSY, DO_NOT_WANT_TO_TALK_TO_YOU), sender, answered. `restarts`: Origin-State-Id before
and after per Origin-Host. `applications`: per application id: requests, answers, `success_pct`,
result classes, `errors` explained through cause_lookup, `routing_errors` (3002, 3003, 3004, 3005,
3006 with the Destination-Realm and Destination-Host the request named), `rtt_ms` p50/p95/max,
unanswered. `failed_avps`: AVP names inside Failed-AVP, counted. `error_messages`: Error-Message
text, capped, untrusted. `routing`: requests with Destination-Host versus realm-only, deepest
Route-Record, redirects. Answers pair by command code and hop-by-hop id in the opposite direction.
Filters: `host` (part of an Origin-Host), `realm`, `application`. `summary`: peers per verdict,
routing errors, missed watchdogs, restarts, disconnects
