---
order: 410
readme: Stitch the legs of one call across B2BUAs, SBCs and CSCFs (icid, Session-ID, X- headers, media, number), with a confidence per link, which hop failed and who rewrote the status
llms: stitch the legs a B2BUA, SBC or CSCF chain gave different Call-IDs into one call. Per leg: Call-ID, hop, status, responder, Q.850 cause, `linked_by` (icid, session_id, x_call_id, replaces, target_dialog: high; same_media_endpoint: medium; number_and_time: low), `added_delay_ms`, `header_changes`; per call: weakest `confidence`, `status_mapping` (which element rewrote a 480 into a 503) and `where_it_failed` with the SIP and Q.850 meaning. `call_id` returns the whole call with its merged ladder.
---

The legs of one call that a B2BUA, SBC or the P-/S-CSCF/TAS chain gave different Call-IDs, stitched
into one row per call (a leg nothing links is a call of one leg). A leg is one Call-ID whose first
request is an INVITE; a proxy that keeps the Call-ID adds `hops` to it. Links, strongest first:
`icid` (P-Charging-Vector icid-value), `session_id` (a shared RFC 7989 UUID, the null UUID ignored),
`x_call_id` (an X- header whose name holds Call-ID or CID naming the other leg's Call-ID, or the
same value on both), `replaces` and `target_dialog` (all high), `same_media_endpoint` (the same SDP
address and port offered within `window_s`: medium), `number_and_time` (same called number by its
last nine digits, the later INVITE leaving the address the earlier went to, within `window_s`: low,
check it). Per leg: Call-ID, src > dst, From, To, R-URI, `status`, `final_frame`, `responder`,
Reason and `q850_cause`, `pdd_ms`, `linked_by` {leg, method, confidence, evidence}, `depth` (hops
from the caller; forks keep both branches), `added_delay_ms` (INVITE in to INVITE out, final
response in to out) and `header_changes` against its parent (From, To, R-URI, P-Asserted-Identity,
Privacy, offered codecs, Via and Record-Route counts). Per call: the weakest `confidence`,
`caller_status`, `status_mapping` (received and sent status and Q.850 cause per element,
`rewritten`, a `note`) and `where_it_failed` (the deepest failed leg, its responder and the SIP and
Q.850 name, meaning and reference from cause_lookup). `call_id` returns the call holding that leg
with its merged `ladder` (leg index per message); `ladder=true` adds it to every call in the page.
`summary` counts calls, legs, multi-leg calls, rewritten statuses and links per method over the
whole file
