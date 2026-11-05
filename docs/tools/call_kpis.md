---
order: 400
readme: ASR, NER, SER, PDD and ACD per peer, trunk, number prefix, user agent or interval
llms: SIP INVITE call KPIs per group (peer, trunk, destination_prefix, source_prefix, user_agent, interval): calls, answered, `asr_pct`, `ser_pct` and `ser_without_487_pct` (RFC 6076), `ner_pct`, `pdd_ms` and `ringing_ms` percentiles, `acd_s`, failure codes and Q.850 causes, `no_final_response` and `near_capture_end` (still open when the capture stopped, left out of the ratios); `method` states every definition and `worst_calls` gives Call-IDs and frames for sip_call_detail. A 401/407 challenge and its retry are one call.
---

Call KPIs for the SIP INVITE calls, per `group_by`: peer (where the first INVITE went), trunk
(source > destination), destination_prefix or source_prefix (first `prefix_len` digits, + and 00
stripped, tel parameters dropped), user_agent, interval (`interval` seconds). Each group: calls,
answered, failed, `asr_pct`, `ser_pct` and `ser_without_487_pct` (RFC 6076 SER, 3xx left out of the
denominator, then 487 too), `ner_pct` (answered plus 486/600/603, and 480/408/487 after a 180/183,
over calls), `pdd_ms` p50/p90/p99/max (first INVITE to first 180/183, or to the failure response
without one: RFC 6076 Session Request Delay), `answer_without_ringing_ms`, `ringing_ms` (18x to
200), `acd_s` mean and median (200 to BYE), `answered_without_bye`, `failure_codes`, `q850_causes`
(from Reason headers), `no_final_response`, `near_capture_end` (no final and the capture ended
within Timer B, 32 s, of the INVITE, or Timer C, 180 s, after a provisional; left out of every
ratio), `first_frame`. `summary` gives the same for the whole file, `method` the definitions,
`worst_calls` up to ten failed or slowest calls with Call-ID and frame. A 401/407 challenge and the
retried INVITE are one call; retransmissions and re-INVITEs do not count
