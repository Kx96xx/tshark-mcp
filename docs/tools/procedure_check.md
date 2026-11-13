---
order: 245
readme: Does a capture follow the standard flow (EPS attach, 2G/3G location update, SIP REGISTER, SIP call)? Each step ok, failed, unanswered, missing or out of order, with frames, the spec clause and the first deviation
llms: compares a capture with a reference procedure (`eps_attach`, `location_update`, `sip_register`, `sip_call`) and returns each step as ok, failed, unanswered, missing, out_of_order or not_seen, with frames, the spec clause, `first_deviation` and a `verdict`.
---

Compares the messages in a capture with a reference flow and names the first step that goes wrong.
`eps_attach` (S6a AIR optional, ULR, GTPv2 Create Session, Modify Bearer; TS 23.401 5.3.2.1) and
`location_update` (MAP sendAuthenticationInfo optional, updateLocation or updateGprsLocation) read
the subscriber's `trace_subscriber` timeline, so `imsi` or `msisdn` is required. `sip_register`
(REGISTER, optional 401/407 challenge, REGISTER with credentials when challenged, 200) and
`sip_call` (INVITE, optional 100 and 180/183, 200, ACK) read `sip_dialogs`: one `call_id`, or every
dialog of that method, up to 20. A step is `ok`, `failed` (answered with an error, or a 3xx-6xx
where the final 2xx was expected), `unanswered` (with `near_capture_end` when the capture stops
before the answer was due), `missing` (required, never seen), `out_of_order` (seen before the step
it should follow) or `not_seen` (optional, absent). The first step that is not ok or not_seen is
`first_deviation`; `verdict` says it in one sentence with its frame and spec clause. Flows are data
in `tshark_mcp/procedure.py`.
