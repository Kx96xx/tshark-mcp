---
order: 240
readme: GTPv2-C requests paired with responses across NATs and proxy chains, cause names, PAA
llms: GTPv2-C requests paired with responses by sequence number; IMSI, APN, F-TEIDs, cause, PAA. On captures with several proxy legs of one procedure, a leg without a response while another leg was answered is `leg_without_response` with a `note` (response not relayed back, or the proxy answered on its own), not `unanswered`; a leg whose response would only have come after the capture on its interface stopped is `near_capture_end` instead, counted apart in `summary.legs_near_capture_end`; a request no leg answered stays `unanswered`, with `near_capture_end` too when the capture on its interface stopped before the answer was due (the slowest answer to the same message plus 0.2 s, at most 2 s), counted in `summary.unanswered_near_capture_end`; this covers the whole session (Modify Bearer, Delete Session and the rest are tied to their legs through the TEIDs the Create announced, or the same sequence number and TEID on both legs); a packet captured twice is `duplicate_of_frame`.
---

GTPv2-C requests paired with responses by sequence and peer (across a NAT too, with
`response_path`): message name, IMSI, MSISDN, APN, F-TEIDs with interface names, cause code and
name, PAA, RTT, `unanswered` (legs of a proxy chain answered elsewhere get `leg_without_response`
and a `note` instead, or `near_capture_end` when the capture on that leg's interface stopped before
the response could be relayed, counted apart; a request no leg answered that the capture stopped too
soon after keeps `unanswered` and gets `near_capture_end`, counted in `unanswered_near_capture_end`;
packets captured twice `duplicate_of_frame`; Modify Bearer, Delete Session and other requests
without an IMSI are tied to their legs through the TEIDs the Create announced, or the same sequence
number and TEID on both legs); the structured filters keep both halves of each transaction, and
`apn` given as a network identifier also matches it with the operator identifier appended
