---
order: 210
readme: Requests paired with answers, result codes named, RTT, unanswered
llms: every Diameter request paired with its answer by Hop-by-Hop and End-to-End id within its Session-Id; command, hosts, User-Name, the command-level Result-Code or Experimental-Result-Code with its name (Result-Codes inside a Multiple-Services-Credit-Control are in `mscc_result_codes`), RTT, `unanswered` (with `near_capture_end` when the capture stopped before the answer was due, counted in `summary.unanswered_near_capture_end`).
---

Requests paired with answers by Hop-by-Hop/End-to-End id and Session-Id: command name, application,
hosts, realms, User-Name, the command-level Result-Code or Experimental-Result-Code with name (a
Result-Code nested in a grouped AVP such as Proxy-Info is ignored; Result-Code wins over an
Experimental-Result beside it, RFC 6733 7.6), `mscc_result_codes` (the Result-Code of each
Multiple-Services-Credit-Control of a credit-control answer) with the names of the failed ones in
`mscc_results`, RTT, `unanswered`
(`near_capture_end` too when the capture stopped before the answer was due, counted apart)
