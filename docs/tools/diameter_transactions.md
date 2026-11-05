---
order: 210
readme: Requests paired with answers, result codes named, RTT, unanswered
llms: every Diameter request paired with its answer by Hop-by-Hop and End-to-End id within its Session-Id; command, hosts, User-Name, Result-Code or Experimental-Result-Code with its name, RTT, `unanswered` (with `near_capture_end` when the capture stopped before the answer was due, counted in `summary.unanswered_near_capture_end`).
---

Requests paired with answers by Hop-by-Hop/End-to-End id and Session-Id: command name, application,
hosts, realms, User-Name, Result-Code or Experimental-Result-Code with name, RTT, `unanswered`
(`near_capture_end` too when the capture stopped before the answer was due, counted apart)
