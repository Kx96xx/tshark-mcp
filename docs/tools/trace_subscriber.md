---
order: 520
readme: One timeline for a subscriber across Diameter, GTP, PFCP, MAP and SIP
llms: one time-ordered timeline for a subscriber across Diameter, GTPv2-C, GTPv1-C, PFCP, MAP and SIP; all its passes share one time budget. Start here for "why did subscriber X fail".
---

One time-ordered timeline for a subscriber across Diameter, GTPv2-C and GTPv1-C (following
control-plane TEIDs), PFCP (by IMSI or the UE address GTP allocated, then by SEID), MAP and SIP,
each row with protocol, message, result and pairing; all passes share one time budget and a spent
budget returns the partial timeline with `truncated`
