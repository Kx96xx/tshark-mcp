---
order: 380
readme: Messages grouped by Call-ID with outcome after any challenge
llms: SIP grouped by Call-ID with the method chain, From/To, final status, time to final response and duration; several messages in one TCP segment are each counted in their own dialog.
---

Messages grouped by Call-ID: method chain, From, To, Request-URI, P-Asserted-Identity, final status,
outcome after any 401/407 challenge, retransmission count, time to final response, dialog duration;
a TCP segment carrying several SIP messages is split so each message joins its own dialog
