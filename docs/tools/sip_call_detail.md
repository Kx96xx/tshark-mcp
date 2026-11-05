---
order: 390
readme: One call: timings, SDP, Reason headers, who hung up
llms: one call in detail: post-dial delay, answer and setup times, call duration, retransmissions, final response, Reason (Q.850 named) and Warning headers, who hung up, and the SDP offer/answer with the codecs both sides share (empty after a 488 means a codec mismatch). Use it after `sip_dialogs` finds the Call-ID.
---

One INVITE call by Call-ID, built on the `sip_dialogs` row: the ladder with the messages that carry
SDP marked, `outcome`, final response with its reason phrase, post-dial delay (INVITE to the first
180/183, or to the failure response as RFC 6076 defines it), ringing, answer and setup times, early
media, call duration from 200 OK to BYE, retransmissions per message, Reason headers with the Q.850
cause named, Warning headers, whether the caller or the callee sent BYE or CANCEL (by From tag), and
each SDP with its offer/answer role, address, port, codecs, direction and ptime, plus the codecs
offer and answer (or a 488's SDP) have in common
