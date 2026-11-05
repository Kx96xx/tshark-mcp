---
order: 470
readme: RFC 4733 and SIP INFO digits in order, checked against the SDP
llms: DTMF digits from RFC 4733 RTP events and SIP INFO, each checked against the negotiated telephone-event payload type, with missing end packets and rejected INFOs flagged.
---

DTMF digits in time order from RFC 4733/2833 telephone-events (one row per digit however many update
and end packets: duration, volume, end packets, payload type, SSRC, call) and SIP INFO
(application/dtmf-relay, application/dtmf, KPML) with the INFO's response status; each RTP event is
checked against the telephone-event payload type the call's SDP negotiated, and `issues` flag an
unnegotiated payload type, a digit without an end packet, or a rejected or unanswered INFO; `calls`
gives the digits per call and method and notes calls that use both
