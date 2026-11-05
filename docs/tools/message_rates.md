---
order: 300
readme: Messages per interval, bursts, storms and subscriber loops with the nodes involved
llms: messages per second (or per `interval`) by name, bursts against the usual rate, and subscribers looping on one request (purge, attach or registration storms) with the gap between repeats and the nodes that sent and received them (MAP global titles, the subscriber's MGT labelled `MGT`, Diameter Origin-Host and Destination-Host or realm, else IP addresses; `alternating` when the repeats switch between two nodes, such as a location ping-pong between two VLRs). Relayed and retransmitted copies count once. Protocols: diameter, gtpv2, gtpv1, sip, map; MAP messages take the IMSI named anywhere in their TCAP dialogue, GTP responses the IMSI of their request.
---

Diameter, GTPv2-C, GTPv1-C, SIP and MAP messages counted by name per interval: total and distinct (a
message seen on both legs of a relay or retransmitted counts once), peak and when, mean rate;
`bursts` (three times the usual rate or more), `subscriber_loops` (one subscriber repeating a
request, with the gap between repeats, whether it is regular, and the sending and receiving nodes:
SCCP global titles for MAP (the subscriber's MGT labelled `MGT`), Origin-Host and Destination-Host
or realm for Diameter, else IP addresses; `alternating` marks a ping-pong between two nodes), a
per-interval `timeline` and one-line `storms`. MAP messages are tied to the IMSI named anywhere in
their TCAP dialogue, GTP responses to the IMSI of their request
