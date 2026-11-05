---
order: 500
readme: Handshake, heartbeats, retransmissions, aborts, INITs refused with ABORT and INIT collisions per association
llms: SCTP handshake state, heartbeats, retransmissions, aborts per endpoint pair; `issues` for INITs answered with ABORT, an INIT collision and 3 or more unacknowledged heartbeats.
---

Per endpoint pair: handshake state, initiate tags, DATA chunks, heartbeats sent vs acked,
retransmissions, ABORT/SHUTDOWN seen, `inits_aborted` (INITs answered with ABORT before any INIT_ACK),
`init_collision` (both ends sent INIT, RFC 9260 5.2.4) and `issues` naming them and 3 or more
unacknowledged heartbeats
