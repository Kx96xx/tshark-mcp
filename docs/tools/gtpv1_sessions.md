---
order: 260
readme: GTPv1-C (Gn/Gp) PDP contexts paired, with cause names
llms: GTPv1-C (Gn/Gp) PDP context signalling paired by sequence number, with APN, NSAPI, TEIDs, GSN addresses, end-user address and cause names; same proxy-chain fields as gtp_sessions.
---

GTPv1-C (Gn/Gp) requests paired with responses by sequence and peer (across a proxy too, with
`response_path`): Create/Update/Delete PDP Context and the rest, IMSI, MSISDN, APN, NSAPI, RAT type,
IMEISV, TEID-C/TEID-U and GSN address on each side, end-user address, cause code and name, RTT,
`unanswered`, and the same proxy-chain fields as gtp_sessions
