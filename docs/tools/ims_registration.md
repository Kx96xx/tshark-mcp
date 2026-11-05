---
order: 480
readme: REGISTER flows per UE with a verdict: registered, expired, deregistered, challenge-loop, failed
llms: IMS registration per public identity: every REGISTER transaction (initial, authenticated, resync with AUTS, re-registration, de-registration) with status and expiry, the implicit IMPU set (P-Associated-URI), Service-Route, Contact feature tags (`smsip`, `mmtel`), third-party REGISTERs to application servers, ESP sent after an unanswered 401 against the SPIs offered, reg-event NOTIFYs (a terminated one is a network-initiated de-registration, with the contact event named), and a `verdict` (registered, expired, deregistered, challenge-loop, failed, in_progress) with `reasons`. Use it for "why can't this UE register to IMS" and before blaming SMS or voice on a UE.
---

IMS registration per public identity from every REGISTER transaction (the legs of one REGISTER
through the CSCFs count once; copies are told from retransmissions): each transaction's kind
(initial, authenticated after a 401, resync with AUTS, re-registration, de-registration), status,
requested and granted expiry, RTT, challenge algorithm; the IMPI, Contact feature tags (`smsip` for
+g.3gpp.smsip, `mmtel` for the MMTel ICSI), sec-agree mechanisms, P-Associated-URI (implicit IMPU
set), Service-Route and Path; third-party REGISTERs to application servers with their status; when a
401 is never answered in clear, the ESP the UE sent to the P-CSCF afterwards and its SPI against the
ones offered in Security-Server; reg-event NOTIFYs (RFC 3680) about the user with the registration
state and contact event they report, a terminated one after the last successful REGISTER ending the
registration; a `verdict` (registered, expired, deregistered by the UE or by the network,
challenge-loop, failed, in_progress near the end of the capture) with `reasons` naming 403, 404,
408, 421, 423, 500, 503 with Retry-After in IMS terms. Nonces, AKA vectors and CK/IK are never
returned
