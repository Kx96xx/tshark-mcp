---
order: 230
readme: The AVPs behind each transaction: flags with bit names, Subscription-Data digest, Gy/Rx/Cx/Sh/S13 digests with failed codes explained, full tree; authentication material never returned
llms: the AVPs of paired Diameter transactions. `key` gives result codes, procedure flags with bit names (ULR, CLR, PUR, PUA, IDR, ...), Cancellation-Type, RAT-Type, Gx request type and rule reports, and a Subscription-Data digest with one line per APN, plus a digest per application under `gy` (MSCC rating group, requested/granted/used units, validity, Final-Unit-Indication, MSCC result), `rx` (media components, flow status, bandwidth, Specific-Action, Abort-Cause), `cx` (authorization/assignment type, identities, auth scheme and item count only), `sh` (Data-Reference, Sh-User-Data size and element names only) and `s13` (IMEI, Equipment-Status); failed result codes carry cause_lookup's `explained`. `full` gives the whole AVP tree, capped per message. Authentication material (RAND, AUTN, XRES, KASME, CK, IK, SIP-Authenticate/Authorization) is never returned. Use it when a transaction row needs the why (what the HSS sent, why the MME asked).
---

The AVPs of paired Diameter transactions. `detail="key"`: Result-Code and Experimental-Result,
ULR/ULA/CLR/PUR/PUA/IDR/NOR flags with bit names, Cancellation-Type, RAT-Type, Visited-PLMN-Id, AIR
vectors, Gx CC-Request-Type, Event-Trigger, rule reports and QoS, and a Subscription-Data digest
(MSISDN, status, ODB, access restrictions, AMBR, one line per APN with PDN type, QCI, ARP, AMBR and
PGW). Per application, picked by application id, a digest: `gy` for Gy/Ro (request type and number,
Service-Context-Id, Subscription-Id, per Multiple-Services-Credit-Control the rating group, service
id, requested, granted and used units with reporting reason, validity time, quota holding time,
thresholds, Final-Unit-Indication action and redirect address, MSCC Result-Code), `rx`
(Rx-Request-Type, UE address, AF identifiers, per Media-Component-Description the media type, flow
status, first line of each Codec-Data, bandwidths and flow count, Specific-Action, Abort-Cause),
`cx` (User-Authorization-Type, Server-Assignment-Type, IMPI, IMPUs, Server-Name or capability
counts, SIP-Number-Auth-Items, authentication scheme and item count, associated identities,
Deregistration-Reason), `sh` (User-Identity, Data-Reference names, requested domain,
Current-Location, Identity-Set, Sh-User-Data as size, root and child element names) and `s13` (IMEI,
software version, Equipment-Status). Each digest's `results` names the Result-Code and
Experimental-Result-Code; a failed one carries `explained` (meaning and reference from cause_lookup,
Experimental codes looked up for that application). `detail="full"`: every AVP as a nested tree,
capped at `max_avps` leaves per message (server cap 2000); enumerated values are named. In both
views authentication material (RAND, XRES, AUTN, KASME, SRES, Kc, CK, IK, SIP-Authenticate,
SIP-Authorization) reads `withheld (authentication material)` and Sh-User-Data is never returned as
a body
