---
order: 250
readme: The IEs behind each GTPv2-C transaction: APN, PDN type, QoS, ULI, PCO names, offending IE, likely causes of a reject
llms: the information elements of paired GTPv2-C transactions, the GTP counterpart of diameter_avps. `key` gives IMSI, MSISDN, MEI, APN, selection mode, PDN type, PAA, serving network, RAT, ULI (TAI, ECGI, ...), indication flags, charging, recovery, APN-AMBR, F-TEIDs, PCO option names (never PAP/CHAP contents), bearer contexts with QCI/ARP/MBR/GBR, the cause with `offending_ie` and `source` (CS bit), the RAN/NAS cause of a Delete Session, and `likely_causes` for a reject built from the request; `full` gives every IE as a tree, capped by `max_ies`. `message` is a type number or name ("Create Session Request").
---

The IEs of paired GTPv2-C requests and responses, selected by `imsi`, `teid` (header or F-TEID),
`frame` or `message` (type number or name; a request name selects its response too). `detail="key"`:
`request_ies` and `response_ies` with IMSI, MSISDN, MEI, APN, selection mode, PDN type, PAA, APN
restriction, serving network (MCC-MNC), RAT, ULI (TAI, ECGI with eNB and cell id, CGI, SAI, RAI,
LAI), UE time zone, indication flags that are set, charging characteristics and ID, recovery,
APN-AMBR, F-TEIDs by interface, PCO option names (PAP and CHAP payloads are never returned), bearer
contexts (EBI, QCI, ARP PL/PCI/PVI, MBR/GBR, F-TEIDs, cause), the cause with `offending_ie` (named
from the request) and `source` (CS bit: this node or relayed), the RAN/NAS cause of a Delete Session
with a `cause_lookup` call, and the names of other IEs. Rejects (and 18/19) get `likely_causes`
built from the request. Enumerations use tshark's own display text. `detail="full"`: every IE as a
tree, at most `max_ies` per message (cap 2000), `*_ies_dropped` for the rest
