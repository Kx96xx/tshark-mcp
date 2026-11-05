---
order: 298
readme: 5G SA per UE: registration (authentication, 5GMM cause), PDU sessions (5GSM cause, QoS flows with 5QI, PFCP establishment, UPF and gNB N3 TEIDs, n3_consistent, GTP-U counts), a VoNR 5QI 1 check and a verdict
llms: per 5G SA UE (NGAP UE association): `registration` (attempts, authentication, Accept/Reject with the 5GMM cause explained, timing), `pdu_sessions` (DNN, 5GSM outcome and cause, NGAP QoS flows QFI/5QI, UPF and gNB N3 F-TEIDs, PFCP establishment and cause, `n3_consistent`, GTP-U packets), `vonr` (IMS session, 5QI 5, 5QI 1), `first_failure` and a `verdict`. Narrow with `supi`, `pdu_session_id`, `dnn`.
---

One row per UE, an NGAP UE association (RAN-UE-NGAP-ID from the Initial UE Message, joined with the
AMF-UE-NGAP-ID), across N1/N2 (NGAP and the NAS-5GS inside it), N4 (PFCP) and N3 (GTP-U). `supi` comes
from a null-scheme SUCI (redacted like an IMSI); `suci` keeps MCC, MNC, routing indicator and protection
scheme only. `registration`: attempts, `authentication` (challenged, answered, failed with
`auth_failure` cause, rejected by the network), `outcome` accepted or rejected with the 5GMM `cause`
explained (TS 24.501 Annex A), `timing_ms`. `pdu_sessions` per PDU session id: `dnn`, `outcome`
(accepted, rejected, failed, in_progress, no_answer) with the 5GSM `cause` explained, `ngap_setup`
(QoS flows with QFI and 5QI, the UPF N3 TEID and address the gNB was given, the gNB's own TEID, a
setup failure), `pfcp` (the Session Establishment paired by sequence number and joined by the UPF TEID,
else by DNN and time: cause named, UPF F-TEID, UE IP), `n3_consistent` (PFCP and NGAP name the same UPF
TEID), `n3_traffic` (GTP-U packets and bytes on the uplink and downlink TEIDs), `steps` with frames and
`first_failure`. `vonr` for a DNN starting with "ims": IMS session established, 5QI 5 and 5QI 1 flows and
an assessment (no 5QI 1 voice flow points at PCF/SMF policy, not the RAN). `ciphered_nas` counts NAS
that could not be read. `summary`: UEs, registrations and PDU sessions per outcome, N3 mismatches,
PFCP establishments matched to no UE. Not read yet: PDU Session Resource Modify (a 5QI 1 flow added
during a call), handovers, several PDU sessions in one NGAP message, and the SBI calls of a session
(use sbi_transactions with `supi`)
