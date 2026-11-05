---
order: 490
readme: Each SMS over IMS with its RP answer and a verdict
llms: SMS over IMS per RP-DATA (SIP MESSAGE with application/vnd.3gpp.sms): MO or MT, RP-MR, SMSC, TPDU type and addresses (never the text), the SIP response, the paired RP-ACK or RP-ERROR with RP cause and the SIP response to its own MESSAGE, the status report, whether the UE registered with +g.3gpp.smsip, and a `verdict` with `reasons` (an RP-ACK the UE never accepted, an RP-ACK coded for the wrong direction, 202 with no RP answer, a 488 to a UE without smsip). Use it for "SMS over IMS sent but not delivered".
---

SMS over IMS: one row per SIP MESSAGE carrying RP-DATA or RP-SMMA (application/vnd.3gpp.sms), legs
through the CSCFs counted once: MO or MT, RP message reference, SMSC address, the TPDU (SMS-SUBMIT,
SMS-DELIVER or SMS-STATUS-REPORT with TP-MR, TP-OA/TP-DA, status report requested, concatenation,
TP-Status; never the text), the SIP response with its frame and delay; `ack`: the RP-ACK or RP-ERROR
answering it (paired by RP-MR and the UE's identity, including the identities its REGISTER
associated) with RP cause named and the SIP response to the MESSAGE that carried it; `status_report`
for a submit that asked for one; `ue_registration` with whether the UE registered with
+g.3gpp.smsip; a `verdict` (accepted, delivered, rejected, ack_not_delivered, sip_failed,
not_registered_for_sms, no_rp_ack, no_response, in_progress, rp_unknown, orphan_ack) with `reasons`,
including an RP-ACK coded for the wrong direction
