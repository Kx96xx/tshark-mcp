---
order: 440
readme: SMS over MAP and SGs: SRI-for-SM, forwardSM, report, paging and the CP/RP exchange per message, with a verdict (delivered, rejected, absent subscriber, paging failed, no response), content-free
llms: SMS over MAP (sendRoutingInfoForSM, mt/mo-forwardSM, reportSM-DeliveryStatus, MAP errors and sm-DeliveryFailure causes named) and SGs (paging, service request, PAGING-REJECT cause, CP and RP layer with RP-MR and causes) as one attempt per message with a `verdict` (delivered, rejected, absent_subscriber, paging_failed, no_response, in_progress). Never the text or the other party's number.
---

One row per SMS attempt: `path` (map or sgs), `direction` (mt, mo), `imsi`, `msisdn`, `steps` in
order and a `verdict` (delivered, rejected, absent_subscriber, paging_failed, no_response,
in_progress: unanswered and the capture ended within 10 s) with `reasons` and `ref`. MAP: TCAP
dialogues paired by transaction id; sendRoutingInfoForSM, the mt-forwardSM to the IMSI it returned
(`routed_to_imsi`) and reportSM-DeliveryStatus for the same MSISDN within 60 s are one attempt;
mo-forwardSM, informServiceCentre, alertServiceCentre and readyForSM join by IMSI or MSISDN. Each
MAP step: operation, result (ok, error, tcap_abort, reject, no_response), `error_code` named through
cause_lookup, `delivery_failure_cause` (memoryCapacityExceeded, equipmentProtocolError, ...),
absent-subscriber diagnostic, `rtt_ms`. SGs: per IMSI, a PAGING-REQUEST for SMS or the first CP-DATA
starts an attempt; steps PAGING-REQUEST (service indicator), SERVICE-REQUEST, PAGING-REJECT (SGs
cause named, TS 29.118), DOWNLINK/UPLINK-UNITDATA with the CP message (CP-DATA, CP-ACK, CP-ERROR and
cause), RP message and RP-MR, RP cause named (TS 24.011), TPDU type and TP-MR. Content-free: never
the text, TP-OA or TP-DA; IMSI and MSISDN follow the redaction rules. SMS over IMS is `sms_over_ims`
