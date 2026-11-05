---
order: 530
readme: Attach, TAU, service request, PDN and bearer procedures per UE from S1AP and NAS EPS: outcome, EMM/ESM and S1AP causes named, timing, ciphered messages counted, unanswered paging
llms: EMM, ESM and S1AP procedures per UE from S1-MME (attach, TAU, service request, detach, PDN connectivity, dedicated bearer, handover, UE context release): `outcome` (accepted, rejected, abandoned, in_progress), EMM/ESM and S1AP causes named with their TS 24.301 / TS 36.413 reference, `timing_ms`, `steps`, `ciphered_count` (ciphered NAS is counted, never guessed; `null_cipher=true` reads EEA0 traffic), `pending_paging` and a `verdict` per UE.
---

EMM, ESM and S1AP procedures per UE from S1-MME captures. S1 UE contexts (an InitialUEMessage opens
one on its association and eNB-UE-S1AP-ID, the MME-UE-S1AP-ID joins on the first downlink message,
UE Context Release Complete closes it) are joined into one UE by IMSI or by the M-TMSI an Attach or
TAU Accept assigned and a later S-TMSI or GUTI names. Per UE: `imsi`, `guti` (MME code and M-TMSI),
`contexts` (id pair, eNB, first and last frame, `release_cause` as group:value), `procedures` in
time order and a `verdict`. Procedure kinds: attach, tau, service_request, detach, pdn_connectivity,
dedicated_bearer_activation, bearer_modification, bearer_deactivation, pdn_disconnect,
bearer_resource_allocation, bearer_resource_modification, handover (S1 with HandoverType, or X2 path
switch), ue_context_release (who asked, cause). Each: `outcome` (accepted on the Accept and Complete
or, for a service request, the Initial Context Setup Response; rejected on a Reject, a Setup or
Preparation Failure, an Authentication or Security mode reject; abandoned when another procedure or
a release came first or its timer ran out; in_progress when the capture ended inside T3410/T3430 15
s, T3417 5 s or the ESM 8 s), EMM or ESM `cause` and `esm_cause` (an ESM reject inside an Attach
Reject), `s1ap_cause` (group and value), each named with meaning and reference from cause_lookup (TS
24.301 Annex A/B, TS 36.413 9.2.1.3), `timing_ms`, `completed` for an accepted attach,
`paging_response`, and `steps` (frame, direction, S1AP message, NAS message, security header,
causes). NAS with security header 2 or 4 is counted in `ciphered_count` and not read;
`null_cipher=true` sets nas-eps.null_decipher and reads it only for a UE whose Security Mode Command
selected EEA0. `pending_paging`: a Paging for the UE's S-TMSI with no service request within 10 s.
`summary`: UEs, procedures per kind and outcome, reject causes, ciphered messages, pagings. NGAP and
NAS 5GS are not read yet
