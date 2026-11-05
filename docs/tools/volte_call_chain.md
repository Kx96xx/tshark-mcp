---
order: 420
readme: One VoLTE call through SIP, Rx, Gx, GTPv2-C bearer creation, PFCP and RTP: each link's status, the first broken link and a verdict
llms: one VoLTE call through SIP, Rx AAR, Gx RAR rule install, GTPv2-C Create Bearer on every leg, PFCP Session Modification, SIP 183/PRACK/UPDATE/180/200 and the first RTP per direction, then BYE, STR, rule removal and Delete Bearer. Each link has a status (ok, failed, missing, not_captured, late), found_by (icid, ue_ip, time) and delay; per call `first_broken_link` and a `verdict` such as "the dedicated bearer was never created: cause 73".
---

One row per INVITE call with its `links` in time order: `invite` (SDP address and ports, icid from
P-Charging-Vector, preconditions), `rx_aar` (Rx AAR/AAA, found by the icid as AF-Charging-Identifier
or by the UE address as Framed-IP-Address), `gx_rar_install` (the Gx RAR with Charging-Rule-Install
on the UE's Gx session, the one whose CCR carried the UE address, else the first install after the
AAR: QCI, rule names, RAA result), `gtp_create_bearer` (every Create Bearer leg whose header TEID a
Create Session Response with the UE's PAA used, plus proxy legs up to 100 ms before them: TEID, QCI,
cause, EBI, round trip), `pfcp_modification` (the Session Modification whose PDR names the UE
address), `sip_183`, `sip_prack`, `sip_update`, `sip_180`, `sip_final`, `rtp_from_ue` and
`rtp_to_ue` (first packet, ms after the 200 OK, before or after the dedicated bearer), then `bye`,
`rx_str`, `gx_rar_remove` and `gtp_delete_bearer`. Each link has a `status` (ok, failed, missing:
the protocol is in the capture but not this call's message, not_captured: the protocol is absent
from the file, late: the bearer came after the 200 OK, skipped), the frame, `found_by` (icid, ue_ip
or time), the result or cause named through cause_lookup (`explained`) and `delay_ms` from the link
before. Per call: `ue_ip` (the argument, else the SDP address that Diameter, GTP or PFCP names as a
UE, else the INVITE's SDP address), `icid`, `final_status`, `first_broken_link` and a `verdict`
sentence. `summary`: calls, intact chains, first broken links, protocols captured. `window_s` (10)
bounds each join
