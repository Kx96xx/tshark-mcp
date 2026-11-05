---
order: 190
readme: What a Diameter, GTP, PFCP, NAS, S1AP/NGAP, SIP, Q.850, MAP, SCCP, SGsAP or SMS cause means, with the 3GPP/ITU reference
llms: what a cause or result code means: name (from tshark's value strings), meaning, spec reference (`ref`), typical causes, related codes and the tool calls to find it in a capture. Protocols: diameter (with `application` s6a, gx, rx, cx, sh, ... for Experimental-Result-Codes), gtpv2, gtpv1, pfcp, nas_emm, nas_esm, nas_5gmm, nas_5gsm, s1ap and ngap (`code="radioNetwork:21"`), sip (with `message` REGISTER or INVITE), q850, isup, camel_release, map, tcap_abort, sccp_return, sgsap, rp, cp, tp_status, http_sbi. `query` searches names and meanings. No capture is read.
---

What a cause or result code means, without a capture: the name from tshark's own value strings
(`tshark -G values`; SIP, MAP, CP, TP-Status and SBI causes from the server's table), the meaning,
the spec reference (`ref`), `typical_causes`, `related` codes and `check_next` tool calls.
Protocols: diameter, gtpv2, gtpv1, pfcp, nas_emm, nas_esm, nas_5gmm, nas_5gsm, s1ap and ngap
(`code="radioNetwork:21"`), sip, q850, isup, camel_release, map, tcap_abort, sccp_return, sgsap, rp,
cp, tp_status, http_sbi (ProblemDetails cause strings). Diameter: `application` (s6a, gx, rx, cx,
sh, ...) reads the code as an Experimental-Result-Code (5004 is DIAMETER_INVALID_AVP_VALUE as a
Result-Code and ROAMING_NOT_ALLOWED in S6a), and a code found in both says so in `also`. `message`
(REGISTER, INVITE) adds the per-message note. `explained: false` means only the name is known;
`known: false` that no table names it or it is reserved. `query` lists codes whose name or meaning
holds every word
