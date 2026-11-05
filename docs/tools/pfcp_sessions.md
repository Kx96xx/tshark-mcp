---
order: 290
readme: PFCP (N4/Sx) sessions, rejections, reports, usage and peer restarts
llms: PFCP (N4/Sx) sessions between SMF/PGW-C and UPF/PGW-U: establishment/modification/deletion results with cause names, Session Reports by type (DLDR, USAR, ERIR, UPIR), FAR actions (BUFF/DROP), usage volumes, `state` and `issues`; `nodes` gives heartbeats and peer restarts (Recovery Time Stamp changes). Use it for "session up but no data", UPF rejects and UPF restarts. `view="transactions"` for every request/response pair.
---

PFCP (N4/Sxa/Sxb, TS 29.244) requests paired with responses and grouped into sessions by their CP
and UP F-SEIDs. `view="sessions"`: per session the SEIDs and addresses, UE IP, network instance/DNN,
establishment and deletion results, modifications (and rejected ones), Session Report counts by type
(DLDR, USAR, ERIR, UPIR), summed usage-report volumes, `state` and `issues` (a rejection with its
cause, a FAR switched to BUFF or DROP, 'Session context not found', requests without a response).
`view="transactions"`: cause code and name, offending IE, rule counts, FAR apply actions, report
types and usage reports per pair; copies of one packet are marked. `nodes`: association result,
heartbeats and Recovery Time Stamp changes (peer restarts). `seid` or `ue_ip` select one session,
both sides
