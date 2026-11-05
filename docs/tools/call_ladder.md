---
order: 415
readme: A ladder diagram for a ticket: one call (Call-ID, every SIP leg) or one subscriber (IMSI/MSISDN) as a Mermaid sequenceDiagram or text, every arrow labelled with its frame, failing steps marked, roles guessed with evidence
llms: a Mermaid `sequenceDiagram` (or fixed-width text, or `arrows` only) of one call (`call_id`, from call_legs) or one subscriber (`imsi`/`msisdn`, from trace_subscriber); every arrow is `#<frame> <message>`, failures sit in a red `rect` with a Note, `participants` carry a guessed role (MME, HSS, SGW, PGW, PCRF, UPF, caller, SIP proxy) with `role_evidence`; deterministic.
---

Renders rows other tools already build. `call_id` takes the call from call_legs (every leg's SIP
messages, the failing response marked with where_it_failed's status and Q.850 cause); `imsi` or
`msisdn` takes the subscriber's timeline from trace_subscriber (a request and its answer are two
arrows; unanswered requests get a "no answer" Note). `format`: `mermaid` (a `sequenceDiagram` with
`autonumber`, failing arrows inside `rect` blocks), `text` (fixed width, failures marked `!!`) or
`json` (no diagram). Every arrow is labelled `#<frame>`, so the diagram, `arrows` and packet_detail
agree. `participants`: addresses in order of first appearance with a role guessed from what they
send (S6a ULR: MME to HSS; Gx: PGW to PCRF; an S11 MME F-TEID: MME to SGW; PFCP: SMF to UPF; the first
INVITE: caller) and `role_evidence`; `roles=false` leaves roles out. `max_rows` (default 80, at most
400) caps the arrows and `rows_dropped` counts the rest. The same input gives a byte-identical
diagram. Labels are packet text, cut to 60 characters and stripped of characters Mermaid or HTML
would interpret; under redaction the addresses and identities in the diagram are tokens too. Hosts
with MCP Apps can show the result as an SVG ladder (`ui://tshark-mcp/ladder.html`, self-contained,
no network); clicking an arrow asks for packet_detail on that frame
