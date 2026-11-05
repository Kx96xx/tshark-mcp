# Validation against public captures

The unit tests prove each tool on synthetic captures built from the specifications
(`tests/pcapgen.py`). To check the tools on traffic nobody wrote for them, the server was run on
public sample captures and every answer was compared with plain tshark.

## What was tested (2026-11-04)

- **102 public captures** from three sets: the Wireshark wiki SampleCaptures (39, GPL), the
  Wireshark repository's `test/captures` (25, GPL-2.0-or-later) and nDPI's test captures (38,
  LGPL-3.0). Areas: DNS, DHCP, HTTP/1.1, HTTP/2, HTTP/3, TLS 1.2/1.3, QUIC, TCP problems, ICMP,
  SIP/RTP/RTCP and DTMF, Diameter, GTP and PFCP, SCTP and SIGTRAN (MAP, CAMEL, TCAP), MQTT/CoAP,
  tunnels (VXLAN, GRE, L2TP, IPsec, WireGuard, Teredo), Kerberos and SMB.
- **1,064 tool calls** over the real MCP stdio client, every tool that applies to each capture.
- **Ground truth** from plain tshark (`-T fields`, `-z` statistics) on the frames involved.
- `pcap_info` packet counts and `conversations` rows matched tshark on all 102 files; DNS,
  Diameter-unanswered and DTMF counts matched after deduplication. 23 defects were found:
  wrong or misleading verdicts, one crash and some friction.

## What was wrong and what changed

| Id | Severity | Defect | Fix |
| --- | --- | --- | --- |
| D1 | high | `filter_packets` crashed when `fields` left out `frame.number` | #114 |
| D2 | high | One-sided TCP captures read as filtered connections and failed TLS handshakes | #120: `one_sided` outcome, one low finding |
| D3 | high | `incident_summary` silent on SCTP, SIGTRAN, PFCP, IKE, Kerberos, CoAP faults | #121: more passes and `not_analysed` |
| D4 | high | QUIC with client and server on one address read as "UDP 443 blocked" | #123: side by address and port |
| D5 | medium-high | Distinct UDP packets (QUIC) counted as capture copies | #124: payload ids in the copy key, window from the first sighting |
| D6 | medium | Identical TCP RSTs counted as capture copies | #124: `repeated_identical` |
| D7 | medium | RTP of the next call attributed to this call, false NAT verdict | #127: link against every SDP, BYE bound |
| D8 | medium | One-way audio flagged when the SDP asks for one-way media | #121: `expected_one_way` |
| D9 | medium | HTTP responses not paired (reassembly, no `request_in`, HTTP/2 header count) | #129: first-segment pass, stream order, HPACK fix; QUIC in `tls_failed`: #121 |
| D10 | medium | IKE "failed" after a normal DH-group retry | #131: outcome from how the negotiation ended |
| D11 | medium | "p99 response" was the transfer time | #129: `ttfb_ms`, slow transfer reported apart |
| D12 | medium | Redaction missed a number inside a USSD string | #134: numbers in USSD/SMS text, packed bytes dropped |
| D13 | low-medium | CAMEL operations not named | #137 |
| D14 | low-medium | SCTP INIT rejections and collision hidden | #137: `inits_aborted`, `init_collision`, issues |
| D15 | low-medium | DNS "slow" from 5 answers; a lost query read as a slow resolver | #139: 10 answers, time from the last resend |
| D16 | low | Happy-eyeballs fallback reported high; refused SYNs counted twice | #139 |
| D17 | low | Diameter result taken from a nested AVP; Gx/Gy naming | #140: command-level result, `mscc_result_codes` |
| D18 | low | gQUIC ignored without a note | #123: `gquic_packets` |
| D19 | low | Heuristic RTP missed RTP inside STUN/TURN | #127 |
| D20 | low | `throughput_timeline` failed by default on long captures | chore/usability: automatic interval |
| D21 | low | `cause_lookup` refused nas, dns, tls | chore/usability: aliases and small tables |
| D22 | low | Teredo and an ERSPAN marker returned nothing and no note | #131: Teredo kind, empty-result note |
| D23 | low | `find_identifier` did not recurse and did not say so | chore/usability: subdirectory hint, default cap |

Each fix has a regression test on a synthetic capture that reproduces the case; the public files
themselves are GPL or LGPL and are never committed here.

## Re-running it

`evals/public/` holds one scenario per defect: the call that showed it, on the same public
capture, and the facts the fixed tool must report. The captures are downloaded by URL and checked
against the SHA-256 in `evals/public/captures.json` (a changed upstream sample is refused). It needs
the network, so it is opt-in and not part of CI:

```sh
python -m evals.public --dir ~/pubcaps --fetch                 # download, verify, run
python -m evals.public --dir ~/pubcaps --report docs/VALIDATION.md   # rewrite the table below
```

## Results on the current main

<!-- public-validation:begin -->
(not run yet)
<!-- public-validation:end -->

## Limits

- Telecom coverage rests on small public files: no public NGAP, S1AP or NAS-5GS capture with clear
  terms was found, and ISUP is not decoded by tshark on the sample that exists.
- About a third of the captures carry a protocol no tool reads (DHCP, MQTT, CoAP, Kerberos, SMB,
  LDAP, NFS/RPC, telnet): `incident_summary` lists those in `not_analysed`.
