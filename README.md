# tshark-mcp

[![CI](https://github.com/Kx96xx/tshark-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Kx96xx/tshark-mcp/actions/workflows/ci.yml)

A read-only [MCP](https://modelcontextprotocol.io) server that lets an LLM agent analyse
existing packet captures through `tshark`, with dedicated tools for the mobile-core
protocols (Diameter, GTPv2-C, GTPv1-C, GTP-U, SIP with RTP/RTCP media, and SCTP/M3UA/SCCP/TCAP/MAP) and for
DNS, TLS handshakes and TCP response times.

The server can only ever run `tshark -r <file>` on files inside directories you allow,
under hard limits on file size, packets, output size and run time. It cannot capture,
write, export, resolve names or load code. That is the point: an agent should be able to
read a capture without being able to run one.

## Why

Investigating a failed attach, a dropped bearer or a lost SMS means correlating Diameter,
GTP, MAP and SIP by subscriber across one capture. tshark can do all of it, but an agent
driving a raw shell is a liability. tshark-mcp gives the agent thirty-one narrow tools that
return compact JSON, pair requests with answers, name the codes it sees (Result-Code 5420,
GTP cause 78, MAP opcode 46) and flag what never got a reply. It also says when the capture
itself cannot be trusted: copies of the same packet, packets the capture dropped, cut-short
frames, checksum offload and clocks that run backwards.

## Install

Requires Python 3.10+, the `mcp` package 2.1 or newer and `pydantic` 2.12 or newer (both installed automatically;
CI also runs the suite on the oldest of each) and tshark
4.0 or newer (tested with 4.2 and 4.6). tshark comes with Wireshark:
`brew install --cask wireshark` on macOS, `apt-get install tshark` on Debian or Ubuntu,
`dnf install wireshark-cli` on Fedora.

```sh
pipx install git+https://github.com/Kx96xx/tshark-mcp
# or, from a clone
uv tool install .        # or: pipx install .
```

## Run

```sh
tshark-mcp --allow-dir /path/to/pcaps [--allow-dir /another] [--log-file ~/tshark-mcp.jsonl]
```

Every path argument an agent passes must resolve (symlinks followed) to a file inside one of
the allowed directories. `TSHARK_MCP_ALLOW_DIRS` (colon-separated) works instead of the flag.

The supported transport is stdio: the client starts the server as a child process and
nothing listens on the network. `--transport streamable-http` exists for local
experiments only. It has no authentication, so never expose it beyond localhost or put it
in front of captures you would not hand to anyone who can reach that port.

### Redaction

Telecom captures carry IMSIs, MSISDNs, IMEIs, SIP users and UE addresses. To hand results
to a hosted model or paste them into a ticket without those values, start the server with
`--redact ids` (or `TSHARK_MCP_REDACT=ids`), or pass `redact="ids"` on a single call. A
call can raise the server's level, never lower it.

```
diameter_sessions(path="/pcaps/dra.pcap", imsi="001010123456789")
-> {"sessions": [{"user_name": "imsi:3f2a9c1b0d", ...}],
    "redaction": {"mode": "ids", "replaced": {"imsi": 1}, "stable": "for this server run", ...}}
```

* `ids` replaces IMSIs, MSISDNs and other E.164 numbers (global titles included), IMEI/IMEISV,
  SIP and tel URI users, and UE addresses (PAA, PDN address, PFCP UE IP, the inner
  addresses of GTP-U tunnels). `ids+ips` also replaces every IPv4 and IPv6 address.
* A token is the first 40 bits of an HMAC-SHA256 of the value. The same value gives the same
  token in every result, so rows from different tools still join. The prefix (`imsi`,
  `msisdn`, `imei`, `user`, `ip`, `id`) is only a hint. The key is random for each run, or
  `TSHARK_MCP_REDACT_KEY` (16 characters or more) to keep tokens across runs; keep that key
  secret, since anyone holding it can test guesses. `--redact-keep-prefix` keeps the IMSI's
  MCC-MNC and the IMEI's TAC in clear (`imsi:001-01:3f2a9c1b0d`).
* Tokens work as arguments: `trace_subscriber(imsi="imsi:3f2a9c1b0d")`, a display filter
  `e212.imsi == "imsi:3f2a9c1b0d"`, or a file name shown with a token in it. The server keeps
  the token-to-value table in memory only and refuses tokens it did not issue. A call that
  passes a token is redacted even without `redact`.
* Values are found by key (`imsi`, `msisdn`, `user_name`, tshark fields such as `e212.imsi`,
  `gtpv2.mei`, `sip.from.user`) and in any string: URI users, `<digits>@realm` NAIs, known
  values as digits, ASCII hex or TBCD hex (raw AVP bytes, for example), any run of 14
  to 20 digits (`id:`), and 11 to 13 digit runs in file names. Keys of the result and the
  audit log are redacted too.
* Limits: names in free text (SIP display names, SMS text) are not touched; a number of 13
  digits or fewer, and in `ids` mode a UE address, is replaced only once the server has seen
  it under a known key or in a URI, in this call or an earlier one (a first `conversations`
  call shows UE addresses in clear: use `ids+ips` when addresses matter); values inside compressed or encrypted payloads, split across
  fields, or in other encodings are not found; host names, realms, APNs and MAC addresses
  are kept. Redaction rewrites results only: the capture is never changed or written.

Claude Code:

```sh
claude mcp add tshark-mcp -- tshark-mcp --allow-dir /path/to/pcaps
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tshark-mcp": {
      "command": "tshark-mcp",
      "args": ["--allow-dir", "/path/to/pcaps"]
    }
  }
}
```

## Tools

| Tool | What it returns |
| --- | --- |
| `find_identifier(path, identifier, kind, max_files, offset)` | Which captures in a directory (or one file) mention an IMSI, MSISDN, IP address, SIP Call-ID or Diameter Session-Id: hits, first/last timestamp and protocol breakdown per file, bounded by a file-count cap and one shared time budget; files without hits that were only read up to the frame cap are listed in `partially_scanned` |
| `pcap_info(path)` | Packet count, duration, first/last timestamp, size, link type, top 15 protocol-hierarchy entries, active limits |
| `capture_quality(path)` | Whether loss and timing conclusions can be drawn from the capture: duplicate copies of the same packet with the likely cause (two VLANs or interfaces, a Linux any capture, tunnelled and decapsulated, rebuilt copies with zeroed TCP headers); TCP bytes the receiver acknowledged that the capture never saw (dropped by the capture, or the file was filtered) versus gaps a retransmission filled (lost on the network before the capture point); frames cut to the snapshot length; packets above 1500 bytes (segmentation offload); bad IP/TCP/UDP checksums and whether they are offload artifacts (one sender, data acknowledged anyway); TCP streams seen in one direction only and unanswered SYNs; timestamps going backwards, identical stamps, resolution, longest silence; a `verdict` (trustworthy, use with care, not trustworthy) with the reasons |
| `tcp_health(path, filter, stream, mtu, limit, offset)` | Per TCP stream, with copies of the same packet dropped first (tshark counts them as retransmissions): handshake with SYN retries, the SYN to SYN-ACK and SYN-ACK to ACK halves of the RTT, MSS, window scale and SACK; per direction data segments and retransmissions split by where the loss happened (`lost_before_capture`, `retransmitted_after_capture`, `missed_by_capture` when the receiver acknowledged bytes the file lacks), reordering told apart by IP ID or TCP timestamp, duplicate ACKs, zero windows, keep-alives; `resets` with `likely_from` endpoint or middlebox from the reset's TTL and source MAC against that side's other packets, and the idle time before it; ICMP errors about the stream; MSS above `mtu`, DF packets above it and the PMTUD black-hole pattern (full-size segments retransmitted and never acknowledged while small ones pass); `issues` in plain words |
| `conversations(path, layer, filter, limit, offset)` | Top talkers at `ip`, `ipv6`, `tcp`, `udp`, `sctp` or `eth` with frames and bytes per direction, optionally restricted by a display filter |
| `filter_packets(path, display_filter, fields, limit, offset)` | Rows of fields for packets matching a display filter; field names are validated against `tshark -G fields` |
| `packet_detail(path, frame, layers, max_fields)` | One frame's full dissection as tshark decodes it, every layer and field nested as in Wireshark's details pane; `layers` keeps only the protocols named; at most `max_fields` leaf fields (default 300, server cap 2000), the innermost layers first, with `fields_dropped` for the rest; `malformed` when tshark flagged the packet. Use it to verify any row: rows carry `frame`, `request_frame`/`answer_frame` or `first_frame`/`last_frame` |
| `expert_info(path, severity, filter, limit, offset)` | tshark's own expert information (`-z expert`): warnings, errors and malformed-packet flags grouped by severity, group (Malformed, Undecoded, Sequence, Protocol, ...), protocol and summary, with the count, first frame and up to five sample frames of each; `summary` counts by severity and protocol and the malformed frames. Check it before trusting a decode |
| `find_fields(query, protocol, limit, offset)` | Search the fields and protocols this tshark knows (`tshark -G fields`): every word of `query` must appear in the abbreviation, name or description; `protocol` keeps one protocol's fields; rows give the abbreviation, name, type, protocol, display base and description, exact matches first. No capture is read |
| `check_filter(filter)` | Check a display filter without reading a capture: the server lint, then tshark compiles it against an empty capture and its own error comes back with the offset and length it points at; dftest warnings (deprecated names) when dftest is installed beside tshark (`warnings_checked`); the fields the filter names, with their types |
| `diameter_sessions(path, session_id, imsi, command_code, filter, limit, offset)` | Diameter grouped by Session-Id: application, hosts, realms, User-Name, first/last time, request and answer command codes, every Result-Code, unanswered and failed counts, worst RTT, and the paired transactions |
| `diameter_transactions(path, filter, limit, offset)` | Requests paired with answers by Hop-by-Hop/End-to-End id and Session-Id: command name, application, hosts, realms, User-Name, Result-Code or Experimental-Result-Code with name, RTT, `unanswered` |
| `diameter_avps(path, session_id, imsi, command_code, frame, filter, detail, max_avps, limit, offset)` | The AVPs of paired Diameter transactions. `detail="key"`: Result-Code and Experimental-Result, ULR/ULA/CLR/PUR/PUA/IDR/NOR flags with bit names, Cancellation-Type, RAT-Type, Visited-PLMN-Id, AIR vectors, Gx CC-Request-Type, Event-Trigger, rule reports and QoS, and a Subscription-Data digest (MSISDN, status, ODB, access restrictions, AMBR, one line per APN with PDN type, QCI, ARP, AMBR and PGW). `detail="full"`: every AVP as a nested tree, capped at `max_avps` leaves per message (server cap 2000); enumerated values are named |
| `gtp_sessions(path, imsi, apn, teid, filter, limit, offset)` | GTPv2-C requests paired with responses by sequence and peer (across a NAT too, with `response_path`): message name, IMSI, MSISDN, APN, F-TEIDs with interface names, cause code and name, PAA, RTT, `unanswered` (legs of a proxy chain answered elsewhere get `leg_without_response` and a `note` instead, packets captured twice `duplicate_of_frame`); the structured filters keep both halves of each transaction, and `apn` given as a network identifier also matches it with the operator identifier appended |
| `gtpv1_sessions(path, imsi, apn, teid, filter, limit, offset)` | GTPv1-C (Gn/Gp) requests paired with responses by sequence and peer (across a proxy too, with `response_path`): Create/Update/Delete PDP Context and the rest, IMSI, MSISDN, APN, NSAPI, RAT type, IMEISV, TEID-C/TEID-U and GSN address on each side, end-user address, cause code and name, RTT, `unanswered`, and the same proxy-chain fields as gtp_sessions |
| `gtp_user_plane(path, teid, limit, offset)` | GTP-U per TEID: packets, bytes, first/last time, outer endpoints, inner IP addresses |
| `gtp_tunnel_health(path, teid, mtu, limit, offset)` | User-plane health per GTP-U tunnel from the packets inside it: inner TCP flows, SYN/SYN-ACK MSS, retransmissions and their share of data segments split like `tcp_health` (`lost_before_capture` when the resend filled a gap, `retransmitted_after_capture` when the capture had already seen the bytes), out-of-order segments (filled a gap but were overtaken, not lost), keep-alives, duplicate ACKs, zero windows, resets; inner ICMP by type with the fragmentation-needed MTU; largest outer and inner packets, tunnel overhead and DF packets above `mtu`; whether the reverse direction carries traffic; `issues` in plain words; ICMP errors sent about the tunnel packets themselves (`outer_icmp`). Copies of the same packet (a capture on several interfaces) are counted once |
| `message_rates(path, protocol, interval, imsi, filter, burst_min, storm_min, limit, offset)` | Diameter, GTPv2-C, GTPv1-C, SIP and MAP messages counted by name per interval: total and distinct (a message seen on both legs of a relay or retransmitted counts once), peak and when, mean rate; `bursts` (three times the usual rate or more), `subscriber_loops` (one subscriber repeating a request, with the gap between repeats and whether it is regular), a per-interval `timeline` and one-line `storms`. MAP messages are tied to the IMSI named anywhere in their TCAP dialogue, GTP responses to the IMSI of their request |
| `pfcp_sessions(path, seid, ue_ip, view, filter, limit, offset)` | PFCP (N4/Sxa/Sxb, TS 29.244) requests paired with responses and grouped into sessions by their CP and UP F-SEIDs. `view="sessions"`: per session the SEIDs and addresses, UE IP, network instance/DNN, establishment and deletion results, modifications (and rejected ones), Session Report counts by type (DLDR, USAR, ERIR, UPIR), summed usage-report volumes, `state` and `issues` (a rejection with its cause, a FAR switched to BUFF or DROP, 'Session context not found', requests without a response). `view="transactions"`: cause code and name, offending IE, rule counts, FAR apply actions, report types and usage reports per pair; copies of one packet are marked. `nodes`: association result, heartbeats and Recovery Time Stamp changes (peer restarts). `seid` or `ue_ip` select one session, both sides |
| `dns_transactions(path, name, filter, limit, offset)` | DNS queries paired with responses by transport, addresses, ports, DNS id and name, unanswered ones included: type, rcode name, answers and addresses, RTT, `unanswered` (`near_capture_end` when the capture may have stopped first), resends with the same id and port, `retry_of` for a new query after an unanswered or failed one, TC answers and the TCP fallback that followed; per-server answered share, rcodes and latency min/p50/p90/p99/max; the names that failed, were retried or were slow; `issues`. Copies of one packet (several interfaces, GTP legs) count once, DNS inside GTP-U is read from the inner packet, and problem transactions come first |
| `tls_handshakes(path, server_name, filter, limit, offset)` | TLS over TCP and QUIC per connection, from the clear part of the handshake (no decryption, no key material): the client's offer (SNI, ALPN, versions, cipher-suite count without GREASE, fallback SCSV) against the server's choice (version, suite, ALPN when in clear), HelloRetryRequest, SYN-to-ClientHello and ClientHello-to-ServerHello times, alerts with level, name and sender (QUIC CONNECTION_CLOSE too), the leaf certificate for TLS 1.2 and older (subject, issuer, SAN, validity, chain length), and an `outcome`: established, alert, no_server_hello, reset_by_server, closed_by_server, client_gave_up, client_rejected_likely (TLS 1.3 alert-sized record instead of Finished), unreadable, incomplete, or server_hello for QUIC; `issues` names expired certificates, SNI/SAN mismatches, deprecated or unoffered versions and repeated ClientHellos. A connection whose ClientHello is not readable is still listed (`client_hello_missing`) when its ServerHello, certificate or alerts are. Copies of the same packet are found with the same rule as `tcp_health` (same IP ID and transport header, or with IP ID 0 the same checksum within a few milliseconds), plus a tap's copies with the TCP header or the IP ID zeroed; they are counted in `duplicate_copies` and never taken for a resent ClientHello or alert |
| `rtp_streams(path, call_id, ssrc, heuristic, filter, limit, offset)` | Per RTP stream (SSRC and source/destination address:port): the SIP Call-ID whose SDP advertised its destination (or source) address and port, payload type and codec from the SDP rtpmap or the static table, packets, expected, lost and lost %, duplicates, sequence errors, out-of-order packets, max/mean interarrival delta, RFC 3550 max/mean jitter, duration, first and last frame, the reverse stream or `one_way`, RTCP reception reports about it (fraction and cumulative lost, jitter, round trip where the LSR matches a captured SR), RTCP XR VoIP metrics as reported, and `mos_estimate`: a simplified ITU-T G.107 E-model score from loss, jitter, delay and the codec's G.113 Ie/Bpl, returned with its method and inputs because it is an estimate, not a measured MOS. `call_id` reads the RTP to or from the call's SDP addresses, so a NATed source is still found; `heuristic` decodes RTP without SDP in the capture. Packets, lost, max delta and max jitter match `tshark -z rtp,streams` |
| `sip_call_detail(path, call_id)` | One INVITE call by Call-ID, built on the `sip_dialogs` row: the ladder with the messages that carry SDP marked, `outcome`, final response with its reason phrase, post-dial delay (INVITE to the first 180/183, or to the failure response as RFC 6076 defines it), ringing, answer and setup times, early media, call duration from 200 OK to BYE, retransmissions per message, Reason headers with the Q.850 cause named, Warning headers, whether the caller or the callee sent BYE or CANCEL (by From tag), and each SDP with its offer/answer role, address, port, codecs, direction and ptime, plus the codecs offer and answer (or a 488's SDP) have in common |
| `response_times(path, filter, limit, offset)` | Where the time goes per TCP flow: each connection cut into exchanges (client data, then the server's answer) with think time, `server_ms` (think time less the capture-to-server round trip, so it holds at any capture point), transfer time, retransmissions and out-of-order segments (told apart by IPv4 ID), stalls with their cause (retransmission, zero_window, server_pause), HTTP/1.x method, URI and status when dissected; on HTTP/2 and gRPC that tshark dissects (cleartext h2c on any port with tshark 4.4.0 and later; tshark 4.2 finds it only on an HTTP port such as 80 or 8080; TLS only with keys) one exchange per stream (`h2_stream`) labelled with :method, :path, :authority, :status and `grpc_status`, RST_STREAM as `stream_reset_by`, pushed streams as `server_pushes`; per flow the handshake (or ACK) round trip, lost SYNs or SYN-ACKs with the time to connect, which side the capture sits near, `time_split_ms` and a `verdict`: server-bound, network-bound, receiver-bound, fast, idle-or-push (answers only after 10 s: long polls, push channels) or no-response; per-server server_ms percentiles, SYNs never answered or refused (`not_opened`). One connection split over several tcp.stream numbers by a tap's copies is joined |
| `media_path_check(path, call_id, heuristic)` | One call's SDP offer and answer (the last completed exchange, so a re-INVITE wins) against the RTP captured in each direction: per direction the expected source and destination, the streams seen and a status (as negotiated, arrives from another source, sent elsewhere, missing); `issues` such as no_rtp, one_way_media, source_differs_from_sdp, nat_not_latched (a private SDP address the far end keeps sending to), rtp_to_wrong_address, private_sdp_address, media_direction (hold), media_rejected, payload_type_not_negotiated, codec_mismatch (no codec in common between the offer and the answer or a 488's SDP) and no_answer; `verdict` in one sentence |
| `dtmf_events(path, call_id, heuristic, limit, offset)` | DTMF digits in time order from RFC 4733/2833 telephone-events (one row per digit however many update and end packets: duration, volume, end packets, payload type, SSRC, call) and SIP INFO (application/dtmf-relay, application/dtmf, KPML) with the INFO's response status; each RTP event is checked against the telephone-event payload type the call's SDP negotiated, and `issues` flag an unnegotiated payload type, a digit without an end packet, or a rejected or unanswered INFO; `calls` gives the digits per call and method and notes calls that use both |
| `sip_dialogs(path, call_id, number, method, filter, limit, offset)` | Messages grouped by Call-ID: method chain, From, To, Request-URI, P-Asserted-Identity, final status, outcome after any 401/407 challenge, retransmission count, time to final response, dialog duration; a TCP segment carrying several SIP messages is split so each message joins its own dialog |
| `sctp_associations(path, limit, offset)` | Per endpoint pair: handshake state, initiate tags, DATA chunks, heartbeats sent vs acked, retransmissions, ABORT/SHUTDOWN seen |
| `sigtran_messages(path, filter, limit, offset)` | M3UA/SCCP/TCAP/MAP: SCCP type and segmentation, calling/called GT and SSN, point codes, TCAP primitive and ids, components with MAP operation name, IMSI, MSISDN; Begins linked to their End |
| `compare_captures(path_a, path_b, imsi, msisdn, imsi_b, msisdn_b, collapse_repeats, limit, offset)` | A working and a failing capture of the same procedure side by side: both message ladders (the subscriber trace, or every transaction without an identity), keepalives dropped, identical retries merged with a `repeat` count, aligned by protocol and message; `first_divergence`, every step as same, changed, replaced, only_a or only_b, the `differences` of changed steps (result, pairing, key Diameter AVPs, GTP IEs; identities ignored) and the largest round-trip and offset gaps |
| `trace_subscriber(path, imsi, msisdn, limit, offset)` | One time-ordered timeline for a subscriber across Diameter, GTPv2-C and GTPv1-C (following control-plane TEIDs), PFCP (by IMSI or the UE address GTP allocated, then by SEID), MAP and SIP, each row with protocol, message, result and pairing; all passes share one time budget and a spent budget returns the partial timeline with `truncated` |

Every tool returns JSON and publishes a typed `outputSchema`, a title and the MCP
annotations `readOnlyHint`, `idempotentHint` and `openWorldHint: false`. Failures come back
as `{"error": {"type": ..., "message": ...}}` rather than exceptions.

Every tool that takes a `limit` also takes an `offset` and returns one page:
`total_matched` rows were found, `returned` of them are in this page starting at `offset`,
`dropped` come after it, and `next_offset` (present only when more rows exist) fetches the
next page with the same arguments (`count` and `total_found` are the older names of
`returned` and `total_matched`). `"truncated": true` always comes with a `truncated_reason`
that says how to get the rest. `total_is_lower_bound: true` means a packet or frame cap
stopped the scan, so more rows exist than were counted and paging cannot reach them:
narrow the filter. The output cap (30 KB by default, about 8k tokens) keeps the longest
prefix of rows that fits and moves `next_offset` to the first row it left out; an inner
list it had to shorten is named in `trimmed` with how many items were kept. In
`find_identifier` the offset counts files of the directory, not rows.

Rows carry the frame numbers they were built from: `frame` on per-packet rows (including
`filter_packets` rows when `frame.number` was not one of the fields), `request_frame` and
`answer_frame` on paired transactions, `first_frame` and `last_frame` on aggregates
(tunnels, SCTP associations, files found by `find_identifier`, message types and
subscriber loops in `message_rates`). `packet_detail(path, frame)` opens any of them.

A capture that ends in the middle of a packet (a ring-buffer file copied while it was being
written) is read up to the damage, and the result carries `"warnings"` saying so. See
[docs/EXAMPLE.md](docs/EXAMPLE.md) for a worked investigation with real output, and
[llms.txt](llms.txt) for a one-page description aimed at agents.

### Examples

Which file in the ring buffer has the subscriber, and when:

```
find_identifier(path="/pcaps/signalling", identifier="001010123456789")
-> {"kind": "subscriber", "files_scanned": 7, "files_with_hits": 4,
    "files": [{"path": ".../all.pcap", "hits": 5, "first": "...T22:13:20.000Z", "last": "...T22:21:41.000Z",
               "protocols": {"DIAMETER": 2, "GTPv2": 1, "GSM MAP": 1, "GSM SMS": 1}}, ...]}
```

Every Diameter session of one IMSI, answers included, with the codes that came back:

```
diameter_sessions(path="/pcaps/diameter.pcap", imsi="001010123456789")
-> {"sessions": [{"session_id": "mme01...;1700000000;1", "application": "S6a/S6d", "request_codes": [316],
                  "answer_codes": [316], "result_codes": [2001], "unanswered": 0, "failed": 0, "max_rtt_ms": 48.0,
                  "transactions": [{"request": "ULR", "answer": "ULA", "result": "DIAMETER_SUCCESS", "rtt_ms": 48.0}]},
                 {"session_id": "mme01...;1700000000;3", "request_codes": [318], "unanswered": 1, ...}]}
```

Everything that touched one PGW control TEID, including the Delete Session that never got a response:

```
gtp_sessions(path="/pcaps/gtpv2.pcap", teid="0xc001")
-> {"transactions": [{"message": "Create Session Request", "response": "Create Session Response", "cause_name": "Request accepted", ...},
                     {"message": "Delete Session Request", "teid": "0x0000c001", "unanswered": true}]}
```

The REGISTER dialogs, with their final responses kept (a raw `sip.Method == "REGISTER"` filter would drop the 401):

```
sip_dialogs(path="/pcaps/sip.pcap", method="REGISTER")
-> {"dialogs": [{"call_id": "reg-77@ue.example", "initial_method": "REGISTER", "final_status": 401,
                 "time_to_final_ms": 40.0, "duration_ms": 40.0, "methods": ["REGISTER"]}]}
```

What the HSS sent back in the Update-Location answer, and why the MME asked:

```
diameter_avps(path="/pcaps/diameter.pcap", command_code=316)
-> {"transactions": [{"request": "ULR", "answer": "ULA", "result": "DIAMETER_SUCCESS",
     "request_avps": {"ULR-Flags": "34 [S6a/S6d-Indicator, Initial-Attach-Indicator]", "RAT-Type": "EUTRAN (1004)", ...},
     "answer_avps": {"Result-Code": 2001, "subscription": {"MSISDN": "15550100123", "Subscriber-Status": "SERVICE_GRANTED (0)",
                     "apns": [{"context": 1, "apn": "internet.test", "pdn_type": "IPv4v6 (2)", "qci": 9, ...}]}}}]}
```

Where a failing attach first departs from a working one:

```
compare_captures(path_a="/pcaps/working.pcap", path_b="/pcaps/failing.pcap", imsi="001010123456789")
-> {"summary": {"same": 0, "changed": 2, "replaced": 0, "only_a": 0, "only_b": 0},
    "first_divergence": {"op": "changed", "a": {"message": "ULR/ULA", ...}, "b": {"message": "ULR/ULA", ...},
                         "differences": {"answer_avps.subscription.apns[ims].apn": {"a": "ims", "b": null}, ...}},
    "ladder": [..., {"op": "changed", "a": {"message": "Create Session Request", "result": "Request accepted"},
                     "b": {"message": "Create Session Request", "result": "Missing or unknown APN"},
                     "differences": {"result": {...}, "paa_allocated": {"a": true, "b": false}, ...}}]}
```

Why a bearer is slow: the MSS the UE announced does not fit the tunnelled path:

```
gtp_tunnel_health(path="/pcaps/userplane.pcap")
-> {"tunnels": [{"teid": "0x00001001", "tunnel_overhead": 36, "max_outer_ip_len": 1476,
                 "tcp": {"syn": 1, "mss_in_syn": {"1460": 1}, "data_segments": 27, "data_retransmissions": 3, ...},
                 "issues": ["MSS 1460 in a SYN on this tunnel lets the peer send inner packets of 1500 bytes, 1536 bytes
                            once tunnelled (36 bytes of overhead), above the 1500-byte path MTU; an MSS of at most 1424 fits"]}],
    "outer_icmp": [{"error": "fragmentation needed", "mtu": 1450, "count": 1, "teids": ["0x00001001"]}]}
```

Can a missing packet in this file be read as network loss?

```
capture_quality(path="/pcaps/span.pcap")
-> {"duplicates": {"copies": 10, "share": 0.2857, "causes": {"seen on two VLANs (SPAN of both ingress and egress)": 10}, ...},
    "tcp_capture_gaps": {"missed_by_capture": 1, "missed_bytes": 400, "lost_before_capture": 0, ...},
    "checksums": {"bad": {"tcp": 10}, "bad_tcp_segments_acknowledged": 10, "likely_offload": true, ...},
    "verdict": {"loss_conclusions": "not trustworthy",
                "reasons": ["10 duplicate copies (28.6% of IP packets; seen on two VLANs ...): raw tshark retransmission and duplicate-ACK flags count these copies ...",
                            "the capture missed 1 TCP gap (400 bytes) that the receiver acknowledged: the capture dropped them ..."],
                "notes": ["bad checksums are checksum offload: ... Not a network fault"]}}
```

Why does the upload stall after the handshake?

```
tcp_health(path="/pcaps/upload.pcap", mtu=1400)
-> {"streams": [{"stream": 0, "client": "192.0.2.90:40001", "server": "198.51.100.90:443",
     "handshake": {"server_side_rtt_ms": 30.0, "client_side_rtt_ms": 2.0, "rtt_ms": 32.0, "client_mss": 1460, "server_mss": 1460, ...},
     "server_to_client": {"data_segments": 7, "max_segment": 1460, "retransmissions": 3, "retransmitted_after_capture": 3, ...},
     "icmp": [{"from": "203.0.113.1", "error": "fragmentation needed", "mtu": 1400, "count": 1}],
     "issues": ["the client announced MSS 1460: the server may send packets of 1500 bytes, above the 1400-byte path MTU; an MSS of at most 1360 fits", ...,
                "server to client: full-size segments (1460 bytes) were retransmitted 3 times and never acknowledged while smaller packets got through: a path MTU black hole ..."]}]}
```

Who reset the connection?

```
tcp_health(path="/pcaps/idle.pcap")
-> {"streams": [{"resets": [{"from": "server", "ttl": 61, "usual_ttl": 50, "mac": "02:00:00:00:00:99", "usual_mac": "02:00:00:00:00:02",
                             "idle_before_s": 3600.01, "likely_from": "middlebox", ...}, {"from": "client", "likely_from": "middlebox", ...}],
     "issues": [..., "resets towards both ends that neither end sent: typical of a firewall or IPS tearing the connection down"]}]}
```

Is this a purge storm, and how fast is it looping?

```
message_rates(path="/pcaps/dra.pcap", interval=10)
-> {"messages": 577, "distinct_messages": 317, "copies": 260,
    "by_message": [{"message": "AIR", "total": 113, "distinct": 57, "peak": 2, ...}, ...],
    "subscriber_loops": [{"subscriber": "001010123456789", "message": "PUR", "count": 6, "median_gap_s": 10.0, "regular": true}],
    "storms": ["6 ULR for 001010123456789 over 50.0 s, about every 10.0 s", ...]}
```

Top talkers on the Diameter port only:

```
conversations(path="/pcaps/all.pcap", layer="sctp", filter="sctp.port == 3868")
-> {"conversations": [{"a": "192.0.2.10:3868", "b": "192.0.2.20:3868", "frames_total": 7, "bytes_total": 1970, ...}],
    "total_frames": 7}
```

## Safety model

The limits are the product. Each one is enforced in code, the numeric ones are
configurable, and none can be switched off.

| Control | Default | Where |
| --- | --- | --- |
| Path allowlist: resolved real path must sit under an `--allow-dir`; paths outside are refused before existence is checked | none (server refuses to start) | `limits.Allowlist` |
| Maximum capture size | 500 MB (`--max-file-mb`, `TSHARK_MCP_MAX_FILE_MB`) | `limits.Limits` |
| Matching packets dissected in full per call by the per-packet tools (Diameter, GTPv2-C, SIGTRAN) | 500 (`--max-packets`, `TSHARK_MCP_MAX_PACKETS`) | `limits.Limits` |
| Frames read from a capture per tshark run (`-c`), and matching packets kept by the aggregating tools (`gtp_user_plane`, `sctp_associations`, `sip_dialogs`, `rtp_streams`, `find_identifier`); a longer capture is reported as truncated | 200 000 (`--max-scan-packets`, `TSHARK_MCP_MAX_SCAN_PACKETS`) | `limits.Limits` |
| Hard ceiling on any `-c` the runner will pass, whatever a tool asks for | `max_scan_packets` + 1 (one sentinel frame that shows whether the file goes on) | `runner.Runner.read_capture` |
| Files opened by one `find_identifier` call | 50 (`--max-files`, `TSHARK_MCP_MAX_FILES`), and the whole call shares one `--timeout` budget | `limits.Limits`, `server.find_identifier` |
| JSON returned per call | 30 KB (`--max-output-kb`, `TSHARK_MCP_MAX_OUTPUT_KB`); rows past it are left for the next page (`next_offset`), inner lists cut to fit are named in `trimmed` | `server._fit` |
| Raw tshark stdout kept in memory | 64 MB (`TSHARK_MCP_MAX_STDOUT_MB`); tshark is killed beyond it | `runner.Runner` |
| Wall-clock per tshark run | 60 s (`--timeout`, `TSHARK_MCP_TIMEOUT`); tshark is killed beyond it | `runner.Runner` |
| Wall-clock per multi-pass call (`find_identifier`, `trace_subscriber`) | the same `--timeout`, shared by every tshark run of the call | `server.find_identifier`, `server.trace_subscriber` |
| Read-only argv | `-r` is mandatory; `-i`, `-w`, `-D`, `-f`, `-a`, `-b`, `-X`, `-o`, `--export-*` and the other capture, write and extension flags are refused before a process is created. The one exception is `-o` followed by exactly `ip.check_checksum:TRUE`, `tcp.check_checksum:TRUE` or `udp.check_checksum:TRUE`, which `capture_quality` sets itself to validate checksums; no agent argument reaches `-o`. `-z` takes only the read-only statistics `io`, `conv`, `endpoints`, `expert`, `rtp`, `sip`, `diameter`, `dns` and `http` | `runner.assert_read_only`, `runner.ALLOWED_PREFERENCES`, `runner.ALLOWED_STATS` |
| No shell, no name resolution | argv list only, `-n` on every run | `runner.Runner` |
| Display filters | linted for control characters and shell metacharacters outside quoted strings, then compiled by tshark against an empty capture before touching the real file. `check_filter` also runs `dftest -- <filter>` when dftest sits beside tshark: it compiles the filter and reads no file | `limits.lint_display_filter`, `runner.validate_display_filter`, `runner.dftest_filter` |
| Field names | must exist in `tshark -G fields` (cached once) | `fields.validate_fields` |
| Structured arguments (`session_id`, `call_id`, `imsi`, `apn`, `teid`, `method`, `identifier`) | linted to the shape of that identifier before being embedded in a display filter; quotes and backslashes are refused | `limits.lint_*`, `search.build_filter` |
| Text copied from packets | every string in a result loses control characters, bidirectional overrides and zero-width characters; SIP names and URIs, Diameter hosts, realms and Session-Ids, DNS names, TLS certificate fields, APNs, expert summaries and other free text are capped at 256 characters, and decoded values (`packet_detail` layers, `filter_packets` values, AVP trees) at 512, with a `...[+N chars]` marker; `untrusted_text_fields` names the keys in each result that hold packet text, which is data from the network, never instructions | `untrusted.apply` |
| Subscriber identifiers | off by default; `--redact ids` or `ids+ips` (or `redact=` on a call) replaces them with keyed tokens before the length caps run; tokens map back to values in memory only, nothing is written | `redact.Redactor`, `server._guarded` |
| Audit log | one JSON line per call: tool, arguments (redacted when redaction is on), duration, status, bytes returned (`--log-file`, `TSHARK_MCP_LOG`) | `server._audit` |

The test-suite covers each of these, including the timeout and output cap against a fake
tshark subprocess, and drives the real server over stdio through the MCP client to check
the published schemas and annotations.

## Limitations

* No live capture, by design. The server reads files that already exist and nothing else.
* No decryption: IPsec, TLS and ciphered NAS are reported as tshark sees them. `tls_handshakes`
  reads only the clear part of the handshake; after a TLS 1.3 ServerHello its outcome is inferred
  from the record pattern and says so.
* Large captures are slow. tshark reads the whole file for every call; a 500 MB capture
  with a selective filter takes tens of seconds, so prefer pre-sliced captures.
* Pairing follows what is in the file. A request whose answer was captured on another
  interface is reported as unanswered. A GTP response is matched to a request with the
  same sequence number between the same two hosts first; failing that, one sent by the
  request's target (or to its sender) on another address, as a NAT or proxy shows it,
  with `response_path` set. Unrelated hosts that reuse a sequence number are not paired.
* MAP decoding relies on tshark's dissectors; a segmented XUDT whose other segments are
  missing is reported as segmented, not guessed.

## Roadmap

1. 5G core: HTTP/2 SBI (Nnrf, Nausf, Nsmf) and PFCP session pairing.
2. Streaming per-call progress so a long tshark run can be cancelled from the client.
3. Optional S1AP/NGAP and NAS summaries with EMM/ESM cause names.

## Development

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

The suite is 565 tests and runs in about a minute; CI runs it on Python 3.10 to 3.13 with
the tshark that Ubuntu 24.04 ships (4.2). The tests build their own synthetic captures with
scapy at run time (among them Diameter ULR/ULA and an unanswered AIR, GTPv2-C Create
Session with cause 16 and 78, GTP-U, a SIP INVITE dialog, SIP calls with RTP, RTCP, RFC 4733 events and SIP INFO DTMF (loss,
reordering, jitter, NAT, one-way media, a 488), an SCTP handshake with an
unanswered heartbeat, MAP updateLocation and mo-forwardSM over M3UA, and test-range IMSI,
MSISDN, IMEISV and UE address values for the redaction tests), so nothing in the
repository contains traffic from a real network.

## Licence

MIT, Copyright (c) 2026 Karl Hulse.
