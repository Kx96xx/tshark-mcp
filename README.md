# tshark-mcp

[![CI](https://github.com/Kx96xx/tshark-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Kx96xx/tshark-mcp/actions/workflows/ci.yml)

A read-only [MCP](https://modelcontextprotocol.io) server that lets an LLM agent analyse
existing packet captures through `tshark`, with first-class support for the mobile-core
protocols: Diameter, GTPv2-C, GTPv1-C, GTP-U, SIP and SCTP/M3UA/SCCP/TCAP/MAP, plus DNS and TLS handshakes.

The server can only ever run `tshark -r <file>` on files inside directories you allow,
under hard limits on file size, packets, output size and run time. It cannot capture,
write, export, resolve names or load code. That is the point: an agent should be able to
read a capture without being able to run one.

## Why

Investigating a failed attach, a dropped bearer or a lost SMS means correlating Diameter,
GTP, MAP and SIP by subscriber across one capture. tshark can do all of it, but an agent
driving a raw shell is a liability. tshark-mcp gives the agent nineteen narrow tools that
return compact JSON, pair requests with answers, name the codes it sees (Result-Code 5420,
GTP cause 78, MAP opcode 46) and flag what never got a reply.

## Install

Requires Python 3.10+, the `mcp` package 1.12 or newer (installed automatically) and tshark
4.0 or newer (tested with 4.2 and 4.6). tshark comes with
Wireshark: `brew install --cask wireshark` on macOS, `apt-get install tshark` on Debian or
Ubuntu, `dnf install wireshark-cli` on Fedora.

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

Tests: 340 (pytest, Python 3.10, 3.11, 3.12 and 3.13 in CI).

| Tool | What it returns |
| --- | --- |
| `find_identifier(path, identifier, kind, max_files)` | Which captures in a directory (or one file) mention an IMSI, MSISDN, IP address, SIP Call-ID or Diameter Session-Id: hits, first/last timestamp and protocol breakdown per file, bounded by a file-count cap and one shared time budget; files without hits that were only read up to the frame cap are listed in `partially_scanned` |
| `pcap_info(path)` | Packet count, duration, first/last timestamp, size, link type, top 15 protocol-hierarchy entries, active limits |
| `conversations(path, layer, filter, limit)` | Top talkers at `ip`, `ipv6`, `tcp`, `udp`, `sctp` or `eth` with frames and bytes per direction, optionally restricted by a display filter |
| `filter_packets(path, display_filter, fields, limit)` | Rows of fields for packets matching a display filter; field names are validated against `tshark -G fields` |
| `diameter_sessions(path, session_id, imsi, command_code, filter, limit)` | Diameter grouped by Session-Id: application, hosts, realms, User-Name, first/last time, request and answer command codes, every Result-Code, unanswered and failed counts, worst RTT, and the paired transactions |
| `diameter_transactions(path, filter, limit)` | Requests paired with answers by Hop-by-Hop/End-to-End id and Session-Id: command name, application, hosts, realms, User-Name, Result-Code or Experimental-Result-Code with name, RTT, `unanswered` |
| `diameter_avps(path, session_id, imsi, command_code, frame, filter, detail, max_avps, limit)` | The AVPs of paired Diameter transactions. `detail="key"`: Result-Code and Experimental-Result, ULR/ULA/CLR/PUR/PUA/IDR/NOR flags with bit names, Cancellation-Type, RAT-Type, Visited-PLMN-Id, AIR vectors, Gx CC-Request-Type, Event-Trigger, rule reports and QoS, and a Subscription-Data digest (MSISDN, status, ODB, access restrictions, AMBR, one line per APN with PDN type, QCI, ARP, AMBR and PGW). `detail="full"`: every AVP as a nested tree, capped at `max_avps` leaves per message (server cap 2000); enumerated values are named |
| `gtp_sessions(path, imsi, apn, teid, filter, limit)` | GTPv2-C requests paired with responses by sequence and peer (across a NAT too, with `response_path`): message name, IMSI, MSISDN, APN, F-TEIDs with interface names, cause code and name, PAA, RTT, `unanswered` (legs of a proxy chain answered elsewhere get `leg_without_response` and a `note` instead, packets captured twice `duplicate_of_frame`); the structured filters keep both halves of each transaction, and `apn` given as a network identifier also matches it with the operator identifier appended |
| `gtpv1_sessions(path, imsi, apn, teid, filter, limit)` | GTPv1-C (Gn/Gp) requests paired with responses by sequence and peer (across a proxy too, with `response_path`): Create/Update/Delete PDP Context and the rest, IMSI, MSISDN, APN, NSAPI, RAT type, IMEISV, TEID-C/TEID-U and GSN address on each side, end-user address, cause code and name, RTT, `unanswered`, and the same proxy-chain fields as gtp_sessions |
| `gtp_user_plane(path, teid, limit)` | GTP-U per TEID: packets, bytes, first/last time, outer endpoints, inner IP addresses |
| `gtp_tunnel_health(path, teid, mtu, limit)` | User-plane health per GTP-U tunnel from the packets inside it: inner TCP flows, SYN/SYN-ACK MSS, retransmissions and their share of data segments, out-of-order segments, keep-alives, duplicate ACKs, zero windows, resets; inner ICMP by type with the fragmentation-needed MTU; largest outer and inner packets, tunnel overhead and DF packets above `mtu`; whether the reverse direction carries traffic; `issues` in plain words; ICMP errors sent about the tunnel packets themselves (`outer_icmp`). Copies of the same packet (a capture on several interfaces) are counted once |
| `message_rates(path, protocol, interval, imsi, filter, burst_min, storm_min, limit)` | Diameter, GTPv2-C, GTPv1-C, SIP and MAP messages counted by name per interval: total and distinct (a message seen on both legs of a relay or retransmitted counts once), peak and when, mean rate; `bursts` (three times the usual rate or more), `subscriber_loops` (one subscriber repeating a request, with the gap between repeats and whether it is regular), a per-interval `timeline` and one-line `storms`. MAP messages are tied to the IMSI named anywhere in their TCAP dialogue, GTP responses to the IMSI of their request |
| `dns_transactions(path, name, filter, limit)` | DNS queries paired with responses by transport, addresses, ports, DNS id and name, unanswered ones included: type, rcode name, answers and addresses, RTT, `unanswered` (`near_capture_end` when the capture may have stopped first), resends with the same id and port, `retry_of` for a new query after an unanswered or failed one, TC answers and the TCP fallback that followed; per-server answered share, rcodes and latency min/p50/p90/p99/max; the names that failed, were retried or were slow; `issues`. Copies of one packet (several interfaces, GTP legs) count once, DNS inside GTP-U is read from the inner packet, and problem transactions come first |
| `tls_handshakes(path, server_name, filter, limit)` | TLS over TCP and QUIC per connection, from the clear part of the handshake (no decryption, no key material): the client's offer (SNI, ALPN, versions, cipher-suite count without GREASE, fallback SCSV) against the server's choice (version, suite, ALPN when in clear), HelloRetryRequest, SYN-to-ClientHello and ClientHello-to-ServerHello times, alerts with level, name and sender (QUIC CONNECTION_CLOSE too), the leaf certificate for TLS 1.2 and older (subject, issuer, SAN, validity, chain length), and an `outcome`: established, alert, no_server_hello, reset_by_server, closed_by_server, client_gave_up, client_rejected_likely (TLS 1.3 alert-sized record instead of Finished), unreadable, incomplete, or server_hello for QUIC; `issues` names expired certificates, SNI/SAN mismatches, deprecated or unoffered versions and repeated ClientHellos. A connection whose ClientHello is not readable is still listed (`client_hello_missing`) when its ServerHello, certificate or alerts are |
| `sip_dialogs(path, call_id, number, method, filter, limit)` | Messages grouped by Call-ID: method chain, From, To, Request-URI, P-Asserted-Identity, final status, outcome after any 401/407 challenge, retransmission count, time to final response, dialog duration; a TCP segment carrying several SIP messages is split so each message joins its own dialog |
| `sctp_associations(path, limit)` | Per endpoint pair: handshake state, initiate tags, DATA chunks, heartbeats sent vs acked, retransmissions, ABORT/SHUTDOWN seen |
| `sigtran_messages(path, filter, limit)` | M3UA/SCCP/TCAP/MAP: SCCP type and segmentation, calling/called GT and SSN, point codes, TCAP primitive and ids, components with MAP operation name, IMSI, MSISDN; Begins linked to their End |
| `compare_captures(path_a, path_b, imsi, msisdn, imsi_b, msisdn_b, collapse_repeats, limit)` | A working and a failing capture of the same procedure side by side: both message ladders (the subscriber trace, or every transaction without an identity), keepalives dropped, identical retries merged with a `repeat` count, aligned by protocol and message; `first_divergence`, every step as same, changed, replaced, only_a or only_b, the `differences` of changed steps (result, pairing, key Diameter AVPs, GTP IEs; identities ignored) and the largest round-trip and offset gaps |
| `trace_subscriber(path, imsi, msisdn, limit)` | One time-ordered timeline for a subscriber across Diameter, GTPv2-C and GTPv1-C (following control-plane TEIDs), MAP and SIP, each row with protocol, message, result and pairing; all passes share one time budget and a spent budget returns the partial timeline with `truncated` |

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
`find_identifier` the offset counts files of the directory, not rows. A capture that ends in the middle of a
packet (a ring-buffer file copied while it was being written) is read up to the damage and
the result carries `"warnings"` saying so. See
[docs/EXAMPLE.md](docs/EXAMPLE.md) for a worked investigation with the real output shapes,
and [llms.txt](llms.txt) for a one-page description aimed at agents.

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

The limits are the product. Each one is enforced in code, configurable, and impossible to
switch off.

| Control | Default | Where |
| --- | --- | --- |
| Path allowlist: resolved real path must sit under an `--allow-dir`; paths outside are refused before existence is checked | none (server refuses to start) | `limits.Allowlist` |
| Maximum capture size | 500 MB (`--max-file-mb`, `TSHARK_MCP_MAX_FILE_MB`) | `limits.Limits` |
| Matching packets dissected in full per call by the per-packet tools (Diameter, GTPv2-C, SIGTRAN) | 500 (`--max-packets`, `TSHARK_MCP_MAX_PACKETS`) | `limits.Limits` |
| Frames read from a capture per tshark run (`-c`), and matching packets kept by the aggregating tools (`gtp_user_plane`, `sctp_associations`, `sip_dialogs`, `find_identifier`); a longer capture is reported as truncated | 200 000 (`--max-scan-packets`, `TSHARK_MCP_MAX_SCAN_PACKETS`) | `limits.Limits` |
| Hard ceiling on any `-c` the runner will pass, whatever a tool asks for | `max_scan_packets` + 1 (one sentinel frame that shows whether the file goes on) | `runner.Runner.read_capture` |
| Files opened by one `find_identifier` call | 50 (`--max-files`, `TSHARK_MCP_MAX_FILES`), and the whole call shares one `--timeout` budget | `limits.Limits`, `server.find_identifier` |
| JSON returned per call | 30 KB (`--max-output-kb`, `TSHARK_MCP_MAX_OUTPUT_KB`); rows past it are left for the next page (`next_offset`), inner lists cut to fit are named in `trimmed` | `server._fit` |
| Raw tshark stdout kept in memory | 64 MB (`TSHARK_MCP_MAX_STDOUT_MB`); tshark is killed beyond it | `runner.Runner` |
| Wall-clock per tshark run | 60 s (`--timeout`, `TSHARK_MCP_TIMEOUT`); tshark is killed beyond it | `runner.Runner` |
| Wall-clock per multi-pass call (`find_identifier`, `trace_subscriber`) | the same `--timeout`, shared by every tshark run of the call | `server.find_identifier`, `server.trace_subscriber` |
| Read-only argv | `-r` is mandatory; `-i`, `-w`, `-D`, `-f`, `-a`, `-b`, `-X`, `-o`, `--export-*` and the other capture, write and extension flags are refused before a process is created | `runner.assert_read_only` |
| No shell, no name resolution | argv list only, `-n` on every run | `runner.Runner` |
| Display filters | linted for control characters and shell metacharacters outside quoted strings, then compiled by tshark against an empty capture before touching the real file | `limits.lint_display_filter`, `runner.validate_display_filter` |
| Field names | must exist in `tshark -G fields` (cached once) | `fields.validate_fields` |
| Structured arguments (`session_id`, `call_id`, `imsi`, `apn`, `teid`, `method`, `identifier`) | linted to the shape of that identifier before being embedded in a display filter; quotes and backslashes are refused | `limits.lint_*`, `search.build_filter` |
| Audit log | one JSON line per call: tool, arguments, duration, status, bytes returned (`--log-file`, `TSHARK_MCP_LOG`) | `server._audit` |

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

The suite is 340 tests and runs in about 30 s; CI runs it on Python 3.10 to 3.13 with the
tshark that Ubuntu 24.04 ships (4.2). Tests build their own synthetic captures with scapy at run time (Diameter ULR/ULA and an
unanswered AIR, GTPv2-C Create Session with cause 16 and 78, GTP-U, a SIP INVITE dialog,
an SCTP handshake with an unanswered heartbeat, MAP updateLocation and mo-forwardSM over
M3UA), so nothing in the repository contains traffic from a real network.

## Licence

MIT, Copyright (c) 2026 Karl Hulse.
