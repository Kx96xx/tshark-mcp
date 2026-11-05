# Changelog

All notable changes to tshark-mcp. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project uses [semantic versioning](https://semver.org/).

## Unreleased

### Added

- Task-success evals (`python -m evals`, docs/EVALS.md): sixteen scenarios over the synthetic
  captures, each an operator question, the calls that answer it and the facts the results must
  hold, with call and token budgets. The harness runs them over the stdio server and scores them
  deterministically, in CI through `tests/test_evals.py`. `--driver llm` lets a model choose the
  calls and scores its final answer as well; it is optional, off by default and never run in CI.
  `--server-dir` and a command after `--` run the scenarios against another stdio server (a
  container). AGENTS.md now names `path_not_allowed` as the error for a path outside the allowlist.

- Six MCP prompts as guided workflows: `one_way_audio`, `subscriber_cannot_attach`,
  `trust_this_capture`, `working_vs_failing`, `ims_registration_or_sms` and `slow_data_session`.
  Each returns the tool calls in order, what to cite, when to stop and the shape of the answer;
  Claude Code lists them as `/mcp__tshark-mcp__<name>`. Their `path` arguments complete
  (`completion/complete`) to capture files and subdirectories inside the allowed directories,
  at most 50 per answer.
- Token-aware output on every tool with `limit`: `columns` keeps only the named row keys (frame
  keys always stay; an unknown name is an `invalid_argument` error listing the valid ones),
  `output="summary"` returns everything but the rows plus the first three rows in under 4 KB with
  paging pointing at the rest, and `max_output_kb` lowers the server's output cap for one call
  (it can never raise it). Every successful result carries `tokens_estimate` (JSON bytes / 3.6).
  The compact tool list writes an optional list argument as `"type": ["array", "null"]`.
- `start` and `end` on every tool that reads a capture: ISO 8601, epoch seconds, `"+120s"` after
  the capture start or `"-30s"` before its end. The window goes ahead of the tool's filter on
  every tshark run, including the `-z` statistics of `conversations`, `expert_info` and
  `pcap_info`; relative bounds resolve per file; results carry `window` and a warning when the
  window misses the capture. `pcap_info` adds `window_hint` and `frames_in_window`;
  `find_identifier` skips files outside the window.
- `capture_index`: a directory of ring-buffer files in time order from capinfos, with per-file
  span, packets, bytes and interfaces, holes and overlaps between files, name-versus-time
  ordering, and which files cover a `start`/`end` window and whether they cover it whole.
- `incident_summary`: the first call on an unknown capture. Runs the overview and the protocol
  tools the capture carries under one time budget and returns findings ranked by severity, each
  one deterministic sentence from a fixed threshold table with its evidence (tool, arguments,
  frames), confidence (from capture_quality's verdict for loss) and the next call; plus the
  capture's trust and blind spots, top talkers, a timeline and the passes it skipped and why.
  Tools called by another tool run in the caller's time window; the runner takes a per-call
  deadline so every run of a multi-tool call shares one budget.
- `diff_captures`: before versus after a change for TCP/IP services. Runs tcp_connections,
  dns_transactions, tls_handshakes, http_transactions and tcp_health on both captures, joins per
  destination, DNS name and resolver, SNI, HTTP endpoint and TCP server, and labels each key
  worse, vanished, appeared, better or same with a sentence and the delta; volumes are also per
  minute because the captures differ in length.
- `throughput_timeline`: bytes, bps and TCP goodput (bytes newly acknowledged, copies and
  retransmissions not counted) per interval, with the retransmitted bytes, zero windows,
  window-full events, duplicate ACKs, SYNs never answered, DNS queries, TLS ClientHellos and
  ICMP errors beside them; series per conversation, host or stream; a verdict per TCP stream
  (loss-limited, receiver-limited, application-idle, sender-limited, fine) and issues that say
  where goodput fell and why, and which counters burst.
- `call_legs`: the legs of one call that a B2BUA, SBC or CSCF chain gave different Call-IDs,
  stitched by icid, RFC 7989 Session-ID, X- Call-ID headers, Replaces and Target-Dialog (high
  confidence), a shared SDP media endpoint (medium) or the called number and time (low), with the
  link and its confidence per leg, the delay each element added, header changes, which element
  rewrote a status or Q.850 cause and the deepest failed leg explained with cause_lookup.
- `diameter_avps(detail="key")` digests per application: `gy` (Gy/Ro: per MSCC rating group,
  requested, granted and used units, reporting reason, validity and quota holding time,
  Final-Unit-Indication, MSCC Result-Code), `rx` (media components, flow status, bandwidth, first
  Codec-Data line, Specific-Action, Abort-Cause), `cx` (authorization and assignment types,
  identities, capability counts, authentication scheme and item count, deregistration reason), `sh`
  (Data-Reference names, Sh-User-Data size and element names) and `s13` (IMEI, Equipment-Status).
  Failed Result-Codes and Experimental-Result-Codes carry `explained` from cause_lookup. Rx
  Experimental-Result-Codes 4261 and 5061 to 5068 are named in every Diameter tool.

### Changed

- `diameter_avps` and every tool built on its AVP tree never return authentication material:
  RAND, XRES, AUTN, KASME, SRES, Kc, CK, IK, SIP-Authenticate and SIP-Authorization read
  `withheld (authentication material)` in both views, and Sh-User-Data is reduced to its size and
  element names. Enumerations, flags and text values are also read when a tshark dictionary spells
  the AVP with a `3GPP-` prefix.

- `tunnels_overview`: every GRE, ERSPAN, VXLAN, Geneve, IP-in-IP, IPsec (IKE, ESP, AH, NAT-T),
  WireGuard, OpenVPN, L2TP and GTP-U tunnel in a capture with its outer endpoints, key or VNI,
  packets and bytes each way, inner protocols, tunnel overhead, DF packets above the path MTU and
  inner SYN MSS against the overhead; IKE exchanges and error notifies, WireGuard and OpenVPN
  handshakes, ESP SAs per direction; issues such as unanswered WireGuard initiations, a missing
  return SA or an MSS that does not fit once tunnelled.

- `export_subset`: the first and only write tool, off unless the server is started with
  `--export-dir DIR`. It writes the packets matching a display filter (and start/end) to a new
  pcapng file in that directory for a vendor or another team: never overwrites, never follows a
  planted symlink, sanitised names, `--export-max-mb` (50) and `max_packets` caps, `headers_only`
  or `snaplen` to cut payloads with editcap, sha256 in the result and a `write` audit record. The
  export directory may not overlap an `--allow-dir` unless `--export-inside-allow-dir`; `-w` and
  `-F` stay refused on every other tshark run.

- `tls_certificates`: the certificate chains servers sent in TLS 1.2 and older handshakes, per
  server, SNI and leaf, with every certificate parsed from DER: subject, issuer, SANs, validity and
  days left, key and signature algorithm, self-signed, fingerprint; whether the chain is in order
  or misses the intermediate, whether the name matches the SNI, OCSP stapling, the TLS versions
  and alerts seen and how many clients refused the certificate. TLS 1.3 connections are counted
  as skipped because their certificates are encrypted. No private keys, no decryption.

- `quic_connections`: QUIC / HTTP/3 connections read from their clear headers (no keys needed):
  version, Retry, Version Negotiation with the versions the server offered, Handshake and 1-RTT
  packets both ways, 0-RTT, CONNECTION_CLOSE when in clear, migration to a new address or port,
  a spin-bit RTT, the outcome per connection, the TCP fallback after a failed attempt and a
  `udp_443_blocked_likely` summary flag.

### Fixed
- PyPI page: README links are absolute, so they work on pypi.org as well as GitHub; a test keeps them absolute and pointing at real files. More project links (documentation, changelog, releases).

- Errors no longer quote an over-long argument back in full: `gtp_ies(message=...)`, the shared
  IMSI/MSISDN check and every other message that names a bad value show its first 80 characters
  and its length (a 5,000-character value cost about 5 KB of error text before). Error messages
  and their text details (tshark stderr, the filter) are capped at 1,000 characters,
  `check_filter` cuts a filter the lint refused, and `find_fields(protocol=...)` refuses a name
  longer than 200 characters instead of echoing it in the result.

## 0.1.0 - 2026-11-04

First release. Everything below was built between 1 and 4 November 2026 in pull requests #1
to #87; the numbers in brackets are the pull requests. The first 33 tools came first, then eight
more (41 in all) and the hardening landed the same day (listed under Added, Changed and Security).

### Added

- `tcp_connections`: every TCP connection attempt with its outcome (connected, refused,
  filtered, ICMP prohibited or unreachable, reset or unfinished handshake), SYN retries, connect
  time, bytes, duration and who closed it; `view="destinations"` gives the success rate per
  server and port and names a client a firewall drops while others connect (#68).
- `icmp_errors`: every ICMP and ICMPv6 error grouped per sender, kind and quoted flow, with the
  MTU of fragmentation-needed errors, whether the quoted packet is in the capture, the sender's
  hop distance, echo loss and RTT, and issues that tell a routing loop from a traceroute (#71).
- `capture_metadata`: the pcapng writer, interfaces, snaplen, capture filter, packet comments and
  the Interface Statistics Block drop counters that tshark has no field for, read by a pure-Python
  block walker that never decodes a packet; `pcap_info` reports `metadata_available` and
  `interface_drops` (#76).
- `cause_lookup`: what a telecom cause or result code means, with the spec reference, typical
  causes, related codes and the tool calls that find it in a capture. Names come from tshark's
  own value strings (`tshark -G values`), so they match the other tools; a test fails when a
  tshark release names a code that has neither curated text nor an `unexplained` listing.
  Diameter codes are read as Result-Code or, with `application`, as that application's
  Experimental-Result-Code. No capture is read (#78).
- `http_transactions`: HTTP/1.x requests paired with responses and HTTP/2 / gRPC streams with
  status, sizes, response time and TTFB, per-endpoint status mix and percentiles, gRPC status
  names, reset streams, unanswered requests and the ports carrying HTTP that tshark left raw (#80).
- `call_kpis`: ASR, SER (RFC 6076, with and without 487), NER, post-dial delay, ringing time and
  ACD per peer, trunk, number prefix, user agent or interval, with failure codes, Q.850 causes and
  the worst calls by Call-ID and frame. Calls still open when the capture stopped are counted as
  `near_capture_end` and left out of the ratios; `method` states every definition (#82).
- `gtp_ies`: the GTPv2-C information elements behind each transaction (APN, PDN type, PAA,
  serving network, RAT, ULI, indication flags, AMBR, F-TEIDs, PCO option names, bearer QoS, cause
  with offending IE and source, RAN/NAS cause) and `likely_causes` for a reject, built from the
  request. PAP and CHAP payloads in the PCO are never returned. `detail="full"` gives the IE tree (#84).
- `roaming_attach_check`: why a roamer cannot attach or get a bearer. The subscriber's S6a, MAP,
  GTPv2-C, Gx and PFCP steps grouped into attempts, the ULA subscription held against the Create
  Session request (APN subscribed, PDN type, home routing or local breakout, RAT against
  Access-Restriction-Data, ODB, AMBR), the first failure with its reference and a one-sentence
  verdict. Authentication vectors are counted, never returned (#86).

### Changed

- Cancelling a request kills tshark within a quarter of a second instead of letting it run to
  its timeout; the audit log records `cancelled`. With a `progressToken`, `find_identifier`
  reports files done out of files planned and other tools one notification per finished tshark
  run, at most one per second (#83).
- `tools/list` is compact by default: 102 KB instead of 263 KB for 41 tools. Output schemas
  keep their top-level keys with JSON types and name the keys of each row list; the keys
  every result may carry are left out; input schemas lose the generated titles and write
  optional arguments as a type list; the twelve descriptions over 1,500 characters move their
  detail to a resource, and the server instructions are rewritten to about 3,100 characters (they
  had grown past the 4,096 some clients keep). Each tool's full description and schemas are
  the resource `schema://tools/<name>`; `--schema-profile full` (`TSHARK_MCP_SCHEMA_PROFILE`)
  publishes the old list. `tests/test_tool_list.py` keeps the compact list within budget (#87).
- Tool errors are returned with `isError: true`, so clients show and count them as failures;
  the structured `{"error": {...}}` stays in `structuredContent` and the text content. Every
  error carries a `fix` hint; `not_found` and `not_a_file` list nearby capture files in
  `candidates`, `invalid_filter` and `unknown_field` list close field names in `suggestions`,
  `timeout` and `output_too_large` name the arguments that narrow the call (#69).

### Security

- Security hardening of the tshark child: an empty read-only personal profile and a scrubbed
  environment, so no personal `init.lua`, Lua script, plugin or extcap loads
  (`--allow-user-profile` to opt back in); nice +10 and, on Linux, a 2 GB address-space limit
  (`--max-tshark-memory-mb`, out-of-memory runs report `out_of_memory: true`); at most two
  tshark runs at once (`--max-concurrent-runs`, `--busy-wait`, then a `busy` error); a capture
  replaced during the run fails with `capture_changed`; `-d` decode-as rules are validated (#73).

### The server

- Read-only MCP server over stdio. Every call runs `tshark -r <file>` on a capture inside an
  operator-allowed directory, through an argv list with `-n`, never a shell. Capture, write,
  export and extension flags are refused before a process starts.
- Hard limits, each enforced in code and none switchable off: file size, matching packets
  dissected in full, frames read per run, JSON returned per call, raw stdout kept, wall clock
  per run and per multi-pass call, files opened per directory search.
- Display filters are linted and compiled against an empty capture before touching the real
  file; field names must exist in `tshark -G fields`; structured arguments (IMSI, APN, TEID,
  Call-ID, ...) are linted to their shape before being embedded in a filter.
- Typed `outputSchema`, a title and the MCP annotations `readOnlyHint`, `idempotentHint` and
  `openWorldHint: false` on every tool; failures come back as `{"error": {...}}` (#1).
- One output contract: `total_matched`, `returned`, `offset`, `next_offset`, `truncated` with a
  `truncated_reason`, and a 30 KB cap that keeps whole rows and says how to get the rest (#25).
- Every row carries the frame numbers it was built from, and `packet_detail` opens any frame (#30).
- Text copied from packets is capped, stripped of control and bidi characters and named in
  `untrusted_text_fields` (#42).
- Redaction of subscriber identifiers with stable keyed tokens that work as arguments
  (`--redact ids` / `ids+ips`), with a bounded pre-scan so even a first `conversations` call
  hides UE addresses (#47, #50).
  An IMEI written as TAC-SNR-CD inside a `urn:gsma:imei:` instance id is found too (#60).
- JSON-lines audit log (`--log-file`).

### Tools (the first 33)

Orientation and capture trust: `pcap_info`, `conversations`, `filter_packets`, `packet_detail`
(#30), `expert_info` (#36), `find_fields` and `check_filter` (#38), `capture_quality` (#29, #44,
#49), `find_identifier` across a directory of captures (#1).

Diameter: `diameter_transactions`, `diameter_sessions` (#1), `diameter_avps` with a key view
(procedure flags with bit names, Subscription-Data digest) and a full AVP tree (#15).

GTP and PFCP: `gtp_sessions` (GTPv2-C paired by sequence and peer, across NATs and proxy
chains, #4, #22, #46, #51), `gtpv1_sessions` (#20), `gtp_user_plane`, `gtp_tunnel_health`
(inner TCP loss, reordering, ICMP and MTU per tunnel, #18, #35), `pfcp_sessions` (#37).

SIP, media and IMS: `sip_dialogs`, `sip_call_detail` (#33), `rtp_streams` with RFC 3550
jitter, RTCP and an E-model MOS estimate (#24), `media_path_check` for one-way audio, NAT and
488 cases (#34), `dtmf_events` (#39), `ims_registration` (#52; network-initiated de-registration
from reg-event NOTIFYs, #61), `sms_over_ims` (#54).

Transport and infrastructure: `tcp_health` (#32, #53), `response_times` (#31, #43),
`tls_handshakes` (#28, #41), `dns_transactions` (#23), `sctp_associations`,
`sigtran_messages` (M3UA/SCCP/TCAP/MAP).

Cross-protocol: `trace_subscriber` (one timeline per subscriber across Diameter, GTPv2-C,
GTPv1-C, PFCP, MAP and SIP, one shared time budget, #13, #16, #20, #37), `compare_captures`
(where a failing capture first departs from a working one, #17), `message_rates` (bursts,
storms and subscriber loops with the nodes involved, #19, #21, #48).

### Fixed during testing against real captures

- Captures that end mid-packet no longer fail every tool; the result carries a warning (#2).
- `-c` counted frames read, not frames matched, so per-packet tools saw only the first 500
  frames (#3).
- MAP returnError reported the CHOICE index instead of the error code, and results without an
  opcode were not named after their invoke (#5, #6).
- A SIP REGISTER answered 401 then 200 was counted as failed; retransmissions were counted as
  new requests; several SIP messages in one TCP segment are now all kept (#7, #14).
- Diameter IMSI queries returned other subscribers' sessions from bundled SCTP packets (#8).
- `find_identifier` dropped partly read files without hits and could overrun its time budget
  (#9, #10); the `apn` filter missed APNs carrying the operator identifier (#11).
- Requests unanswered only because the capture stopped are marked `near_capture_end` and
  counted apart, for Diameter, GTPv2-C, GTPv1-C, PFCP and DNS (#51, #55).

### Fixed by the bug hunt over public captures (4 November 2026)

Every tool was driven over 16 synthetic edge cases and 245 captures from the Wireshark
repository through the MCP stdio client, with default and hostile arguments, output
schemas validated and counts cross-checked against raw tshark.

- `message_rates` crashed (`StatisticsError`) with `storm_min` below 2 (#65).
- `filter_packets` with an empty `display_filter` escaped the error contract as a bare MCP
  error; it is now `invalid_argument` (#66).
- `capture_quality` called every same-sized datagram of a flow a duplicate copy when the
  sender reuses one IP ID (97% "copies" on the README's own one-way-audio example); verified
  checksums and SCTP TSNs now break a false match (#67).
- `tcp_health`, `capture_quality` and `gtp_tunnel_health` reported out-of-order segments as
  retransmissions "lost before the capture point" when a multi-queue sender emitted them with
  IP IDs in emission order (45% false retransmissions on an ordinary HTTPS download); a gap
  filled within one round trip is reordering, and a stack reusing one IP ID falls back to the
  time window (#70, #75).
- `pcap_info` reported 1 packet for a capture cut short in the middle of a packet; the
  readable part is counted (#72).
- `media_path_check` called a call with `a=recvonly`/`a=sendonly` one-way audio; directions
  the SDP rules out are "not expected" (#74).
- `rtp_streams` merged RTP over Bluetooth AVDTP into one bogus stream; RTP over IP only (#77).
- A tshark crash (SIGSEGV on fuzzed captures) was reported as `tshark exited with -11`; the
  message now names the signal, says the bug is in tshark's dissectors and what to try (#79).
- A path the filesystem cannot take (5000-character name) came back as `internal_error`;
  it is `invalid_path` (#81).

### Documentation and project

- README with quickstart, a worked one-way-audio example on a committed synthetic capture,
  per-tool table, safety model and limitations (#26, #57), then restructured for a 60-second
  read with the detail moved to `docs/TOOLS.md` and `docs/SAFETY.md` (#64); `AGENTS.md` and
  `CLAUDE.md` for agents (#63); `llms.txt`; `docs/EXAMPLE.md` walking through a failed attach.
- `examples/`: three synthetic sample captures (SIP one-way audio, Diameter error answer,
  GTPv2 Create Session rejected) regenerated and checked by `tests/test_examples.py` (#56).
- CI on Python 3.10 to 3.13 with the tshark Ubuntu 24.04 ships (4.2), plus a run on the
  oldest supported `mcp` and `pydantic` (#27). All test captures are synthetic.
- `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, issue and pull request templates (#58).
- The distribution is named `tshark-mcp-server` (the PyPI name `tshark-mcp` belongs to an
  unrelated project); the import name `tshark_mcp` and the `tshark-mcp` command are unchanged.
  A publish workflow uploads to PyPI through trusted publishing when a GitHub release is
  published (#59).
