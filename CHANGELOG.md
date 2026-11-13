# Changelog

All notable changes to tshark-mcp. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project uses [semantic versioning](https://semver.org/).

## Unreleased

Changes merged since the last release are fragments in [changelog.d/](https://github.com/Kx96xx/tshark-mcp/tree/main/changelog.d); `python scripts/changelog.py --release X.Y.Z` moves them here.

## 0.4.0 - 2026-11-12

### Added

- PcapBench `--driver claude-code`: each question is one `claude -p` session with only the arm's
  MCP server, so a benchmark run can use a Claude subscription instead of API credits; usage and
  the session's reported cost are recorded, and `--max-usd` stops on that cost. With a model, both
  arms are now judged alike (answer, budgets, at least one tool call) instead of holding the
  tshark-mcp arm to the scripted path; `redaction_join` gained an answer check.
- PcapBench answers: the system prompt asks for a value-only answer inside `<response>` tags (the
  mcp-builder evaluation format), and an answer check passes on that value or on the whole reply.
  First model results (Claude Code, Sonnet 5.5): tshark-mcp 30/35, plain tshark 27/35
  (docs/BENCHMARK.md, evals/results/2026-11-12-claude-code.json).
- `correlate_captures` (toolset `network`): the same traffic captured at two points on its path
  (client and server side, either side of a firewall, NAT or tunnel), matched packet by packet on
  an identity that survives NAT (IP protocol, ID and length plus TCP raw sequence and ack, or UDP
  length). Returns packets lost between the points per flow, NAT address and port rewrites, the
  TTL drop (hops), DSCP changes, the clock offset between the captures and the delay variation
  around it, with `issues` and a `verdict`.
- `incident_summary(audience="support")` adds `explanation`: the same findings in plain words for
  a support agent or a ticket. Each point says what happened, what it means for the user and which
  team usually owns it, with its frames; a headline, caveats (an untrusted capture, protocols no
  check reads, findings beyond the first five) and `ticket_lines` ready to paste. No new judgement:
  the findings are identical to the default `audience="engineer"`.
- `procedure_check` (toolset `mobile`): does a capture follow the standard flow, and which step
  goes wrong first? Reference flows as data in `tshark_mcp/procedure.py`: `eps_attach` (S6a AIR
  optional, ULR, GTPv2 Create Session, Modify Bearer) and `location_update` (MAP) from the
  subscriber's trace_subscriber timeline; `sip_register` (REGISTER, optional 401/407 challenge,
  REGISTER with credentials, 200) and `sip_call` (INVITE, optional 100 and 180/183, 200, ACK)
  from sip_dialogs, for one Call-ID or every dialog of the method (up to 20). Each step is ok,
  failed, unanswered, missing, out_of_order or not_seen, with frames and the spec clause;
  `first_deviation` and a one-sentence `verdict`.

### Changed

- `diameter_transactions`, `sip_dialogs`, `ims_registration` and `conversations` say in their
  description when to use them and which sibling answers the neighbouring question
  (`diameter_sessions`, `sip_call_detail`, `sms_over_ims`, `tcp_connections`, ...), so an agent
  picks the right tool first.

## 0.3.0 - 2026-11-12

### Added

- `call_ladder`: a Mermaid `sequenceDiagram` (or text) of one call or one subscriber for tickets,
  every arrow labelled with its frame number, failing steps marked, participant roles guessed
  with evidence; byte-identical on rerun. An MCP Apps view (`ui://tshark-mcp/ladder.html`) draws
  it as an SVG ladder in hosts that support Apps.
- `open_capture(path, filter=None, start=, end=)`: a handle (`cap:...`) that every capture tool
  takes in place of `path` (also `path_a`/`path_b`). It pins the file, and optionally a display
  filter and a time window, for every later call on it. A changed file gives `stale_handle`; a
  restarted server gives `unknown_handle`.
- A memory cache of finished tshark and capinfos runs, keyed by file identity and the full argv
  (`--cache-mb`, default 256, 0 off, env `TSHARK_MCP_CACHE_MB`). A repeated call, or two tools that
  issue the same run, read the file once; such a result carries `cache: {hits, misses}`. On a
  37 MB capture a second `incident_summary` took 3.9 s instead of 11.6 s (9 of 9 runs cached).
- `esp_null` argument on `sip_dialogs`, `sip_call_detail`, `call_legs`, `ims_registration`,
  `sms_over_ims`, `volte_call_chain` and `trace_subscriber`: reads SIP between UE and P-CSCF
  inside IPsec ESP with NULL encryption (RFC 2410) by switching on tshark's NULL-ESP heuristic.
  No keys are accepted.
- `ipsec` block on those tools when the capture carries ESP: packets, SPIs, how many were read
  as NULL encryption and how many stay unreadable, with a hint such as "SIP may be inside 1,240
  ESP packets on SPI 0x...". `pcap_info` names ESP the same way.
- `evals/tshark_mcp_eval.xml`: 19 verified questions in the evaluation format of Anthropic's
  mcp-builder skill (exact-string answers, several multi-hop, one True/False trap), and
  `evals/xml_bridge.py`: `python -m evals --xml evals/tshark_mcp_eval.xml` runs them on the
  harness (scripted driver in CI, `--driver llm` for a model score). docs/EVALS.md has the
  reference-harness command and its known limits.
- `fiveg_session`: 5G SA registration and PDU sessions per UE across NGAP/NAS-5GS, PFCP and GTP-U:
  5GMM and 5GSM causes explained, QoS flows with 5QI, the PFCP establishment joined by the UPF N3
  TEID with `n3_consistent`, GTP-U counts per tunnel, a VoNR check (IMS session, 5QI 5, 5QI 1),
  `first_failure` and a one-sentence verdict.
- `ims_registration`: reg-event SUBSCRIBEs per user in `reg_subscriptions` (UE or network
  subscriber, status, requested and granted expiry; a refused or unanswered one is named in
  `reasons`). Reg-event NOTIFY rows now carry the final response (`status`,
  `no_final_response`), `subscription_state`, `retry_after` and `contact_matched`; the UE's own
  contact (by its REGISTER Contact URI) decides when a NOTIFY lists several, so a contact ended
  on its own while another device keeps the registration active is a de-registration, and
  another device's contact ending is not. A contact event `shortened` brings the registration
  expiry forward (verdict `expired` when the UE does not re-register in time). A decisive
  NOTIFY the UE refused (481) or never answered is named in `reasons`.
- `incident_summary` covers more of the capture (public-validation D3): new passes for
  `quic_connections`, `tunnels_overview`, `ims_registration`, `gtpv1_sessions`, `pfcp_sessions`,
  `sctp_associations`, `sigtran_messages` and error-level `expert_info`, so SCTP INIT/ABORT storms,
  unanswered heartbeats, MAP errors, TCAP rejects and unanswered Begins, GTPv1-C and PFCP rejects,
  PFCP peer restarts, failed IKE/WireGuard/OpenVPN handshakes, one-way tunnels, failed QUIC
  connections, failed IMS registrations and malformed packets are findings now. A new
  `not_analysed` list names the protocols in the file that no check reads (DHCP, MQTT, CoAP, ...)
  with the call that shows them, and the summary says "no checks exist for: ...".
- `incident_summary` is the documented front door: server instructions, prompts, AGENTS.md
  ("Start here") and the README point to it first.
- `rtp_streams`: a stream without a reverse stream gets `expected_one_way` (and
  `summary.expected_one_way`) when the call's SDP asks for one-way media (sendonly, recvonly,
  inactive).
- `iot_sessions`: MQTT 3.1.1/5.0 connections (CONNACK named, keepalive violations, reconnect
  loops, PUBACK latency, how the connection ended), CoAP retransmissions and exhausted
  confirmable requests, LwM2M registrations with lifetime and expiry; traffic inside GTP-U names
  its TEID. Payloads are never read; client ids and endpoint names are redacted.
- PcapBench (`python -m evals.bench`, docs/BENCHMARK.md): the 35 eval questions answered through
  two arms, tshark-mcp and a `run_tshark(path, args)` baseline under the same sandbox
  (`evals/tshark_only.py`). Each run records success, calls, model tokens, cost and time. A model
  run must state `--max-runs` up front and can stop at `--max-usd`. CI runs the scripted driver.
- `python -m evals.public`: an opt-in re-run of the public-capture validation (one scenario per
  defect D2 to D23 on the same public sample captures, downloaded by URL and checked against a
  SHA-256, never committed), and `docs/VALIDATION.md` with what was tested, what was wrong, what
  changed and the latest results table.
- `sbi_transactions`: 5G core SBI (HTTP/2 between network functions) per request: service,
  operation, consumer and producer NF, status, latency, ProblemDetails cause explained, resets,
  NRF discovery parameters and profile count, per-operation 4xx/5xx share and latency
  percentiles. SUPI, GPSI and PEI are redacted with the IMSI, MSISDN and IMEI tokens; the SUCI
  scheme output and authentication material are never returned; TLS without keys is counted.
- `security_triage`: defensive triage of a capture: port scans, host sweeps and SYN floods,
  beaconing with a RITA-style score and the raw interval and size statistics, DNS tunnel hints,
  TLS clients grouped by JA4 (JA3 fallback) and servers by JA3S, ARP conflicts, and cleartext
  credentials (protocol, peers and counts only, never the values). No lookups outside the capture.

### Changed

- The tool tables of the README and docs/TOOLS.md, the tool list of llms.txt and the tool counts
  are generated from the server's tool registry (`scripts/gen_docs.py`, words in
  `docs/tools/<name>.md`), so their argument lists always match the tools. docs/TOOLS.md and
  llms.txt list the tools in the README's order.
- `incident_summary`: a `next_call` (in `findings` or `not_analysed`) to a tool that the active
  `--toolsets` do not list carries `toolset`, the name that lists it (for example `mobile` for
  `sctp_associations`). The tool still answers a call by name.
- Every argument of every tool has a one-line schema `description`, in the compact and the full
  tool list (mcp-builder audit G1). The compact tool list grows from about 2,890 to 3,210 bytes
  per tool on average.
- Tool results carry their text content as compact JSON (no indentation): about 30% fewer bytes
  for the same `structuredContent` (G2).
- Paged results return `has_more` next to `next_offset`: true when more rows exist, false on the
  last page (G4).
- `columns` lists its valid row keys as `items.enum` in the full schema (`schema://tools/<name>`,
  `--schema-profile full`); the compact list leaves the enum out (G7).
- `output="summary"` is capped at 8 KB instead of 4 KB, so it keeps its three rows on wide rows
  such as `ims_registration` and `call_legs`, where it used to return one (G11).
- The Claude Code plugin starts the server from the PyPI release (`uvx --from
  "tshark-mcp-server>=0.3.0" tshark-mcp`) instead of building the main branch from git: faster
  first start, no git needed, and the server a user runs is a published version.
- Tools can live in their own module under `src/tshark_mcp/tools/`, found and registered when the
  server starts (`diameter_peers` is the first). No change to any tool's name, arguments or
  output. `python -m tshark_mcp.server` now runs the installed package's module, so it serves the
  same tools as the `tshark-mcp` command.
- `tools/list` shows a small default toolset: 34 of the 56 tools (33 of 55 before `open_capture`) (`incident_summary`, the
  capture overview and generic tools, the most used TCP/IP and telecom tools). The compact list
  drops from about 177 KB to 104 KB (about 49k to 29k tokens). `--toolsets mobile,voice,network`
  (or `all`, env `TSHARK_MCP_TOOLSETS`) lists the rest. A tool outside the active toolsets still
  answers a call by name, and a prompt that names one is not listed. The Claude Desktop
  extension gains a "Toolsets" setting. To keep the old list: `--toolsets all`.
- `throughput_timeline`: without `interval`, a capture too long for 10,000 one-second intervals gets
  the smallest round interval that fits (2 s up to 1 day) and `interval_auto: true`, instead of an
  error; an explicit `interval` that gives too many intervals is still refused (public-validation D20).
- `cause_lookup`: new protocols `dns` (RCODEs), `tls` (alert descriptions), `icmp`/`icmpv6`
  (`code="type:code"`) and `http` (status codes), and `nas`, which looks a code up in all four NAS
  tables and lists the other readings in `other_tables` (public-validation D21).
- `find_identifier`: `max_files` defaults to the server's --max-files (it was 20), and a directory
  whose subdirectories hold captures names them in `subdirectories_with_captures` with a note,
  since subdirectories are not searched (public-validation D23).

### Fixed

- `capture_quality` and every tool that drops capture copies: distinct UDP packets of one flow
  (QUIC, RTP, DNS) that share a size and an offloaded checksum are no longer taken for copies; the
  copy key now holds the QUIC packet number, RTP sequence number and SSRC or DNS ID, and the 5 ms
  window is measured from the first sighting instead of chaining from copy to copy
  (public-validation D5).
- `capture_quality`: byte-identical TCP RSTs and pure ACKs with IP ID 0 and no link-layer
  difference (interface, VLAN, MAC pair, SLL direction) are counted in
  `duplicates.repeated_identical`, not as mirror copies (public-validation D6).
- Diameter tools (`diameter_transactions`, `diameter_sessions`, `trace_subscriber`,
  `roaming_attach_check`, ...): the result is the command-level Result-Code or Experimental-Result-Code;
  a Result-Code nested in a Multiple-Services-Credit-Control or Proxy-Info no longer replaces it, and
  an Experimental-Result beside a Result-Code no longer overrides it (public-validation D17).
- `diameter_transactions`: `mscc_result_codes` lists the Result-Code of each MSCC of a credit-control
  answer and `mscc_results` names the failed ones (for example DIAMETER_CREDIT_LIMIT_REACHED).
- `roaming_attach_check` calls an application-4 CCR-I "Gy/Ro CCR-I/CCA-I" (and looks causes up in the
  Gy table), as `diameter_transactions` does; "Gx" is kept for application 16777238.
- `http_transactions`: a response tshark cannot reassemble in one pass (headers split over many
  segments, segments out of order) is now read from its first segment with TCP reassembly off and
  paired, with `response_decoded_from: "first_segment"`, instead of leaving the request
  "unanswered" (public-validation D9a).
- `http_transactions`: a response without `http.request_in` is paired with the oldest open request on
  its connection (`paired_by: "stream_order"`) (public-validation D9b).
- `http_transactions`: an HTTP/2 response whose HPACK block includes a table-size update (header
  count larger than the headers listed) is no longer missed (public-validation D9c, HTTP/2 part).
- `http_transactions` gives `ttfb_ms` for HTTP/1.x too, and endpoints get `ttfb_ms` p50/p99. The
  slow-endpoint issue uses the time to first byte; a slow body transfer behind a fast first byte is
  reported as "p99 transfer ..., but the first byte came within N ms", which `incident_summary` no
  longer reports as a slow server (public-validation D11).
- `tunnels_overview`: an IKEv2 negotiation where the responder answered INVALID_KE_PAYLOAD (asking for
  another DH group) and the initiator retried is `established` when IKE_AUTH was answered without
  an error or ESP flows both ways; the retry is listed in `handshake.retried`, not as an issue
  (public-validation D10).
- `tunnels_overview`: Teredo (IPv6 over UDP 3544) is a tunnel kind (`kind="teredo"`), and a capture
  without any tunnel this tool reads gets a `summary.note` saying that an undecoded tunnel shows up
  as plain UDP or TCP (public-validation D22).
- `incident_summary` no longer reports high `one_way_audio` when the SDP asks for one-way media
  (public-validation D8), and no longer counts a QUIC handshake as a failed TLS handshake
  (`tls_failed`, public-validation D9c): QUIC is judged by the new QUIC pass.
- `tcp_connections`: a connection captured in one direction only (a one-way tap or asymmetric
  routing) gets the new outcome `one_sided` with `missing_direction`, instead of `filtered` or
  `handshake_incomplete`; it is not counted as a failed attempt (public-validation D2).
- `tcp_health` says "only the client's direction is in the capture" instead of "SYN and no SYN-ACK"
  when the SYN sender went on sending ACKs and data.
- `tls_handshakes`: a TCP connection seen in one direction only gets the outcome `one_sided` (not a
  failure); a SYN-ACK without the SYN now names the client; the summary counts
  `client_hello_missing`.
- `incident_summary` no longer reports high-severity `connect_failures` and `tls_failed` for
  one-sided captures; it reports one low `tcp_one_sided` finding that points to `capture_quality`.
- `quic_connections`: when the client and the server share an address (a loopback capture), each
  packet's side is taken from its address and port; before, every server packet counted as the
  client's and a working handshake read as "no answer: UDP 443 blocked" (public-validation D4).
  The "no answer" issue names the server's real UDP port.
- `quic_connections`: Google QUIC (gQUIC) packets are counted in `summary.gquic_packets` with an
  issue saying they are not analysed, instead of an empty result (public-validation D18).
- `rtp_streams` and `media_path_check` with a `call_id`: a later call that reuses the offerer's
  address and port no longer has its RTP tagged with this Call-ID. Streams are linked against
  every SDP in the capture, and a call whose BYE or CANCEL came before a stream started never owns
  it. This removes false "NAT or media relay rewrote it" and "payload type that neither SDP
  lists" issues (public-validation D7).
- `rtp_streams`, `dtmf_events` and `media_path_check` with `heuristic=true` also find RTP inside
  STUN/TURN (WebRTC through a relay), when the tshark in use has the STUN dissectors
  (public-validation D19).
- `sigtran_messages`: CAMEL (CAP, TS 29.078) components are read from tshark's `camel` layer and named
  (initialDP, requestReportBCSMEvent, applyCharging, ...), with CAP error names and
  `application: "camel"`; before, `by_operation` was empty on CAMEL traffic (public-validation D13).
- `sctp_associations`: `inits_aborted`, `init_collision` and `issues` ("N INITs answered with ABORT",
  "INIT collision", 3 or more unacknowledged heartbeats); an association that came up after a run
  of refused INITs no longer reads as a clean handshake (public-validation D14).
- `dns_transactions`: server latency percentiles run from the last copy of a query that was sent
  again (`rtt_after_resend_ms` on the row), a "slow" percentile needs 10 answers from the server,
  and a query answered quickly after its resend is reported as a lost query, not a slow resolver;
  `incident_summary` needs 10 answers before `dns_slow` (public-validation D15).
- `tcp_connections` destinations get `failed_then_connected_elsewhere` (happy eyeballs: the same
  dual-stack client connected to another address on the same port within 1 s), and
  `incident_summary` reports such failures as low severity; `tcp_health` no longer reports SYNs
  refused with a reset as "SYN and no SYN-ACK", so a port scan is not counted twice
  (public-validation D16).

### Security

- Redaction (`redact="ids"` or `--redact ids`): a number typed into a USSD string or SMS text
  (`*140*<number>#`) is replaced like any other number, the pre-scan learns it, and the packed
  GSM 7-bit bytes field of the same text is dropped. Before, `packet_detail` and `filter_packets`
  returned both in clear next to a redacted IMSI and MSISDN (public-validation D12).

## 0.2.0 - 2026-11-05

### Added

- Claude Code plugin in `plugin/` with a marketplace entry in `.claude-plugin/marketplace.json`:
  `/plugin install tshark-mcp --marketplace Kx96xx/tshark-mcp` adds the server (started with `uvx`
  from the main branch, so tools and skills match), asks for the capture directory and redaction
  (off, ids, ids+ips), and adds seven skills: `pcap-investigation` and one per MCP prompt, each
  pointing at that prompt. `tests/test_plugin.py` checks the manifests against the package, that
  every prompt has a skill and every tool a skill names exists, and starts the server with the
  plugin's own arguments over stdio; a CI `plugin` job also runs `claude plugin validate` on the
  plugin and the marketplace.
- README first screen: a one-line `claude mcp add` with `uvx --from tshark-mcp-server`, PyPI version
  and downloads badges, and a demo GIF recorded with vhs from a live MCP client session against the
  PyPI package (docs/media/demo.tape, docs/media/demo_client.py). A "Found a bug or a wrong answer?"
  section, issue forms for wrong answers and for bugs, questions routed to GitHub Discussions, and a
  1280x640 social preview image (docs/media/social-preview.png).
- `Dockerfile`: tshark from Debian pinned to the 4.4 series (the build fails if the series
  changes), the server installed from the checkout, a non-root user (uid 10001), `/captures` as the
  read-only capture mount, a healthcheck (package imports, tshark runs) and no port. A CI `docker`
  job builds it (never pushes it), checks the user, the tshark version and the refusal without
  `--allow-dir`, and runs every task-success scenario over stdio inside `docker run -i --read-only
  --cap-drop ALL --network none`.
- MCP Registry metadata: `server.json` (`io.github.Kx96xx/tshark-mcp`, PyPI package, stdio,
  `TSHARK_MCP_ALLOW_DIRS` required), the `mcp-name` marker in README, `glama.json`, and a
  `registry` job in publish.yml that publishes server.json with `mcp-publisher` (pinned, digest
  checked, GitHub OIDC) after the PyPI upload. A release fails early unless the tag, pyproject and
  server.json versions agree. `uvx tshark-mcp-server` now starts the server (second entry point
  named after the distribution). tests/test_server_json.py validates server.json against the
  registry schema (vendored) and keeps it in step with pyproject.
- MCPB desktop bundle for Claude Desktop: `mcpb/manifest.json` (manifest 0.4, `uv` server type, so
  the host installs Python and the dependencies and nothing compiled ships), settings for the
  capture directories (several, required; each becomes one `--allow-dir`), redaction and the tshark
  path, and `mcpb/build.py` to write the bundle directory and keep the manifest's version and
  tools list in step with the package (`--check`, `--update`). A CI `mcpb` job validates and packs
  the bundle (never published) and starts the built bundle over stdio. tshark is also looked for
  at `/Applications/Wireshark.app/Contents/MacOS/tshark`, since desktop hosts start the server
  without the shell's PATH.
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
- `nas_procedures`: EMM, ESM and S1AP procedures per UE from S1-MME captures (attach, TAU,
  service request, detach, PDN connectivity, dedicated bearer activation, bearer modification and
  deactivation, S1 and X2 handover, UE context release). S1 contexts are joined into UEs by IMSI
  or assigned M-TMSI; each procedure has an outcome, EMM/ESM and S1AP causes named through
  cause_lookup, timing and its steps; ciphered NAS is counted, not guessed (`null_cipher=true` reads
  EEA0 traffic), and a Paging nobody answered is listed. `nas-eps.null_decipher` joins the allowed
  preferences.
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
- `volte_call_chain`: one VoLTE call followed through SIP, Rx (by icid or UE address), Gx (the
  UE's session), GTPv2-C Create Bearer on every leg (by the TEIDs of the UE's PDN connection),
  PFCP and the first RTP per direction, then the teardown; each link has a status (ok, failed,
  missing, not_captured, late), how it was found and its delay, and each call a first broken link
  and a verdict.
- `sigtran_health`: SS7-over-IP link health per SCTP association: episodes from INIT to ABORT
  (cause named) or SHUTDOWN and the gap before the next INIT, heartbeat failures, the M3UA ASP state
  machine with acknowledgement times, ERR named, DUNA/DAVA outages per point code (ITU 3-8-3 and
  ANSI 8-8-8), SCCP returns per unreachable GT and SSN and TCAP P-Abort causes, with a verdict
  (healthy, degraded, flapping, down) and issues in plain words.
- `sms_delivery`: SMS over MAP and SGs as one attempt per message: sendRoutingInfoForSM,
  mt/mo-forwardSM and reportSM-DeliveryStatus joined by MSISDN and the IMSI routing returned, SGsAP
  paging, service request, PAGING-REJECT and the CP/RP exchange per IMSI, with MAP, SGs, CP and RP
  causes named and a verdict (delivered, rejected, absent subscriber, paging failed, no response).
  Content-free: no text, no TP-OA or TP-DA.
- `diameter_peers`: the per-peer view of a DRA: CER/CEA capabilities, watchdog cadence and missed
  DWAs, DPR with Disconnect-Cause, restarts from Origin-State-Id, per-application success ratio,
  result classes, routing errors with the Destination-Realm they named, Failed-AVP names, Error-Message
  text and RTT percentiles, with a verdict (healthy, degraded, restarted, down) per peer.

### Changed

- `diameter_avps` and every tool built on its AVP tree never return authentication material:
  RAND, XRES, AUTN, KASME, SRES, Kc, CK, IK, SIP-Authenticate and SIP-Authorization read
  `withheld (authentication material)` in both views, and Sh-User-Data is reduced to its size and
  element names. Enumerations, flags and text values are also read when a tshark dictionary spells
  the AVP with a `3GPP-` prefix.

### Fixed
- `filter_packets` no longer fails with an unstructured "Error executing tool" when `fields` leaves out `frame.number`: the output schema now allows the integer frame number it adds to each row (found by the public-capture validation, D1).
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
