# Changelog

All notable changes to tshark-mcp. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project uses [semantic versioning](https://semver.org/).

## 0.1.0 - 2026-11-04

First release. Everything below was built between 1 and 4 November 2026 in pull requests #1
to #62; the numbers in brackets are the pull requests.

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

### Tools (33)

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
