# tshark-mcp

[![CI](https://github.com/Kx96xx/tshark-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Kx96xx/tshark-mcp/actions/workflows/ci.yml)
![Python 3.10 to 3.13](https://img.shields.io/badge/python-3.10%20to%203.13-blue)
![Licence MIT](https://img.shields.io/badge/licence-MIT-green)

**A read-only MCP server that lets an AI assistant analyse packet captures with tshark.**
Point it at a directory of pcap files, connect Claude or any other MCP client, and ask
questions about the calls, sessions and subscribers in them.

## Why

- **Telecom captures need correlation, not grep.** A failed attach, a dropped bearer or
  one-way audio spans Diameter, GTP, SIP, RTP and MAP. The tools pair requests with answers,
  name the result codes (Diameter 5420, GTP cause 78, Q.850 cause 16) and say what never got a
  reply.
- **An agent with a shell and tshark is a liability.** This server can only run
  `tshark -r <file>` on files inside directories you allow, under hard caps on size,
  packets, output and time. It cannot capture, write, export, resolve names or load code.
- **It tells you when the capture itself cannot be trusted:** duplicate packets from a SPAN
  session, bytes the capture missed, cut-short frames, checksum offload, clocks that run
  backwards.

## Install and connect

1. Install tshark (it comes with Wireshark): `brew install --cask wireshark`,
   `apt-get install tshark` or `dnf install wireshark-cli`.
2. Install the server (Python 3.10 or newer):

   ```sh
   uv tool install git+https://github.com/Kx96xx/tshark-mcp
   # or: pipx install git+https://github.com/Kx96xx/tshark-mcp
   ```

   Requirements: Python 3.10+, tshark 4.0 or newer (tested with 4.2 and 4.6); the `mcp` (2.1+) and
   `pydantic` (2.12+) packages are installed automatically. The package is published as
   `tshark-mcp-server` (the PyPI name `tshark-mcp` belongs to an unrelated project); the command
   stays `tshark-mcp`. From a clone: `uv tool install .` or `pipx install .`.

3. Connect a client, naming the directory that holds your captures.

   Claude Code:

   ```sh
   claude mcp add tshark-mcp -- tshark-mcp --allow-dir /path/to/pcaps
   ```

   Claude Desktop (`claude_desktop_config.json`), Cursor, or any client that starts stdio servers:

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

   To run it by hand: `tshark-mcp --allow-dir /path/to/pcaps [--allow-dir /more] [--log-file ~/tshark-mcp.jsonl]`.
   `TSHARK_MCP_ALLOW_DIRS` (colon-separated) works instead of the flag. Three small synthetic
   captures to start with are in [examples/](examples/).

## What you can ask it

- "Which capture in this directory mentions IMSI 001010123456789, and when?"
- "Why did this subscriber's attach fail?" (Diameter result codes and the AVPs behind them)
- "Was the GTP session created? What cause came back, and which PAA?"
- "Why is there one-way audio on this call?"
- "What was the call quality: loss, jitter, MOS?"
- "Why can't this UE register on IMS?" and "Where did the SMS go?"
- "Is this a purge storm? How often is the MME looping?"
- "Where does the failing capture first differ from the working one?"
- "Which DNS resolver is failing, and for which names?"
- "Is the upload slow because of the network, the server or the receiver?"
- "Can I trust the loss numbers in this file at all?"

One real answer, trimmed. The capture is
[`examples/sip_one_way_audio.pcap`](examples/sip_one_way_audio.pcap): a SIP call where the
called side never sends media. The agent finds the Call-ID with `sip_dialogs`, then calls:

```
media_path_check(path="/captures/sip_one_way_audio.pcap", call_id="one-way-audio-1@ue.example")
```

```json
{
  "offer":  {"message": "INVITE", "media_endpoint": "198.51.100.9:40010", "codecs": ["PCMA/8000", "telephone-event/8000"]},
  "answer": {"message": "200 INVITE", "media_endpoint": "192.0.2.70:30010", "codecs": ["PCMA/8000", "telephone-event/8000"]},
  "directions": [
    {"direction": "offerer to answerer", "expected": "198.51.100.9:40010 > 192.0.2.70:30010",
     "streams": [{"ssrc": "0x6a6a6a6a", "packets": 250, "codec": "PCMA/8000", "first_frame": 6}], "status": "as negotiated"},
    {"direction": "answerer to offerer", "expected": "192.0.2.70:30010 > 198.51.100.9:40010", "streams": [], "status": "missing"}
  ],
  "issues": [{"kind": "one_way_media", "detail": "no RTP seen answerer to offerer (192.0.2.70:30010 > 198.51.100.9:40010): one-way audio as captured"}],
  "verdict": "no RTP seen answerer to offerer (192.0.2.70:30010 > 198.51.100.9:40010): one-way audio as captured"
}
```

The caller's RTP arrived exactly where the SDP answer asked for it and nothing came back,
so the fault is behind the media gateway, not the caller's NAT or codec. Every row carries
frame numbers (`first_frame: 6`), so `packet_detail` can show the packet behind any claim.
More worked examples, one per tool, are in [docs/TOOLS.md](docs/TOOLS.md#examples); a full
investigation of a failed attach is in [docs/EXAMPLE.md](docs/EXAMPLE.md).

## Safety model

- **Read-only by construction.** The only program started is tshark, from an argv list with
  `-n` and `-r`, never a shell. Capture, write, export and extension flags are refused before
  a process exists. tshark gets an empty profile, so no personal Lua script, plugin or extcap
  loads, and at most two tshark processes run at once.
- **Allowlist and caps.** Every path must resolve inside an `--allow-dir`. File size (500 MB),
  packets dissected per call (500), frames read per run (200 000), JSON per call (30 KB) and
  run time (60 s) are capped; the numbers are configurable, none can be switched off.
- **Packet text is data, not instructions.** Strings copied from packets are cleaned, capped
  and named in `untrusted_text_fields`. Optional redaction (`--redact ids`) replaces IMSIs,
  MSISDNs, IMEIs, SIP users and UE addresses with stable tokens before anything leaves the
  server.

Transport is stdio only; `--transport streamable-http` is for local experiments and has no
authentication. Details, the full caps table and the redaction rules: [docs/SAFETY.md](docs/SAFETY.md).
How to report a vulnerability: [SECURITY.md](SECURITY.md).

## Tools

Thirty-six tools. Every one returns JSON with a typed `outputSchema`, pages with `limit`
and `offset`, and returns failures as `{"error": {...}}` with `isError: true` and a `fix` hint. Full arguments, fields and
examples: [docs/TOOLS.md](docs/TOOLS.md).

| Tool | One line |
| --- | --- |
| `find_identifier` | Which captures in a directory mention an IMSI, MSISDN, IP, Call-ID or Session-Id |
| `pcap_info` | Packet count, duration, link type, protocol hierarchy, active limits |
| `capture_metadata` | pcapng writer, interfaces, snaplen, capture filter and the drop counters tshark cannot show |
| `capture_quality` | Can loss and timing conclusions be drawn from this file? Verdict with reasons |
| `conversations` | Top talkers at IP, TCP, UDP, SCTP or Ethernet level |
| `filter_packets` | Rows of fields for any display filter (the escape hatch) |
| `packet_detail` | One frame's full dissection, as in Wireshark's details pane |
| `expert_info` | tshark's expert warnings, errors and malformed packets, with frames |
| `find_fields` | Search tshark's field names without reading a capture |
| `check_filter` | Compile a display filter and name its fields without reading a capture |
| `diameter_transactions` | Requests paired with answers, result codes named, RTT, unanswered |
| `diameter_sessions` | The same grouped by Session-Id, with per-session counts |
| `diameter_avps` | The AVPs behind each transaction: flags with bit names, Subscription-Data digest, full tree |
| `gtp_sessions` | GTPv2-C requests paired with responses across NATs and proxy chains, cause names, PAA |
| `gtpv1_sessions` | GTPv1-C (Gn/Gp) PDP contexts paired, with cause names |
| `gtp_user_plane` | GTP-U packets, bytes and inner addresses per tunnel |
| `gtp_tunnel_health` | Inner TCP loss, reordering, MSS/MTU and ICMP per GTP-U tunnel |
| `pfcp_sessions` | PFCP (N4/Sx) sessions, rejections, reports, usage and peer restarts |
| `message_rates` | Messages per interval, bursts, storms and subscriber loops with the nodes involved |
| `dns_transactions` | Queries paired with responses, unanswered ones included, per-server latency, failing names |
| `tls_handshakes` | Client offer versus server choice, alerts, certificate, outcome per connection |
| `response_times` | Network, server and receiver time per TCP flow (HTTP/1, HTTP/2, gRPC) |
| `tcp_health` | Per-stream loss by location, resets with their likely source, windows, MTU black holes |
| `tcp_connections` | Every connection attempt: connected, refused, filtered or ICMP-prohibited, who closed it; per destination success rate |
| `icmp_errors` | Every ICMP/ICMPv6 error by sender, kind and quoted flow: fragmentation needed, rejects, routing loops, lost pings |
| `sip_dialogs` | Messages grouped by Call-ID with outcome after any challenge |
| `sip_call_detail` | One call: timings, SDP, Reason headers, who hung up |
| `media_path_check` | SDP-negotiated media against the RTP seen: one-way audio, NAT, 488 |
| `rtp_streams` | Per-stream loss, jitter, RTCP and an E-model MOS estimate, linked to the call |
| `dtmf_events` | RFC 4733 and SIP INFO digits in order, checked against the SDP |
| `ims_registration` | REGISTER flows per UE with a verdict: registered, expired, deregistered, challenge-loop, failed |
| `sms_over_ims` | Each SMS over IMS with its RP answer and a verdict |
| `sctp_associations` | Handshake, heartbeats, retransmissions, aborts per association |
| `sigtran_messages` | M3UA, SCCP, TCAP and MAP with operation names, IMSI and MSISDN |
| `trace_subscriber` | One timeline for a subscriber across Diameter, GTP, PFCP, MAP and SIP |
| `compare_captures` | A working and a failing capture side by side, with the first divergence |

## Redaction

Telecom captures carry IMSIs, MSISDNs, IMEIs, SIP users and UE addresses. Start the server
with `--redact ids` (or `TSHARK_MCP_REDACT=ids`), or pass `redact="ids"` on a call, and those
values come back as stable keyed tokens such as `imsi:3f2a9c1b0d` that still join across
tools and work as arguments in later calls. `ids+ips` hides every IP address too. A call can
raise the server's level, never lower it. What is found, what is not, and how the pre-scan
works: [docs/SAFETY.md](docs/SAFETY.md#redaction).

## Limitations

* No live capture, by design. The server reads files that already exist and nothing else.
* No decryption: IPsec, TLS and ciphered NAS are reported as tshark sees them. `tls_handshakes`
  reads only the clear part of the handshake; after a TLS 1.3 ServerHello its outcome is inferred
  from the record pattern and says so.
* Large captures are slow. tshark reads the whole file for every call; a 500 MB capture
  with a selective filter takes tens of seconds, so prefer pre-sliced captures.
* Pairing follows what is in the file. A request whose answer was captured on another
  interface is `unanswered`; one the capture stopped too soon to answer is also
  `near_capture_end`. How GTP responses are matched across NATs and proxies is in
  [docs/TOOLS.md](docs/TOOLS.md).
* MAP decoding relies on tshark's dissectors; a segmented XUDT whose other segments are
  missing is reported as segmented, not guessed.

## Roadmap

1. 5G core: HTTP/2 SBI (Nnrf, Nausf, Nsmf).
2. Streaming per-call progress so a long tshark run can be cancelled from the client.
3. Optional S1AP/NGAP and NAS summaries with EMM/ESM cause names.

## Development

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

The suite is 645 tests and runs in about a minute; CI runs it on Python 3.10 to 3.13 with
the tshark that Ubuntu 24.04 ships (4.2). Every capture the tests use is synthetic, built by
`tests/pcapgen.py` at run time with documentation addresses and test identities, and the three
captures under `examples/` come from the same generator, so nothing in the repository contains
traffic from a real network (the list of scenarios is in [docs/TOOLS.md](docs/TOOLS.md#how-the-tools-are-tested)).
Conventions for contributors and for agents: [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md).

## Licence

MIT, Copyright (c) 2026 Karl Hulse.
