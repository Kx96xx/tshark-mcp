# tshark-mcp

A read-only [MCP](https://modelcontextprotocol.io) server that lets an LLM agent analyse
existing packet captures through `tshark`, with first-class support for the mobile-core
protocols: Diameter, GTPv2-C, GTP-U, SIP and SCTP/M3UA/SCCP/TCAP/MAP.

The server can only ever run `tshark -r <file>` on files inside directories you allow,
under hard limits on file size, packets, output size and run time. It cannot capture,
write, export, resolve names or load code. That is the point: an agent should be able to
read a capture without being able to run one.

## Why

Investigating a failed attach, a dropped bearer or a lost SMS means correlating Diameter,
GTP, MAP and SIP by subscriber across one capture. tshark can do all of it, but an agent
driving a raw shell is a liability. tshark-mcp gives the agent ten narrow tools that return
compact JSON, pair requests with answers, name the codes it sees (Result-Code 5420, GTP
cause 78, MAP opcode 46) and flag what never got a reply.

## Install

Requires Python 3.10+ and tshark 4.0 or newer (tested with 4.2 and 4.6). tshark comes with
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
| `pcap_info(path)` | Packet count, duration, first/last timestamp, size, link type, top 15 protocol-hierarchy entries, active limits |
| `conversations(path, layer)` | Endpoint pairs at `ip`, `ipv6`, `tcp`, `udp`, `sctp` or `eth` with frames and bytes per direction |
| `filter_packets(path, display_filter, fields, limit)` | Rows of fields for packets matching a display filter; field names are validated against `tshark -G fields` |
| `diameter_transactions(path, filter, limit)` | Requests paired with answers by Hop-by-Hop/End-to-End id and Session-Id: command name, application, hosts, realms, User-Name, Result-Code or Experimental-Result-Code with name, RTT, `unanswered` |
| `gtp_sessions(path, filter, limit)` | GTPv2-C requests paired with responses by sequence and peer: message name, IMSI, MSISDN, APN, F-TEIDs with interface names, cause code and name, PAA, RTT, `unanswered` |
| `gtp_user_plane(path, teid, limit)` | GTP-U per TEID: packets, bytes, first/last time, outer endpoints, inner IP addresses |
| `sip_dialogs(path, filter, limit)` | Messages grouped by Call-ID: method and response sequence, From, To, Request-URI, P-Asserted-Identity, final status, time to final response |
| `sctp_associations(path, limit)` | Per endpoint pair: handshake state, initiate tags, DATA chunks, heartbeats sent vs acked, retransmissions, ABORT/SHUTDOWN seen |
| `sigtran_messages(path, filter, limit)` | M3UA/SCCP/TCAP/MAP: SCCP type and segmentation, calling/called GT and SSN, point codes, TCAP primitive and ids, components with MAP operation name, IMSI, MSISDN; Begins linked to their End |
| `trace_subscriber(path, imsi, msisdn, limit)` | One time-ordered timeline for a subscriber across Diameter, GTPv2-C (following control-plane TEIDs), MAP and SIP, each row with protocol, message, result and pairing |

Every tool returns JSON. Failures come back as `{"error": {"type": ..., "message": ...}}`
rather than exceptions, and `"truncated": true` tells the agent a cap was reached and the
filter should be narrowed. See [docs/EXAMPLE.md](docs/EXAMPLE.md) for a worked
investigation with the real output shapes.

## Safety model

The limits are the product. Each one is enforced in code, configurable, and impossible to
switch off.

| Control | Default | Where |
| --- | --- | --- |
| Path allowlist: resolved real path must sit under an `--allow-dir`; paths outside are refused before existence is checked | none (server refuses to start) | `limits.Allowlist` |
| Maximum capture size | 500 MB (`--max-file-mb`, `TSHARK_MCP_MAX_FILE_MB`) | `limits.Limits` |
| Packets dissected per call (`-c`) | 500 (`--max-packets`); 20 000 for aggregating tools | `limits.Limits` |
| JSON returned per call | 200 KB (`--max-output-kb`); rows are dropped to fit and `truncated` is set | `server._fit` |
| Raw tshark stdout kept in memory | 64 MB; tshark is killed beyond it | `runner.Runner` |
| Wall-clock per tshark run | 60 s (`--timeout`); tshark is killed beyond it | `runner.Runner` |
| Read-only argv | `-r` is mandatory; `-i`, `-w`, `-D`, `-f`, `-a`, `-b`, `-X`, `-o`, `--export-*` and the other capture, write and extension flags are refused before a process is created | `runner.assert_read_only` |
| No shell, no name resolution | argv list only, `-n` on every run | `runner.Runner` |
| Display filters | linted for control characters and shell metacharacters outside quoted strings, then compiled by tshark against an empty capture before touching the real file | `limits.lint_display_filter`, `runner.validate_display_filter` |
| Field names | must exist in `tshark -G fields` (cached once) | `fields.validate_fields` |
| Audit log | one JSON line per call: tool, arguments, duration, status, bytes returned (`--log-file`, `TSHARK_MCP_LOG`) | `server._audit` |

The test-suite covers each of these, including the timeout and output cap against a fake
tshark subprocess.

## Limitations

* No live capture, by design. The server reads files that already exist and nothing else.
* No decryption: IPsec, TLS and ciphered NAS are reported as tshark sees them.
* Large captures are slow. tshark reads the whole file for every call; a 500 MB capture
  with a selective filter takes tens of seconds, so prefer pre-sliced captures.
* Pairing follows what is in the file. A request whose answer was captured on another
  interface is reported as unanswered; a sequence-number collision between unrelated
  GTP peers is disambiguated by peer pair only.
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

Tests build their own synthetic captures with scapy at run time (Diameter ULR/ULA and an
unanswered AIR, GTPv2-C Create Session with cause 16 and 78, GTP-U, a SIP INVITE dialog,
an SCTP handshake with an unanswered heartbeat, MAP updateLocation and mo-forwardSM over
M3UA), so nothing in the repository contains traffic from a real network.

## Licence

MIT, Copyright (c) 2026 Karl Hulse.
