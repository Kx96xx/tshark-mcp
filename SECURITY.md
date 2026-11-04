# Security

## Design

tshark-mcp is built so that an agent can read a capture without being able to run one, and
so that a malicious capture or a malicious agent cannot turn the server into anything more
than a bounded `tshark -r`.

- **Read-only by construction.** The only program the server starts is tshark (and `dftest`
  beside it, for `check_filter`). It is started from an argv list, never a shell, always with
  `-n` and `-r`. Capture, write, export, preference and extension flags (`-i`, `-w`, `-D`,
  `-f`, `-a`, `-b`, `-X`, `-o`, `--export-*`, ...) are refused before a process is created;
  the one `-o` the server sets itself is checksum validation in `capture_quality`. `-z` is
  limited to a fixed list of read-only statistics.
- **Path allowlist.** Every path an agent passes must resolve, symlinks followed, to a file
  under one of the `--allow-dir` directories. Paths outside are refused before existence is
  checked, so the server cannot be used to probe the filesystem. It refuses to start without
  an allowlist.
- **Hard caps, none switchable off**: capture size (500 MB), matching packets dissected in
  full (500), frames read per run (200 000, with a ceiling on any `-c` the runner will pass),
  JSON per call (30 KB), raw stdout kept (64 MB, tshark is killed beyond it), wall clock per
  run and per multi-pass call (60 s, tshark is killed beyond it), files opened per directory
  search (50). The numeric ones are configurable; see the caps table in [docs/SAFETY.md](docs/SAFETY.md).
- **Inputs are validated before they reach tshark.** Display filters are linted for control
  characters and shell metacharacters outside quoted strings, then compiled by tshark against
  an empty capture before the real file is touched. Field names must exist in
  `tshark -G fields`. Structured arguments (IMSI, MSISDN, APN, TEID, Call-ID, Session-Id,
  method, identifier) are linted to the shape of that identifier; quotes and backslashes are
  refused.
- **Packet text is data, not instructions.** Every string copied from a packet (SIP URIs and
  display names, Diameter hosts and realms, DNS names, certificate fields, decoded values) is
  stripped of control, bidirectional-override and zero-width characters, capped in length,
  and the keys that hold such text are listed in `untrusted_text_fields` so a client can treat
  them accordingly. Nonces, authentication vectors and SMS text are never returned.
- **Subscriber identifiers can be redacted** (`--redact ids` or `ids+ips`) with keyed tokens
  that the server maps back in memory only; nothing is written to disk and a call can raise
  the server's redaction level but never lower it.
- **Audit log.** With `--log-file`, one JSON line per call records the tool, arguments
  (redacted when redaction is on), duration, status and bytes returned.

## Transport

The supported transport is **stdio**: the MCP client starts the server as a child process and
nothing listens on the network. `--transport streamable-http` exists for local experiments
only. It has **no authentication**; never expose it beyond localhost, and never put it in
front of captures you would not hand to anyone who can reach that port.

## What is out of scope

- tshark itself. The dissectors run on untrusted input, and Wireshark publishes its own
  advisories; keep tshark updated and treat captures from unknown sources as hostile. The caps
  above bound the damage a crashing or looping dissector can do (time, memory, output), but
  cannot prevent a dissector bug from being reached.
- The host the server runs on. The server reads the files it is pointed at with the
  permissions of the user who started it; run it as a user who can read the captures and
  nothing more.

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/Kx96xx/tshark-mcp/security/advisories/new)
for this repository rather than in a public issue. Include the tshark and Python versions, the
tool and arguments, and a synthetic capture or generator that reproduces the problem (never
real traffic). You will get an acknowledgement within a week; fixes go out as a new release
with a changelog entry crediting the reporter unless they prefer otherwise.

Supported versions: the latest release and `main`.
