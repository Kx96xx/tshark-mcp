# Safety model

How tshark-mcp stays read-only and bounded, in detail. The [README](../README.md) has the
three-bullet version; [SECURITY.md](../SECURITY.md) says how to report a vulnerability.

## Transport

The supported transport is stdio: the client starts the server as a child process and
nothing listens on the network. `--transport streamable-http` exists for local
experiments only. It has no authentication, so never expose it beyond localhost or put it
in front of captures you would not hand to anyone who can reach that port.

## Controls and caps

The limits are the product. Each one is enforced in code, the numeric ones are
configurable, and none can be switched off.

| Control | Default | Where |
| --- | --- | --- |
| Path allowlist: resolved real path must sit under an `--allow-dir`; paths outside are refused before existence is checked | none (server refuses to start) | `limits.Allowlist` |
| Maximum capture size | 500 MB (`--max-file-mb`, `TSHARK_MCP_MAX_FILE_MB`) | `limits.Limits` |
| Matching packets dissected in full per call by the per-packet tools (Diameter, GTPv2-C, SIGTRAN) | 500 (`--max-packets`, `TSHARK_MCP_MAX_PACKETS`) | `limits.Limits` |
| Frames read from a capture per dissecting tshark run (`-c`), and matching packets kept by the aggregating tools (`gtp_user_plane`, `sctp_associations`, `sip_dialogs`, `rtp_streams`, `find_identifier`); a longer capture is reported as truncated | 200 000 (`--max-scan-packets`, `TSHARK_MCP_MAX_SCAN_PACKETS`) | `limits.Limits` |
| Hard ceiling on any `-c` the runner will pass, whatever a tool asks for. The statistics runs of `pcap_info` (`capinfos`, `-z io,phs`) and `conversations` (`-z conv`) read the whole file, bounded by the size cap and the timeout | `max_scan_packets` + 1 (one sentinel frame that shows whether the file goes on) | `runner.Runner.read_capture` |
| Files opened by one `find_identifier` call | 50 (`--max-files`, `TSHARK_MCP_MAX_FILES`), and the whole call shares one `--timeout` budget | `limits.Limits`, `server.find_identifier` |
| JSON returned per call | 30 KB (`--max-output-kb`, `TSHARK_MCP_MAX_OUTPUT_KB`); rows past it are left for the next page (`next_offset`), inner lists cut to fit are named in `trimmed`; a call's `max_output_kb` (and `output="summary"`, 8 KB) can only lower it | `server._fit` |
| Raw tshark stdout kept in memory | 64 MB (`TSHARK_MCP_MAX_STDOUT_MB`); tshark is killed beyond it | `runner.Runner` |
| Wall-clock per tshark run | 60 s (`--timeout`, `TSHARK_MCP_TIMEOUT`); tshark is killed beyond it | `runner.Runner` |
| Cancelled requests | the runner polls the request's cancellation every 0.25 s while tshark runs and while it waits for a slot, kills the child and returns nothing; the audit line says `cancelled` | `runner.Runner._run`, `progress.cancelled` |
| Wall-clock per multi-pass call (`find_identifier`, `trace_subscriber`) | the same `--timeout`, shared by every tshark run of the call | `server.find_identifier`, `server.trace_subscriber` |
| Read-only argv | `-r` is mandatory; `-i`, `-w`, `-D`, `-f`, `-a`, `-b`, `-X`, `-o`, `--export-*` and the other capture, write and extension flags are refused before a process is created. The one exception is `-o` followed by exactly `ip.check_checksum:TRUE`, `tcp.check_checksum:TRUE` or `udp.check_checksum:TRUE`, which `capture_quality` sets itself to validate checksums, `nas-eps.null_decipher:TRUE`/`FALSE` (`nas_procedures` `null_cipher`) and `esp.enable_null_encryption_decode_heuristic:TRUE` (the SIP/IMS tools' `esp_null`: read SIP inside ESP with NULL encryption; ESP keys are never accepted); an agent argument can only switch one of these fixed values on, never name a preference. `-z` takes only the read-only statistics `io`, `conv`, `endpoints`, `expert`, `rtp`, `sip`, `diameter`, `dns` and `http` | `runner.assert_read_only`, `runner.ALLOWED_PREFERENCES`, `runner.ALLOWED_STATS` |
| Writing files | only `export_subset`, only with `--export-dir DIR` (off by default). The directory must exist, may not be a symlink and may not overlap an `--allow-dir` (unless `--export-inside-allow-dir`), so an agent cannot grow the corpus it reads. The runner builds the one write argv itself (`-n -r <capture> -c N -Y <filter> -F pcapng -w <tmp>`), checks its exact shape and that the target is a temporary file the server created with O_EXCL in that directory; `-w` and `-F` stay refused on every other run. The file is linked to its sanitised name and never replaces an existing file or symlink; `--export-max-mb` (50) and 100,000 packets cap it; every write is an audit record with its sha256 | `export.py`, `runner.Runner.write_subset`, `runner._check_write_argv` |
| No shell, no name resolution | argv list only, `-n` on every run | `runner.Runner` |
| Clean tshark profile | every child (tshark, capinfos, dftest) gets an environment with only `PATH`, locale, `TZ` and temp variables kept, and `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `WIRESHARK_CONFIG_DIR` and `WIRESHARK_EXTCAP_DIR` pointing at one empty read-only directory the server creates. No personal `init.lua`, Lua script, binary plugin, extcap, preference, colouring rule or profile of the account running the server is loaded, and inherited `WIRESHARK_*`, `SSLKEYLOGFILE`, `LD_PRELOAD` and `DYLD_*` are dropped. The global (system) plugins stay, since dissection is the product. `--allow-user-profile` (`TSHARK_MCP_ALLOW_USER_PROFILE=1`) passes the environment through unchanged | `runner.Runner.child_env` |
| Concurrent tshark runs | 2 across all calls (`--max-concurrent-runs`, `TSHARK_MCP_MAX_CONCURRENT_RUNS`); a run waits up to 30 s for a slot (`--busy-wait`, `TSHARK_MCP_BUSY_WAIT`), then the call fails with `busy` | `runner.Runner._execute` |
| CPU priority and memory per run | nice +10 on every child; on Linux an address-space limit (RLIMIT_AS) of 2048 MB (`--max-tshark-memory-mb`, `TSHARK_MCP_MAX_TSHARK_MEMORY_MB`) set right after the start, before tshark opens the capture. A run that runs out of memory fails with `tshark_failed` and `out_of_memory: true`. macOS has no working RLIMIT_AS: run the server in a container or VM with a memory limit there | `runner.Runner._constrain` |
| Capture swapped after the allowlist check | the capture's device and inode are taken before tshark starts and compared right after the start and again at the end of the run; any change fails the call with `capture_changed` and nothing from the run is returned | `runner.Runner.read_capture` |
| Decode-as (`-d`) | allowed only as `tcp.port`, `udp.port`, `sctp.port` or `sctp.ppi` `==<number>[-<number>],<protocol>`; anything else is refused like a forbidden flag | `runner.check_decode_as` |
| Display filters | linted for control characters and shell metacharacters outside quoted strings, then compiled by tshark against an empty capture before touching the real file. `check_filter` also runs `dftest -- <filter>` when dftest sits beside tshark: it compiles the filter and reads no file | `limits.lint_display_filter`, `runner.validate_display_filter`, `runner.dftest_filter` |
| Field names | must exist in `tshark -G fields` (cached once) | `fields.validate_fields` |
| Structured arguments (`session_id`, `call_id`, `imsi`, `apn`, `teid`, `method`, `identifier`) | linted to the shape of that identifier before being embedded in a display filter; quotes and backslashes are refused | `limits.lint_*`, `search.build_filter` |
| Text copied from packets | every string in a result loses control characters, bidirectional overrides and zero-width characters; SIP names and URIs, Diameter hosts, realms and Session-Ids, DNS names, TLS certificate fields, APNs, expert summaries and other free text are capped at 256 characters, and decoded values (`packet_detail` layers, `filter_packets` values, AVP trees) at 512, with a `...[+N chars]` marker; `untrusted_text_fields` names the keys in each result that hold packet text, which is data from the network, never instructions | `untrusted.apply` |
| Subscriber identifiers | off by default; `--redact ids` or `ids+ips` (or `redact=` on a call) replaces them with keyed tokens before the length caps run; tokens map back to values in memory only, nothing is written | `redact.Redactor`, `server._guarded` |
| Redaction pre-scan | with redaction on, one `-T fields` run per capture (path and mtime) under the frame, time and stdout caps above, before the first result leaves; a pre-scan stopped by a cap marks results `redaction.complete: false` with a warning | `server._prescan`, `redact.Redactor.seed` |
| Audit log | one JSON line per call: tool, arguments (redacted when redaction is on), duration, status, bytes returned (`--log-file`, `TSHARK_MCP_LOG`) | `server._audit` |

The test-suite covers each of these, including the timeout and output cap against a fake
tshark subprocess, and drives the real server over stdio through the MCP client to check
the published schemas and annotations.

## Redaction

Telecom captures carry IMSIs, MSISDNs, IMEIs, SIP users and UE addresses. To hand results
to a hosted model or paste them into a ticket without those values, start the server with
`--redact ids` (or `TSHARK_MCP_REDACT=ids`), or pass `redact="ids"` on a single call. A
call can raise the server's level, never lower it.

```
diameter_sessions(path="/pcaps/dra.pcap", imsi="001010123456789")
-> {"sessions": [{"user_name": "imsi:3f2a9c1b0d", ...}],
    "redaction": {"mode": "ids", "replaced": {"imsi": 1}, "stable": "for this server run", ...}}
```

* `ids` replaces IMSIs, MSISDNs and other E.164 numbers (global titles included), IMEI/IMEISV
  (also split as TAC-SNR-CD inside a `urn:gsma:imei:` instance id), SIP and tel URI users, and UE addresses (PAA, PDN address, PFCP UE IP, the inner
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
* Pre-scan: the first call that reads a capture also runs one bounded `tshark -r -T fields`
  pass over it (the usual frame, time and stdout caps) that collects its UE addresses (GTPv2
  PAA, GTPv1 End User Address, PFCP UE IP, RADIUS and Diameter Framed-IP, GTP-U inner
  addresses, SIP REGISTER Contact and Via hosts, contacts with `+sip.instance`) and the
  numbers in identifier fields, before anything is returned. So a first `conversations`
  call already hides them. It runs once per capture path and modification time, in memory
  only, and costs about one more read of the file (2.2 s on a 39 MB, 80 000-frame capture whose `conversations` call takes 1.0 s). If it stops at a cap
  (frame cap, timeout, a full token table), the result says `redaction.complete: false` with
  a warning: use `ids+ips` then.
* Numbers typed into USSD strings and SMS text (`gsm_map.ussd_string`, `gsm_sms.sms_text`): every
  run of 6 or more digits is replaced as a number (`*140*msisdn:3f2a9c1b0d#`), the pre-scan learns
  them too, and the packed GSM 7-bit bytes of the same text (`gsm_map.ss.ussd_String`) are dropped
  (`<redacted: N bytes of packed text>`). Shorter codes (`*100#`) stay.
* Limits: names in free text (SIP display names, SMS text) are not touched; a number of 13
  digits or fewer, or in `ids` mode a UE address, that sits in none of the fields above is
  replaced only once a tool shows it under a known key or in a URI; values inside compressed
  or encrypted payloads, split across fields, or in other encodings are not found; host
  names, realms, APNs and MAC addresses are kept. Redaction rewrites results only: the
  capture is never changed or written.
