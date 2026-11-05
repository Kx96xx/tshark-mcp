---
order: 50
readme: Off unless `--export-dir`: write the packets matching a filter and window to a new pcapng file for a vendor (never overwrites, size-capped, `headers_only` cuts payloads)
llms: only when the server runs with `--export-dir`: writes the matching packets (and start/end window) to a NEW pcapng file in that directory; returns `written` (path, packets, bytes, sha256, first/last), `capped`; never overwrites; `headers_only` cuts payloads to 96 bytes. Otherwise it returns `export_disabled`.
---

The one tool that writes, off unless the server was started with `--export-dir DIR`
(`export_disabled` otherwise). A `-T fields` pass lists the frames matching `display_filter`
(required) and the window under the frame cap; the first `max_packets` (default 10,000, at most
100,000) that fit in `--export-max-mb` (default 50) are written by tshark (`-F pcapng -w`, argv
built by the runner, never by the agent) to a temporary file the server created with O_EXCL in the
export directory, cut by `editcap -s` when `headers_only` (96 bytes) or `snaplen` (64 to 262,144) is
given, then hard-linked to `name` (reduced to `[A-Za-z0-9._-]`, `.pcapng` appended, no leading dot,
at most 100 characters). An existing file or symlink under that name is `file_exists`: nothing is
ever replaced. Returns `written` (`path`, `name`, `packets`, `bytes`, `sha256`, `first`/`last`,
`first_frame`/`last_frame`, `snaplen`), `capped` and `capped_reason`, `export_dir`,
`max_export_bytes` and a `reminder` that the file still holds addresses and identifiers (redaction
rewrites results, not packets). The audit log gets a `write` record with source, file, packets,
bytes, sha256 and filter. Annotated `readOnlyHint: false`, `destructiveHint: false`
