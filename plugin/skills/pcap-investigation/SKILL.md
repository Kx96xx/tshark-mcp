---
name: pcap-investigation
description: Investigate a packet capture (pcap, pcapng) with the tshark-mcp tools. Use when the user asks what went wrong in a capture, about a subscriber, call, session, DNS, TLS or TCP problem in a pcap, or which capture holds an identifier.
---

# Investigating a capture with tshark-mcp

The tshark-mcp server reads capture files inside the directory set in the plugin settings.
Paths are absolute. It never captures, writes or runs a shell.

1. Unknown file: `incident_summary(path)` ranks the findings, each with its `next_call`.
   Unknown file name: `find_identifier(path=<directory>, identifier=...)`; ring buffers:
   `capture_index(path=<directory>, start=..., end=...)`.
2. Before blaming the network for loss: `capture_quality(path)` and read its `verdict`.
3. Then the protocol tool the question names: `trace_subscriber`, `diameter_sessions`,
   `gtp_sessions`, `sip_dialogs`, `media_path_check`, `tcp_health`, `dns_transactions`,
   `tls_handshakes`. `cause_lookup(protocol, code)` explains any code you quote.
4. Large results: `output="summary"` first, `columns=[...]` to keep only some keys. A result
   with `next_offset` has more rows: never call something absent from one page.
5. Quote verdicts and frame numbers; confirm a claim with `packet_detail(path, frame)`.

For a guided run the server also offers MCP prompts; the skills of this plugin named after
them (one-way-audio, subscriber-cannot-attach, trust-this-capture, working-vs-failing,
ims-registration-or-sms, slow-data-session) give the order of calls.
