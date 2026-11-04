---
name: Bug report
about: A tool returned the wrong thing, failed, or disagreed with raw tshark
title: ""
labels: bug
assignees: ""
---

**Tool and arguments**

```
diameter_transactions(path="/captures/x.pcap", filter="...")
```

**What came back** (the JSON, trimmed to the relevant rows; redact identifiers if needed)

```json
```

**What you expected**, with the raw tshark command or `-z` statistic that shows it:

```
tshark -n -r x.pcap -z diameter,srt
```

**How to reproduce without real traffic**

A few lines for `tests/pcapgen.py`, or a capture built with scapy or `text2pcap` from
hand-written packets, with documentation addresses and test identities. Please do not attach
captures from a real network, even redacted ones.

**Versions**

- tshark-mcp: (`tshark-mcp --version` or the commit)
- tshark: (`tshark --version | head -1`)
- Python and OS:
- MCP client (Claude Code, Claude Desktop, other):
