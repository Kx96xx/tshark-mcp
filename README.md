# tshark-mcp: Wireshark analysis for AI assistants

<!-- mcp-name: io.github.Kx96xx/tshark-mcp -->

[![CI](https://github.com/Kx96xx/tshark-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Kx96xx/tshark-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tshark-mcp-server)](https://pypi.org/project/tshark-mcp-server/)
![Licence MIT](https://img.shields.io/badge/licence-MIT-green)

**Drop a pcap, ask your AI assistant what went wrong, get an answer with frame numbers.**
tshark-mcp is a read-only MCP server that runs `tshark -r` on captures you allow and turns
them into answers: failed connections, slow servers, DNS and TLS errors, one-way audio, and
the telecom failures generic tools miss (Diameter, GTP, SIP/IMS, SIGTRAN, 5G).

```sh
claude mcp add tshark-mcp -- uvx --from tshark-mcp-server tshark-mcp --allow-dir /path/to/pcaps
```

Needs [uv](https://docs.astral.sh/uv/) and tshark (comes with Wireshark). Cursor, Claude Desktop,
VS Code, Docker and the Claude Code plugin: [the guide](https://github.com/Kx96xx/tshark-mcp/blob/main/docs/GUIDE.md#install-and-connect).

![A real MCP client session: sip_dialogs and media_path_check on the one-way audio example](https://raw.githubusercontent.com/Kx96xx/tshark-mcp/main/docs/media/demo.gif)

## Why this one

- **Answers, not packet dumps.** Ask "what is wrong in this capture?" and `incident_summary`
  runs every check the capture's protocols allow, ranks the findings and names the next call.
  Every claim carries frame numbers you can open in Wireshark.
- **Built by a mobile core engineer.** It pairs requests with answers across Diameter, GTP,
  PFCP, SIP, RTP and MAP, names the cause codes with their 3GPP reference, and follows one
  subscriber across all of them.
- **Safe to hand to an agent.** No shell, no live capture, no writes: only `tshark -r` on files
  inside directories you allow, under hard caps on size, packets, output and time. Optional
  redaction hides IMSIs, phone numbers and IPs.
- **Checked against public captures.** 102 public sample captures, 1,064 tool calls; every
  wrong answer found was fixed and is re-tested ([results](https://github.com/Kx96xx/tshark-mcp/blob/main/docs/VALIDATION.md)).

<!-- tool-count -->Sixty-three<!-- /tool-count --> tools in all; a default set of 34 keeps the tool list small.

## Learn more

- [Guide](https://github.com/Kx96xx/tshark-mcp/blob/main/docs/GUIDE.md): install, example questions, tool list, prompts, safety, limits
- [Tool reference](https://github.com/Kx96xx/tshark-mcp/blob/main/docs/TOOLS.md) and a [worked investigation](https://github.com/Kx96xx/tshark-mcp/blob/main/docs/EXAMPLE.md)
- [Report a wrong answer or a bug](https://github.com/Kx96xx/tshark-mcp/issues/new/choose)

MIT licence, Copyright (c) 2026 Karl Hulse.
