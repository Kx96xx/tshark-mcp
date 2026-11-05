- `tools/list` shows a small default toolset: 33 of the 55 tools (`incident_summary`, the
  capture overview and generic tools, the most used TCP/IP and telecom tools). The compact list
  drops from about 159 KB to 94 KB (about 44k to 26k tokens). `--toolsets mobile,voice,network`
  (or `all`, env `TSHARK_MCP_TOOLSETS`) lists the rest. A tool outside the active toolsets still
  answers a call by name, and a prompt that names one is not listed. The Claude Desktop
  extension gains a "Toolsets" setting. To keep the old list: `--toolsets all`.
