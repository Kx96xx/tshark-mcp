- `tools/list` shows a small default toolset: 34 of the 56 tools (33 of 55 before `open_capture`) (`incident_summary`, the
  capture overview and generic tools, the most used TCP/IP and telecom tools). The compact list
  drops from about 177 KB to 104 KB (about 49k to 29k tokens). `--toolsets mobile,voice,network`
  (or `all`, env `TSHARK_MCP_TOOLSETS`) lists the rest. A tool outside the active toolsets still
  answers a call by name, and a prompt that names one is not listed. The Claude Desktop
  extension gains a "Toolsets" setting. To keep the old list: `--toolsets all`.
