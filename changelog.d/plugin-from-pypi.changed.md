- The Claude Code plugin starts the server from the PyPI release (`uvx --from
  "tshark-mcp-server>=0.2.0" tshark-mcp`) instead of building the main branch from git: faster
  first start, no git needed, and the server a user runs is a published version.
