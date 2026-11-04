# CLAUDE.md

See [AGENTS.md](AGENTS.md): it holds the conventions for using this server and for
contributing to it, and it is the file to keep current.

Claude-specific notes:

- To use the server from Claude Code: `claude mcp add tshark-mcp -- tshark-mcp --allow-dir /path/to/pcaps`.
  From Claude Desktop, add `{"command": "tshark-mcp", "args": ["--allow-dir", "/path/to/pcaps"]}`
  under `mcpServers` in `claude_desktop_config.json`.
- When working on this repository: run `pytest` and `ruff check --select F,E9 src tests` before
  opening a pull request; one bug or feature per PR with its regression test; synthetic captures
  only; no generated-by footers or co-author trailers in commits or PR text.
