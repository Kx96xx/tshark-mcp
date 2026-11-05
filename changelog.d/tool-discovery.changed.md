- Tools can live in their own module under `src/tshark_mcp/tools/`, found and registered when the
  server starts (`diameter_peers` is the first). No change to any tool's name, arguments or
  output. `python -m tshark_mcp.server` now runs the installed package's module, so it serves the
  same tools as the `tshark-mcp` command.
