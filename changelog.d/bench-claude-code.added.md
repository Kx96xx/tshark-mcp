- PcapBench `--driver claude-code`: each question is one `claude -p` session with only the arm's
  MCP server, so a benchmark run can use a Claude subscription instead of API credits; usage and
  the session's reported cost are recorded, and `--max-usd` stops on that cost. With a model, both
  arms are now judged alike (answer, budgets, at least one tool call) instead of holding the
  tshark-mcp arm to the scripted path; `redaction_join` gained an answer check.
- PcapBench answers: the system prompt asks for a value-only answer inside `<response>` tags (the
  mcp-builder evaluation format), and an answer check passes on that value or on the whole reply.
  First model results (Claude Code, Sonnet 5.5): tshark-mcp 30/35, plain tshark 27/35
  (docs/BENCHMARK.md, evals/results/2026-11-12-claude-code.json).
