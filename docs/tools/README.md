# docs/tools

One file per tool, `docs/tools/<tool name>.md`: the words that `scripts/gen_docs.py` puts into
the generated tool tables of the README and `docs/TOOLS.md` and the tool list of `llms.txt`.
Edit the words here, never in those tables; the tool set, the argument lists and the tool
count come from the server's registry (`tshark_mcp.server.TOOLS`).

```markdown
---
order: 200
readme: The one line of the README table.
llms: the line of llms.txt after the signature, for an agent choosing a tool.
---

The docs/TOOLS.md reference text: what the tool returns, its verdicts, its narrowing
arguments and its limits. Lines may wrap; they are joined with one space.
```

- `order` places the tool in all three lists (ties sort by name). Look at the README table and
  pick a number between the neighbours you want; gaps of ten leave room.
- Each value is one line. A `|` inside `readme` or the reference text is written `\|`.
- A tool with no file, or a file with no tool, fails `python scripts/gen_docs.py --check`
  (CI, and `tests/test_gen_docs.py`).

After adding a tool or changing one of these files, run `python scripts/gen_docs.py` and commit
what it rewrites (README.md, docs/TOOLS.md, llms.txt, AGENTS.md, mcpb/manifest.json).
