## What and why

One bug or one feature per pull request. Say what was wrong or missing, what changed, and
how a user sees the difference (the tool, its arguments and the rows or fields that change).

## Checks

- [ ] A test covers the change, built on synthetic packets in `tests/pcapgen.py` (no real traffic).
- [ ] Counts or pairings in the new output were checked against raw tshark (`-z ...` or `-T fields`).
- [ ] Nothing new can capture, write, export, load code or reach a shell; limits still apply.
- [ ] A fragment in `changelog.d/` (`<topic>.<section>.md`, see changelog.d/README.md) if users can see the change; never an edit to `CHANGELOG.md`.
- [ ] A new or changed tool: `docs/tools/<name>.md` written or updated and `python scripts/gen_docs.py` run (it rewrites the tables, llms.txt, counts and the MCPB manifest).
- [ ] `pytest` and `ruff check --select F,E9` pass locally; CI green before merge.
