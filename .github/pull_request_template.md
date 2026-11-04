## What and why

One bug or one feature per pull request. Say what was wrong or missing, what changed, and
how a user sees the difference (the tool, its arguments and the rows or fields that change).

## Checks

- [ ] A test covers the change, built on synthetic packets in `tests/pcapgen.py` (no real traffic).
- [ ] Counts or pairings in the new output were checked against raw tshark (`-z ...` or `-T fields`).
- [ ] Nothing new can capture, write, export, load code or reach a shell; limits still apply.
- [ ] README and `docs/TOOLS.md` tables, `llms.txt`, `AGENTS.md`, `CHANGELOG.md` and the test count updated if a tool or its arguments changed.
- [ ] `pytest` and `ruff check --select F,E9` pass locally; CI green before merge.
