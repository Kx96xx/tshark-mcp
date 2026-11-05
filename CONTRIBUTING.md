# Contributing

Thanks for looking. Small, focused pull requests are easiest to review and revert, so one bug
or one feature per PR, with its own test.

## Set up

```sh
git clone https://github.com/Kx96xx/tshark-mcp && cd tshark-mcp
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

You need tshark 4.0 or newer on `PATH` (`TSHARK_MCP_TSHARK=/path/to/tshark` overrides it).
CI runs the suite on Python 3.10 to 3.13 with tshark 4.2, so anything that depends on a newer
tshark must be gated on the version (`tests/conftest.py: tshark_version()`), and on the
oldest supported `mcp` and `pydantic`.

## Rules of the road

- **Read-only stays read-only.** Nothing may add a tshark flag that captures, writes, exports
  or loads code, relax a limit without a cap, or let an argument reach the shell. If a change
  touches `runner.py` or `limits.py`, say so in the PR and add a test that the refusal still
  holds.
- **Synthetic captures only.** Tests build their packets in `tests/pcapgen.py` with
  documentation addresses (RFC 5737), the test PLMN 001/01 and reserved numbers. Never commit
  or attach a capture from a real network, even a redacted one. The files under `examples/`
  are regenerated from the same generator and `tests/test_examples.py` checks them.
- **Verify against raw tshark.** When a tool counts or pairs something, the test (or the PR
  text) should show the number agrees with `tshark -z ...` or a `tshark -T fields` pass.
- **Name the codes.** New result codes, causes and flags get their names from the specification
  they come from, with the reference in a comment.
- **Keep the output contract.** Paged tools take `limit` and `offset` and return
  `total_matched`, `returned`, `dropped` and `next_offset`; truncation always comes with a
  `truncated_reason`; packet text goes through `untrusted.apply`. A new tool is a module in
  `src/tshark_mcp/tools/` plus `docs/tools/<name>.md`; then run `python scripts/gen_docs.py`,
  which rewrites the tool tables, the tool list in `llms.txt`, the tool counts and the MCPB
  manifest (never edit those by hand; CI checks them). Add a changelog fragment.
- `ruff check --select F,E9` must be clean; CI must be green on the exact commit before merge.

## Reporting a bug

Open an issue with the tshark and Python versions, the tool and arguments, what came back and
what you expected. Include a way to reproduce that does not involve real traffic: a few lines
added to `tests/pcapgen.py`, or a capture built with scapy or `text2pcap` from hand-written
packets.

## Changelog

Do not edit `CHANGELOG.md`. Add one file per pull request, `changelog.d/<topic>.<section>.md`
(section: added, changed, deprecated, removed, fixed or security), holding Markdown bullets for
users; [changelog.d/README.md](https://github.com/Kx96xx/tshark-mcp/blob/main/changelog.d/README.md) has the format. CI fails a pull request that changes `src/`
without one, unless it is labelled `no-changelog`.

## Releases

[RELEASING.md](https://github.com/Kx96xx/tshark-mcp/blob/main/RELEASING.md): the files that carry the version, assembling the fragments with
`python scripts/changelog.py --release X.Y.Z`, the release pull request and the GitHub release
that publishes to PyPI and the MCP Registry.
