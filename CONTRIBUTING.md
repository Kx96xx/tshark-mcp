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
  `truncated_reason`; packet text goes through `untrusted.apply`. Update the tool tables in the README and `docs/TOOLS.md`,
  `llms.txt`, `AGENTS.md` and the test count when a tool is added or its arguments change.
- `ruff check --select F,E9` must be clean; CI must be green on the exact commit before merge.

## Reporting a bug

Open an issue with the tshark and Python versions, the tool and arguments, what came back and
what you expected. Include a way to reproduce that does not involve real traffic: a few lines
added to `tests/pcapgen.py`, or a capture built with scapy or `text2pcap` from hand-written
packets.
