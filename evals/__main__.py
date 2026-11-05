"""Run the task-success scenarios against the server over stdio.

    python -m evals                          # scripted driver: deterministic, no API cost
    python -m evals --only one_way_audio     # one scenario
    python -m evals --report docs/EVALS.md   # rewrite the results table in the docs
    python -m evals --xml evals/tshark_mcp_eval.xml   # the mcp-builder XML question set instead
    python -m evals --driver llm --model claude-opus-5-5   # a model picks the calls (costs tokens)
    python -m evals --server-dir /captures -- docker run -i --rm -v "$DIR:/captures:ro" tshark-mcp

The exit status is 1 when fewer than --min-pass scenarios pass (default: all of them).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

from .harness import build_captures, markdown_table, run_all
from .scenarios import SCENARIOS

REPORT_BEGIN = "<!-- evals:begin -->"
REPORT_END = "<!-- evals:end -->"


def _write_report(path: Path, table: str) -> None:
    text = path.read_text(encoding="utf-8")
    start, end = text.index(REPORT_BEGIN) + len(REPORT_BEGIN), text.index(REPORT_END)
    path.write_text(text[:start] + "\n" + table + text[end:], encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m evals", description=__doc__.splitlines()[0])
    p.add_argument("--driver", choices=("scripted", "llm"), default="scripted",
                   help="scripted replays each scenario's steps (default); llm lets a model choose the calls")
    p.add_argument("--model", default=None,
                   help="llm driver: Anthropic model id (default claude-opus-5-5), or 'scripted' for the offline stand-in")
    p.add_argument("--only", action="append", default=[], metavar="ID", help="run only these scenario ids")
    p.add_argument("--captures", type=Path, default=None,
                   help="directory to write the synthetic captures to (default: a temporary directory)")
    p.add_argument("--server-dir", default=None,
                   help="the capture directory as the server sees it (for a server in a container)")
    p.add_argument("--min-pass", type=float, default=1.0,
                   help="fraction of scenarios that must pass for exit status 0 (default 1.0)")
    p.add_argument("--report", type=Path, default=None, help="rewrite the table between the evals markers in this file")
    p.add_argument("--json", type=Path, default=None, help="write per-scenario results and calls as JSON")
    p.add_argument("--xml", type=Path, default=None, metavar="FILE",
                   help="run the qa_pairs of an mcp-builder evaluation XML file (evals/tshark_mcp_eval.xml) "
                        "instead of the built-in scenarios")
    p.add_argument("--list", action="store_true", help="list the scenarios and exit")
    p.add_argument("command", nargs="*", help="after --: the server command (default: this Python's tshark_mcp.server)")
    args = p.parse_args(argv)

    if args.xml:
        from .xml_bridge import load  # noqa: PLC0415
        source = load(args.xml)
    else:
        source = list(SCENARIOS)
    scenarios = [s for s in source if not args.only or s.id in args.only]
    if args.list:
        for s in source:
            print(f"{s.id}: {s.question}")
        return 0
    unknown = set(args.only) - {s.id for s in source}
    if unknown:
        p.error(f"unknown scenario id(s): {', '.join(sorted(unknown))}")

    model = None
    if args.driver == "llm":
        from .llm import DEFAULT_MODEL, AnthropicModel  # noqa: PLC0415
        model = "scripted" if args.model == "scripted" else AnthropicModel(args.model or DEFAULT_MODEL)

    with tempfile.TemporaryDirectory(prefix="tshark-mcp-evals-") as tmp:
        captures = build_captures((args.captures or Path(tmp)).resolve())
        results = asyncio.run(run_all(scenarios, captures=str(captures), server_dir=args.server_dir,
                                      command=args.command or None, driver=args.driver, model=model))

    table = markdown_table(results, scenarios)
    print(table, end="")
    if args.report:
        _write_report(args.report, table)
    if args.json:
        args.json.write_text(json.dumps(
            [dict(r.row(), answer=r.answer, transcript=[{"tool": c.tool, "args": c.args, "is_error": c.is_error}
                                                        for c in r.calls]) for r in results], indent=1) + "\n")
    passed = sum(r.passed for r in results)
    return 0 if passed >= args.min_pass * len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
