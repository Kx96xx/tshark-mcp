"""PcapBench: the same questions answered by a model through two arms.

* ``tshark-mcp``: this server (every toolset listed);
* ``tshark-only``: one ``run_tshark(path, args)`` tool with the same sandbox and caps
  (:mod:`evals.tshark_only`), to measure what the tools add over plain tshark.

The questions are the built-in scenarios (``evals/scenarios.py``) and the mcp-builder XML set
(``evals/tshark_mcp_eval.xml``). Per arm and question it records success, calls, the model's input
and output tokens (from the API's ``usage``), the summed result size (``tokens_estimate``) and
wall time, and writes ``evals/results/<date>.json`` plus the table for ``docs/BENCHMARK.md``.

    python -m evals.bench --driver scripted              # CI: tshark-mcp arm, no model, no cost
    python -m evals.bench --driver llm --model claude-opus-5-5 --max-runs 70 \\
        --price-in <USD per MTok> --price-out <USD per MTok> --max-usd 20

Cost guard: a model run must state ``--max-runs`` (questions x arms x repeats) up front and is
refused when the plan is larger. With ``--price-in``/``--price-out`` the run stops before the
next question once the measured cost passes ``--max-usd``. The scripted driver plays only the
tshark-mcp arm (its steps name tshark-mcp tools).
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .harness import CaseResult, Scenario, build_captures, run_all
from .scenarios import SCENARIOS
from .xml_bridge import DEFAULT_XML, load

ARMS = ("tshark-mcp", "tshark-only")
RESULTS_DIR = Path(__file__).resolve().parent / "results"
SCHEMA_VERSION = 1


def questions(source: str = "all") -> list[Scenario]:
    """The benchmark questions: ``scenarios``, ``xml`` or ``all`` (ids are unique across both)."""
    out: list[Scenario] = []
    if source in ("all", "scenarios"):
        out += list(SCENARIOS)
    if source in ("all", "xml"):
        out += load(DEFAULT_XML)
    return out


def arm_command(arm: str) -> list[str] | None:
    """The stdio command of an arm (None: the harness default, this server with every toolset)."""
    if arm == "tshark-mcp":
        return None
    return [sys.executable, "-m", "evals.tshark_only"]


def for_arm(arm: str, scenario: Scenario, driver: str = "scripted") -> Scenario:
    """The question as one arm is scored; budgets stay the same in both arms.

    The scripted driver replays the scenario's steps, so it keeps them. With a model, both arms
    are judged alike: the answer, the call and token budgets, and at least one tool call (see
    :func:`row`). A model is not held to the scenario's own path through tshark-mcp's tools; the
    baseline arm, which has one tool, could not be held to anything comparable."""
    if driver == "scripted":
        return scenario if arm == "tshark-mcp" else dataclasses.replace(scenario, tools=frozenset({"run_tshark"}))
    return dataclasses.replace(scenario, steps=(), tools=frozenset())


class Metered:
    """Wraps a model and sums the API ``usage`` of every turn; the scenario key says whose it is."""

    def __init__(self, model: Any) -> None:
        self.model = model
        self.usage: dict[str, dict[str, int]] = {}
        self.current = ""

    def create(self, system: str, tools: list[dict[str, Any]], messages: list[dict[str, Any]]) -> Any:
        response = self.model.create(system, tools, messages)
        usage = response.get("usage") if isinstance(response, dict) else getattr(response, "usage", None)
        row = self.usage.setdefault(self.current, {"input_tokens": 0, "output_tokens": 0, "turns": 0})
        row["turns"] += 1
        for key in ("input_tokens", "output_tokens"):
            value = usage.get(key) if isinstance(usage, dict) else getattr(usage, key, None)
            row[key] += int(value or 0)
        return response


def cost_usd(usage: dict[str, int], price_in: float | None, price_out: float | None) -> float | None:
    if price_in is None or price_out is None:
        return None
    return round(usage["input_tokens"] / 1e6 * price_in + usage["output_tokens"] / 1e6 * price_out, 4)


async def run_arm(arm: str, qs: list[Scenario], captures: str, driver: str, model: Any,
                  budget: "Budget") -> list[dict[str, Any]]:
    rows = []
    metered = hasattr(model, "usage")  # Metered or a driver that meters itself (not isinstance: see __main__)
    if not metered:  # no cost to watch: one server for the whole arm
        results = await run_all([for_arm(arm, q, driver) for q in qs], captures=captures,
                                command=_with_dir(arm_command(arm), captures), driver=driver, model=model)
        return [row(arm, r, None, r.seconds, budget) for r in results] if results else []
    for q in qs:  # one server per question, so the cost cap is checked between questions
        if budget.exhausted():
            rows.append({"arm": arm, "id": q.id, "skipped": "cost cap reached"})
            continue
        model.current = f"{arm}/{q.id}"
        t0 = time.monotonic()
        (result,) = await run_all([for_arm(arm, q, driver)], captures=captures, command=_with_dir(arm_command(arm), captures),
                                  driver=driver, model=model)
        usage = model.usage.get(f"{arm}/{q.id}")
        rows.append(row(arm, result, usage, time.monotonic() - t0, budget))
        if usage:
            budget.add(usage)
    return rows


def _with_dir(command: list[str] | None, captures: str) -> list[str] | None:
    return None if command is None else [*command, "--allow-dir", captures]


def row(arm: str, r: CaseResult, usage: dict[str, int] | None, seconds: float, budget: "Budget") -> dict[str, Any]:
    failures = list(r.failures)
    if not r.calls:
        failures.append("answered without calling a tool")
    out = {"arm": arm, "id": r.id, "passed": not failures, "failures": failures[:5], "calls": len(r.calls),
           "tools": [c.tool for c in r.calls], "result_tokens_estimate": r.tokens, "seconds": round(seconds, 2),
           "refused_calls": sum(1 for c in r.calls if c.is_error and isinstance(c.result, dict)
                                and (c.result.get("error") or {}).get("type") in ("path_not_allowed", "forbidden_argument")),
           "answer": r.answer[:2000]}
    if usage:
        out.update(input_tokens=usage["input_tokens"], output_tokens=usage["output_tokens"], turns=usage["turns"],
                   cost_usd=cost_usd(usage, budget.price_in, budget.price_out))
        if "reported_cost_usd" in usage:  # claude-code: what the session itself reports
            out["reported_cost_usd"] = round(usage["reported_cost_usd"], 4)
    return out


@dataclasses.dataclass
class Budget:
    price_in: float | None = None
    price_out: float | None = None
    max_usd: float | None = None
    spent: float = 0.0

    def add(self, usage: dict[str, Any]) -> None:
        c = cost_usd(usage, self.price_in, self.price_out)
        if c is None:  # no prices given: the cost the session reports (claude-code), if any
            c = usage.get("reported_cost_usd")
        if c is not None:
            self.spent += c

    def exhausted(self) -> bool:
        return self.max_usd is not None and self.spent >= self.max_usd


def summarise(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for arm in dict.fromkeys(r["arm"] for r in rows):
        done = [r for r in rows if r["arm"] == arm and "passed" in r]
        n = len(done) or 1
        out[arm] = {
            "questions": len(done), "passed": sum(r["passed"] for r in done),
            "success_pct": round(100.0 * sum(r["passed"] for r in done) / n, 1),
            "mean_calls": round(sum(r["calls"] for r in done) / n, 2),
            "mean_result_tokens": round(sum(r["result_tokens_estimate"] for r in done) / n),
            "input_tokens": sum(r.get("input_tokens", 0) for r in done),
            "output_tokens": sum(r.get("output_tokens", 0) for r in done),
            "cost_usd": round(sum(r.get("cost_usd") or 0 for r in done), 4) if any(r.get("cost_usd") is not None for r in done) else None,
            "mean_seconds": round(sum(r["seconds"] for r in done) / n, 2),
            "reported_cost_usd": round(sum(r["reported_cost_usd"] for r in done), 4)
            if any("reported_cost_usd" in r for r in done) else None,
            "refused_calls": sum(r["refused_calls"] for r in done),
            "skipped": sum(1 for r in rows if r["arm"] == arm and "skipped" in r),
        }
    return out


def markdown(summary: dict[str, dict[str, Any]], meta: dict[str, Any]) -> str:
    lines = [f"Run {meta['date']}: driver `{meta['driver']}`, model `{meta.get('model') or '-'}`, "
             f"{meta['questions']} questions, {meta['repeats']} run(s) each.", "",
             "| Arm | Success | Mean calls | Mean result tokens | Model input / output tokens | Cost (USD) | Mean s |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for arm, s in summary.items():
        cost = "-" if s["cost_usd"] is None else f"{s['cost_usd']:.2f}"
        if s["cost_usd"] is None and s.get("reported_cost_usd") is not None:
            cost = f"{s['reported_cost_usd']:.2f} (reported)"
        io = "-" if not s["input_tokens"] else f"{s['input_tokens']:,} / {s['output_tokens']:,}"
        lines.append(f"| {arm} | {s['passed']}/{s['questions']} ({s['success_pct']}%) | {s['mean_calls']} | "
                     f"{s['mean_result_tokens']:,} | {io} | {cost} | {s['mean_seconds']} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m evals.bench", description=__doc__.splitlines()[0])
    p.add_argument("--driver", choices=("scripted", "llm", "claude-code"), default="scripted",
                   help="claude-code: each question is a `claude -p` session on a Claude subscription")
    p.add_argument("--model", default=None, help="llm driver: Anthropic model id, or 'scripted' (offline stand-in)")
    p.add_argument("--arms", default=None, help="comma-separated: tshark-mcp, tshark-only (default: both with a model driver, "
                                                "tshark-mcp with the scripted driver)")
    p.add_argument("--questions", choices=("all", "scenarios", "xml"), default="all")
    p.add_argument("--only", action="append", default=[], metavar="ID")
    p.add_argument("--repeats", type=int, default=1)
    p.add_argument("--max-runs", type=int, default=None,
                   help="llm driver: refuse to start when questions x arms x repeats is above this (required)")
    p.add_argument("--price-in", type=float, default=None, help="USD per million input tokens of the model")
    p.add_argument("--price-out", type=float, default=None, help="USD per million output tokens of the model")
    p.add_argument("--max-usd", type=float, default=None, help="stop before the next question past this cost")
    p.add_argument("--out", type=Path, default=None, help="results JSON (default evals/results/<date>-<driver>.json)")
    p.add_argument("--captures", type=Path, default=None)
    args = p.parse_args(argv)

    arms = [a.strip() for a in (args.arms or ("tshark-mcp,tshark-only" if args.driver != "scripted" else "tshark-mcp")).split(",")]
    if set(arms) - set(ARMS):
        p.error(f"unknown arm(s): {', '.join(sorted(set(arms) - set(ARMS)))}")
    if args.driver == "scripted" and arms != ["tshark-mcp"]:
        p.error("the scripted driver replays tshark-mcp calls: use --arms tshark-mcp")
    qs = [q for q in questions(args.questions) if not args.only or q.id in args.only]
    planned = len(qs) * len(arms) * args.repeats
    real_model = (args.driver == "llm" and args.model != "scripted") or args.driver == "claude-code"
    if real_model and (args.max_runs is None or planned > args.max_runs):
        p.error(f"{planned} model runs planned; state the cap with --max-runs N (at least {planned}) before spending")
    model: Any = None
    if args.driver == "claude-code":
        from .claude_code import ClaudeCodeModel  # noqa: PLC0415
        model = ClaudeCodeModel(args.model)
    elif args.driver == "llm":
        if args.model == "scripted":
            model = "scripted"
        else:
            from .llm import DEFAULT_MODEL, AnthropicModel  # noqa: PLC0415
            model = Metered(AnthropicModel(args.model or DEFAULT_MODEL))
    budget = Budget(args.price_in, args.price_out, args.max_usd)
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="pcapbench-") as tmp:
        captures = str(build_captures((args.captures or Path(tmp)).resolve()))
        for _ in range(args.repeats):
            for arm in arms:
                rows += asyncio.run(run_arm(arm, qs, captures, args.driver, model, budget))
    meta = {"schema_version": SCHEMA_VERSION, "date": dt.date.today().isoformat(), "driver": args.driver,
            "model": (args.model or "claude-opus-5-5") if args.driver == "llm" else
            (args.model or "claude default") if args.driver == "claude-code" else None, "arms": arms,
            "questions": len(qs), "repeats": args.repeats, "planned_runs": planned,
            "price_in": args.price_in, "price_out": args.price_out}
    summary = summarise(rows)
    out = args.out or RESULTS_DIR / f"{meta['date']}-{args.driver}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"meta": meta, "summary": summary, "rows": rows}, indent=1) + "\n", encoding="utf-8")
    print(markdown(summary, meta), end="")
    print(f"results: {out}", file=sys.stderr)
    return 0 if all(s["passed"] == s["questions"] for s in summary.values()) or args.driver != "scripted" else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
