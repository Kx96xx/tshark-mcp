"""Task-success evaluation harness.

A scenario is a question an operator would ask about a capture, the tool calls that answer
it and the facts the answer must contain. The harness starts the server over stdio (the
same way a client does), runs each scenario and scores it deterministically:

* the tools it calls exist in ``tools/list`` and are the ones the scenario expects;
* every check on every result holds (a verdict, a cause code, a frame number);
* no result says something the scenario forbids (for example "not found" on a page that
  was only truncated);
* the number of calls and the summed ``tokens_estimate`` stay under the scenario's budget.

Two drivers produce the tool calls. ``scripted`` (the default, used in CI) replays the
scenario's own steps: it proves the tools still answer the question with the right facts
and costs nothing. ``llm`` lets a model pick the calls from the question alone and adds
two checks on its final answer (``answer`` patterns that must appear, ``forbidden``
patterns that must not). The model driver is optional and off by default; see
``evals/llm.py`` and docs/EVALS.md.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------- scenarios


@dataclass(frozen=True)
class Check:
    """One fact on a tool result.

    ``path`` walks the structured result: ``a.b`` for keys, ``a[0]`` for an index,
    ``a[*]`` for every element (the check then holds when any element passes),
    ``a[key=value]`` for the first element whose ``key`` equals ``value``. ``op`` is one of
    eq, ne, contains (a list holds the value, or a string holds the substring),
    startswith, regex, ge, le, present, absent.
    """

    path: str
    op: str = "eq"
    value: Any = None

    def describe(self) -> str:
        if self.op in ("present", "absent"):
            return f"{self.path} {self.op}"
        return f"{self.path} {self.op} {self.value!r}"


@dataclass(frozen=True)
class Step:
    """One tool call. String arguments may hold ``{captures}`` (the capture directory as the
    server sees it) and ``{step0:path}`` (a value from an earlier step's result)."""

    tool: str
    args: dict[str, Any]
    checks: tuple[Check, ...] = ()
    expect_error: str | None = None  # the error type this call must return, if any


@dataclass(frozen=True)
class Scenario:
    id: str
    question: str
    steps: tuple[Step, ...]
    answer: tuple[str, ...] = ()       # regexes the final answer must match (llm driver)
    forbidden: tuple[str, ...] = ()    # regexes no answer may match
    reference_answer: str = ""         # what a correct answer says; checked against answer/forbidden
    tools: frozenset[str] = frozenset()  # tools the llm driver must call (default: the steps' tools)
    max_calls: int = 6
    max_tokens: int = 8000             # summed tokens_estimate of all results

    @property
    def expected_tools(self) -> frozenset[str]:
        return self.tools or frozenset(s.tool for s in self.steps if s.expect_error is None)


# --------------------------------------------------------------------------- paths and checks

_SEGMENT = re.compile(r"([^.\[\]]+)|\[(\*|-?\d+|[^\]=]+=[^\]]*)\]")
_MISSING = object()


def resolve(obj: Any, path: str) -> list[Any]:
    """Every value ``path`` reaches in ``obj`` (one value unless ``[*]`` fans out)."""
    values = [obj]
    for key, bracket in _SEGMENT.findall(path):
        nxt: list[Any] = []
        for v in values:
            if key:
                if isinstance(v, dict) and key in v:
                    nxt.append(v[key])
            elif bracket == "*":
                if isinstance(v, list):
                    nxt.extend(v)
            elif "=" in bracket:
                k, want = bracket.split("=", 1)
                if isinstance(v, list):
                    hit = next((e for e in v if isinstance(e, dict) and str(e.get(k)) == want), _MISSING)
                    if hit is not _MISSING:
                        nxt.append(hit)
            else:
                i = int(bracket)
                if isinstance(v, list) and -len(v) <= i < len(v):
                    nxt.append(v[i])
        values = nxt
    return values


def _holds(op: str, actual: Any, want: Any) -> bool:
    try:
        if op == "eq":
            return actual == want
        if op == "ne":
            return actual != want
        if op == "contains":
            return want in actual
        if op == "startswith":
            return isinstance(actual, str) and actual.startswith(want)
        if op == "regex":
            return isinstance(actual, str) and re.search(want, actual) is not None
        if op == "ge":
            return actual >= want
        if op == "le":
            return actual <= want
    except TypeError:
        return False
    raise ValueError(f"unknown op {op!r}")


def check(result: Any, c: Check) -> bool:
    values = resolve(result, c.path)
    if c.op == "present":
        return bool(values)
    if c.op == "absent":
        return not values
    return any(_holds(c.op, v, c.value) for v in values)


_REF = re.compile(r"\{step(\d+):([^}]+)\}")


def fill(value: Any, captures: str, results: list[Any]) -> Any:
    """Substitute ``{captures}`` and ``{stepN:path}`` in a step's arguments."""
    if isinstance(value, dict):
        return {k: fill(v, captures, results) for k, v in value.items()}
    if isinstance(value, list):
        return [fill(v, captures, results) for v in value]
    if not isinstance(value, str):
        return value
    whole = _REF.fullmatch(value)
    if whole:  # a whole-string reference keeps the referenced value's type
        found = resolve(results[int(whole.group(1))], whole.group(2))
        if not found:
            raise LookupError(f"{value}: nothing at that path in step {whole.group(1)}'s result")
        return found[0]
    value = _REF.sub(lambda m: str((resolve(results[int(m.group(1))], m.group(2)) or [""])[0]), value)
    return value.replace("{captures}", captures)


# --------------------------------------------------------------------------- captures


def build_captures(directory: Path) -> Path:
    """Write every synthetic capture the scenarios read (tests/pcapgen.py, no real traffic)."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from tests import pcapgen  # noqa: PLC0415  (scapy is a dev dependency)

    directory.mkdir(parents=True, exist_ok=True)
    pcapgen.write_all(directory)
    pcapgen.write_merged_pcap(directory / "all.pcap", directory)
    pcapgen.write_voice_pcaps(directory / "voice")
    pcapgen.write_ims_pcaps(directory / "ims")
    pcapgen.write_example_pcaps(directory / "examples")
    return directory


# --------------------------------------------------------------------------- results


@dataclass
class Call:
    tool: str
    args: dict[str, Any]
    result: Any
    is_error: bool
    seconds: float


@dataclass
class CaseResult:
    id: str
    passed: bool
    failures: list[str] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    answer: str = ""
    tokens: int = 0
    seconds: float = 0.0

    def row(self) -> dict[str, Any]:
        return {"id": self.id, "passed": self.passed, "failures": self.failures,
                "tools": [c.tool for c in self.calls], "calls": len(self.calls),
                "tokens_estimate": self.tokens, "seconds": round(self.seconds, 2)}


def result_payload(call_result: Any) -> tuple[Any, bool]:
    """The structured content of an MCP CallToolResult (text JSON when there is none)."""
    is_error = bool(getattr(call_result, "is_error", None) or getattr(call_result, "isError", None))
    data = getattr(call_result, "structured_content", None) or getattr(call_result, "structuredContent", None)
    if data is None:
        texts = [getattr(b, "text", "") for b in getattr(call_result, "content", []) or []]
        try:
            data = json.loads("".join(texts))
        except ValueError:
            data = {"text": "".join(texts)}
    if isinstance(data, dict) and "error" in data:
        is_error = True
    return data, is_error


def score(scenario: Scenario, calls: list[Call], listed: set[str], answer: str | None,
          step_failures: list[str]) -> CaseResult:
    failures = list(step_failures)
    for c in calls:
        if c.tool not in listed:
            failures.append(f"called {c.tool}, which is not in tools/list")
    called = {c.tool for c in calls}
    for tool in sorted(scenario.expected_tools - called):
        failures.append(f"never called {tool}")
    if len(calls) > scenario.max_calls:
        failures.append(f"{len(calls)} calls, budget {scenario.max_calls}")
    tokens = sum(int(c.result.get("tokens_estimate", 0)) for c in calls if isinstance(c.result, dict))
    if tokens > scenario.max_tokens:
        failures.append(f"results cost about {tokens} tokens, budget {scenario.max_tokens}")
    text = scenario.reference_answer if answer is None else answer
    for pattern in scenario.answer:
        if not re.search(pattern, text, re.IGNORECASE):
            failures.append(f"answer does not say /{pattern}/")
    for pattern in scenario.forbidden:
        if re.search(pattern, text, re.IGNORECASE):
            failures.append(f"answer says the forbidden /{pattern}/")
    return CaseResult(scenario.id, not failures, failures, calls, text, tokens,
                      sum(c.seconds for c in calls))


# --------------------------------------------------------------------------- drivers

CallTool = Callable[[str, dict[str, Any]], Any]  # async (name, args) -> CallToolResult


async def run_scripted(scenario: Scenario, call_tool: CallTool, listed: set[str], captures: str) -> CaseResult:
    """Replay the scenario's steps and check every fact on every result."""
    calls: list[Call] = []
    results: list[Any] = []
    failures: list[str] = []
    for n, step in enumerate(scenario.steps):
        try:
            args = fill(step.args, captures, results)
        except LookupError as exc:
            failures.append(f"step {n} {step.tool}: {exc}")
            break
        t0 = time.monotonic()
        data, is_error = result_payload(await call_tool(step.tool, args))
        calls.append(Call(step.tool, args, data, is_error, time.monotonic() - t0))
        results.append(data)
        if step.expect_error is not None:
            got = data.get("error", {}).get("type") if isinstance(data, dict) else None
            if got != step.expect_error:
                failures.append(f"step {n} {step.tool}: expected error {step.expect_error}, got {got or 'success'}")
        elif is_error:
            err = data.get("error", {}) if isinstance(data, dict) else {}
            failures.append(f"step {n} {step.tool}: {err.get('type')}: {err.get('message')}")
            continue
        for c in step.checks:
            if not check(data, c):
                failures.append(f"step {n} {step.tool}: {c.describe()} (got {resolve(data, c.path)[:3]!r})")
    return score(scenario, calls, listed, None, failures)


# --------------------------------------------------------------------------- session


def server_params(allow_dir: str, command: list[str] | None = None):
    """How to start the server: this interpreter's ``tshark_mcp.server`` by default, or any
    command (``docker run -i ...``) that speaks MCP over stdio."""
    from mcp.client.stdio import StdioServerParameters  # noqa: PLC0415

    env = dict(os.environ)
    if command:
        return StdioServerParameters(command=command[0], args=command[1:], env=env)
    return StdioServerParameters(command=sys.executable,
                                 args=["-m", "tshark_mcp.server", "--allow-dir", allow_dir], env=env)


async def run_all(scenarios: list[Scenario], *, captures: str, server_dir: str | None = None,
                  command: list[str] | None = None, driver: str = "scripted",
                  model: Any = None) -> list[CaseResult]:
    """Start one server over stdio and run every scenario against it."""
    from mcp import ClientSession  # noqa: PLC0415
    from mcp.client.stdio import stdio_client  # noqa: PLC0415

    seen_dir = server_dir or captures
    out: list[CaseResult] = []
    async with stdio_client(server_params(seen_dir, command)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            listed = {t.name for t in tools}

            async def call_tool(name: str, args: dict[str, Any]) -> Any:
                return await session.call_tool(name, args)

            for scenario in scenarios:
                if driver == "scripted":
                    out.append(await run_scripted(scenario, call_tool, listed, seen_dir))
                else:
                    from .llm import run_llm  # noqa: PLC0415
                    out.append(await run_llm(scenario, call_tool, tools, listed, seen_dir, model))
    return out


# --------------------------------------------------------------------------- report


def markdown_table(results: list[CaseResult], scenarios: list[Scenario]) -> str:
    by_id = {s.id: s for s in scenarios}
    lines = ["| Scenario | Question | Tools | Calls | Tokens | Result |", "| --- | --- | --- | --- | --- | --- |"]
    for r in results:
        tools = ", ".join(f"`{t}`" for t in dict.fromkeys(c.tool for c in r.calls))
        verdict = "pass" if r.passed else "FAIL: " + "; ".join(r.failures)[:200]
        lines.append(f"| `{r.id}` | {by_id[r.id].question} | {tools} | {len(r.calls)} | {r.tokens} | {verdict} |")
    passed = sum(r.passed for r in results)
    lines.append("")
    lines.append(f"{passed} of {len(results)} scenarios pass.")
    return "\n".join(lines) + "\n"
