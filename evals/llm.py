"""The optional model driver: a model answers each scenario's question with the tools.

Off by default. ``python -m evals --driver llm`` needs the ``anthropic`` package and
credentials (``ANTHROPIC_API_KEY`` or an ``ant auth login`` profile); every run costs API
tokens. The loop is a plain Messages API tool-use loop: the tools are the server's own
``tools/list`` entries, each ``tool_use`` block becomes one MCP ``tools/call``, the result
goes back as a ``tool_result`` and the loop ends on the first turn without a tool call.

``ScriptedModel`` speaks the same shapes without a network: it plays a scenario's steps as
``tool_use`` blocks and then writes the scenario's reference answer, so CI exercises this
loop for free (tests/test_evals.py).
"""

from __future__ import annotations

import json
import time
from typing import Any

from .harness import Call, CallTool, CaseResult, Scenario, fill, result_payload, score

DEFAULT_MODEL = "claude-opus-5-5"
MAX_TURNS = 12
RESULT_CHARS = 60_000  # one tool result handed to the model, at most

SYSTEM = (
    "You investigate packet captures with the tshark-mcp tools. Capture files are under {captures} "
    "(subdirectories voice/, ims/ and examples/). Use absolute paths. Answer the question in a few "
    "sentences, quote the verdicts, codes and frame numbers the tools return, and never conclude that "
    "something is absent from a page that says more rows exist. When the question asks for a value "
    "only, end with that value alone inside <response></response>."
)


def _tool_defs(tools: list[Any]) -> list[dict[str, Any]]:
    out = []
    for t in tools:
        schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {"type": "object"}
        out.append({"name": t.name, "description": (t.description or "")[:4000], "input_schema": schema})
    return out


def _blocks(response: Any) -> list[dict[str, Any]]:
    """Content blocks as plain dicts, from an SDK Message or a dict."""
    content = response["content"] if isinstance(response, dict) else response.content
    blocks = []
    for b in content:
        blocks.append(b if isinstance(b, dict) else b.model_dump(exclude_none=True))
    return blocks


class AnthropicModel:
    """The Messages API through the official SDK (imported only when this driver is used)."""

    def __init__(self, model: str = DEFAULT_MODEL, max_tokens: int = 16000) -> None:
        import anthropic  # noqa: PLC0415

        self.client = anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens

    def create(self, system: str, tools: list[dict[str, Any]], messages: list[dict[str, Any]]) -> Any:
        return self.client.messages.create(model=self.model, max_tokens=self.max_tokens, system=system,
                                           tools=tools, messages=messages)


class ScriptedModel:
    """A stand-in model: one turn per scenario step, then the reference answer."""

    def __init__(self, scenario: Scenario, captures: str) -> None:
        self.scenario = scenario
        self.captures = captures
        self.turn = 0
        self.results: list[Any] = []

    def create(self, system: str, tools: list[dict[str, Any]], messages: list[dict[str, Any]]) -> dict[str, Any]:
        last = messages[-1]["content"]
        if isinstance(last, list):  # tool results of the previous turn feed {stepN:...} references
            for block in last:
                if block.get("type") == "tool_result":
                    self.results.append(json.loads(block["content"]))
        if self.turn < len(self.scenario.steps):
            step = self.scenario.steps[self.turn]
            self.turn += 1
            args = fill(step.args, self.captures, self.results)
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": f"call_{self.turn}", "name": step.tool, "input": args}]}
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": self.scenario.reference_answer}]}


async def run_llm(scenario: Scenario, call_tool: CallTool, tools: list[Any], listed: set[str],
                  captures: str, model: Any) -> CaseResult:
    """Let ``model`` answer the question; score its calls and its final text."""
    if model is None or model == "scripted":
        model = ScriptedModel(scenario, captures)
    defs = _tool_defs(tools)
    system = SYSTEM.format(captures=captures)
    messages: list[dict[str, Any]] = [{"role": "user", "content": scenario.question}]
    calls: list[Call] = []
    answer = ""
    for _ in range(MAX_TURNS):
        response = model.create(system, defs, messages)
        blocks = _blocks(response)
        messages.append({"role": "assistant", "content": blocks})
        uses = [b for b in blocks if b.get("type") == "tool_use"]
        if not uses:
            answer = "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text")
            break
        results = []
        for use in uses:  # every result of one turn goes back in one user message
            t0 = time.monotonic()
            data, is_error = result_payload(await call_tool(use["name"], use.get("input") or {}))
            calls.append(Call(use["name"], use.get("input") or {}, data, is_error, time.monotonic() - t0))
            results.append({"type": "tool_result", "tool_use_id": use["id"],
                            "content": json.dumps(data)[:RESULT_CHARS], "is_error": is_error})
        messages.append({"role": "user", "content": results})
    else:
        return score(scenario, calls, listed, answer, [f"no final answer after {MAX_TURNS} turns"])
    return score(scenario, calls, listed, answer, [])
