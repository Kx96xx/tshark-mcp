"""The Claude Code driver: each question is one ``claude -p`` session with the arm's server.

``--driver claude-code`` needs the ``claude`` CLI logged in (or ``CLAUDE_CODE_OAUTH_TOKEN`` in the
environment, from ``claude setup-token``); it runs on a Claude subscription instead of API
credits. Claude Code runs its own tool loop: the session gets only the arm's MCP server (no
built-in tools, no settings, no other MCP servers, nothing persisted), the same system prompt
as the ``llm`` driver, and the question. The tool calls and results are read back from the
``stream-json`` transcript and scored by :func:`evals.harness.score`, like every other driver.

Input tokens are what the session reports, cached ones included: Claude Code adds its own
framing, so they are higher than the ``llm`` driver's for the same question.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from .bench import Metered
from .harness import Call, CaseResult, Scenario, score
from .llm import SYSTEM

ROOT = str(Path(__file__).resolve().parent.parent)  # so `-m evals.tshark_only` imports from any cwd
SERVER = "pcap"  # the MCP server name inside the session: tools appear as mcp__pcap__<tool>
TIMEOUT_S = 900


def arm_server(command: list[str] | None, captures: str) -> dict[str, Any]:
    """The stdio server of an arm, as an MCP config entry (None: this server, every toolset)."""
    if not command:
        command = [sys.executable, "-m", "tshark_mcp.server", "--allow-dir", captures, "--toolsets", "all"]
    return {"command": command[0], "args": command[1:],
            "env": {"PYTHONPATH": os.pathsep.join(filter(None, [ROOT, os.environ.get("PYTHONPATH")]))}}


def claude_argv(model: str | None, config: str, system: str, max_turns: int) -> list[str]:
    argv = [shutil.which("claude") or "claude", "-p", "--system-prompt", system, "--mcp-config", config,
            "--strict-mcp-config", "--tools", "", "--allowedTools", f"mcp__{SERVER}",
            "--output-format", "stream-json", "--verbose", "--no-session-persistence",
            "--setting-sources", "", "--max-turns", str(max_turns)]
    return argv + (["--model", model] if model else [])


def _result_data(content: Any) -> Any:
    """A tool_result's content (a string or text blocks) as the tool's JSON, if it is JSON."""
    if isinstance(content, list):
        content = "".join(b.get("text", "") for b in content if isinstance(b, dict))
    try:
        return json.loads(content)
    except (TypeError, ValueError):
        return {"text": content}


def parse_transcript(lines: list[str]) -> tuple[list[Call], str, dict[str, int], list[str]]:
    """Tool calls, final answer, token usage and problems from a ``stream-json`` transcript."""
    uses: dict[str, tuple[str, dict[str, Any]]] = {}
    calls: list[Call] = []
    answer, problems, ended = "", [], False
    usage = {"input_tokens": 0, "output_tokens": 0, "turns": 0}
    prefix = f"mcp__{SERVER}__"
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get("type")
        if kind in ("assistant", "user"):
            for block in event.get("message", {}).get("content") or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    name = block.get("name", "")
                    uses[block.get("id", "")] = (name[len(prefix):] if name.startswith(prefix) else name,
                                                 block.get("input") or {})
                elif block.get("type") == "tool_result" and block.get("tool_use_id") in uses:
                    tool, args = uses[block["tool_use_id"]]
                    data = _result_data(block.get("content"))
                    is_error = bool(block.get("is_error")) or (isinstance(data, dict) and "error" in data)
                    calls.append(Call(tool, args, data, is_error, 0.0))
        elif kind == "result":
            ended = True
            answer = event.get("result") or ""
            u = event.get("usage") or {}
            usage["input_tokens"] = int(u.get("input_tokens") or 0) + int(u.get("cache_creation_input_tokens") or 0) \
                + int(u.get("cache_read_input_tokens") or 0)
            usage["output_tokens"] = int(u.get("output_tokens") or 0)
            usage["turns"] = int(event.get("num_turns") or 0)
            if event.get("total_cost_usd") is not None:
                usage["reported_cost_usd"] = event["total_cost_usd"]
            if event.get("is_error") or event.get("subtype", "success") != "success":
                problems.append(f"claude session ended with {event.get('subtype') or 'an error'}")
    if not ended:
        problems.append("claude session gave no result")
    return calls, answer, usage, problems


class ClaudeCodeModel(Metered):
    """Runs questions through ``claude -p``; ``usage`` per question, keyed like :class:`Metered`."""

    def __init__(self, model: str | None = None, max_turns: int = 12) -> None:
        if not shutil.which("claude"):
            raise SystemExit("--driver claude-code needs the claude CLI on PATH")
        super().__init__(None)
        self.name = model
        self.max_turns = max_turns

    def run(self, scenario: Scenario, listed: set[str], captures: str, command: list[str] | None) -> CaseResult:
        with tempfile.TemporaryDirectory(prefix="pcapbench-cc-") as tmp:
            config = os.path.join(tmp, "mcp.json")
            with open(config, "w", encoding="utf-8") as f:
                json.dump({"mcpServers": {SERVER: arm_server(command, captures)}}, f)
            env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}  # bill the subscription
            try:
                out = subprocess.run(claude_argv(self.name, config, SYSTEM.format(captures=captures), self.max_turns),
                                     input=scenario.question, capture_output=True, text=True, timeout=TIMEOUT_S,
                                     cwd=tmp, env=env)
                lines = out.stdout.splitlines()
            except subprocess.TimeoutExpired:
                lines = []
        calls, answer, usage, problems = parse_transcript(lines)
        if not lines:
            problems = [f"claude session timed out or printed nothing ({TIMEOUT_S} s)"]
        self.usage[self.current] = usage
        return score(scenario, calls, listed, answer, problems)
