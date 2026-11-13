"""PcapBench (evals/bench.py) and its baseline arm (evals/tshark_only.py)."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from evals import bench

from .conftest import TSHARK, requires_tshark


def test_questions_are_unique_across_both_sets():
    qs = bench.questions()
    assert len(qs) == len({q.id for q in qs}) >= 30
    assert {q.id for q in bench.questions("xml")} <= {q.id for q in qs}


def test_baseline_arm_may_only_call_run_tshark():
    q = bench.questions("xml")[0]
    assert bench.for_arm("tshark-only", q).expected_tools == {"run_tshark"}
    assert bench.for_arm("tshark-mcp", q) is q
    for arm in bench.ARMS:  # a model is judged on its answer and budgets, the same in both arms
        judged = bench.for_arm(arm, q, "claude-code")
        assert judged.expected_tools == frozenset() and judged.answer == q.answer and judged.max_calls == q.max_calls


def test_cost_guard_refuses_an_unstated_cap(capsys):
    with pytest.raises(SystemExit):
        bench.main(["--driver", "llm", "--model", "claude-opus-5-5"])
    assert "state the cap with --max-runs" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        bench.main(["--driver", "llm", "--model", "claude-opus-5-5", "--max-runs", "3"])
    with pytest.raises(SystemExit):
        bench.main(["--arms", "tshark-only"])  # the scripted driver cannot play the baseline


def test_budget_and_metering():
    budget = bench.Budget(price_in=2.0, price_out=10.0, max_usd=1.0)
    assert not budget.exhausted()
    budget.add({"input_tokens": 400_000, "output_tokens": 20_000})  # 0.8 + 0.2
    assert budget.exhausted() and bench.cost_usd({"input_tokens": 1_000_000, "output_tokens": 0}, 2.0, 10.0) == 2.0
    assert bench.cost_usd({"input_tokens": 1, "output_tokens": 1}, None, None) is None

    class Fake:
        def create(self, system, tools, messages):
            return {"content": [], "usage": {"input_tokens": 7, "output_tokens": 3}}
    m = bench.Metered(Fake())
    m.current = "a/q"
    m.create("", [], [])
    m.create("", [], [])
    assert m.usage["a/q"] == {"input_tokens": 14, "output_tokens": 6, "turns": 2}


@requires_tshark
def test_scripted_run_writes_the_results_file(tmp_path: Path, capsys):
    out = tmp_path / "r.json"
    assert bench.main(["--questions", "xml", "--out", str(out), "--captures", str(tmp_path / "caps")]) == 0
    data = json.loads(out.read_text())
    assert data["meta"]["schema_version"] == bench.SCHEMA_VERSION and data["meta"]["driver"] == "scripted"
    s = data["summary"]["tshark-mcp"]
    assert s["questions"] == s["passed"] == len(bench.questions("xml")) and s["success_pct"] == 100.0
    for r in data["rows"]:
        assert {"arm", "id", "passed", "calls", "tools", "result_tokens_estimate", "seconds", "refused_calls"} <= set(r)
    assert "| tshark-mcp |" in capsys.readouterr().out


@requires_tshark
def test_baseline_server_over_stdio(tmp_path: Path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    from . import pcapgen
    pcapgen.write_all(tmp_path)

    async def go():
        params = StdioServerParameters(command=sys.executable, env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK),
                                       args=["-m", "evals.tshark_only", "--allow-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = {t.name for t in (await session.list_tools()).tools}
                ok = await session.call_tool("run_tshark", {"path": str(tmp_path / "diameter.pcap"),
                                                            "args": ["-Y", "diameter", "-T", "fields", "-e", "frame.number"]})
                write_try = await session.call_tool("run_tshark", {"path": str(tmp_path / "diameter.pcap"),
                                                                   "args": ["-w", str(tmp_path / "x.pcap")]})
                outside = await session.call_tool("run_tshark", {"path": "/etc/hosts", "args": []})
                return names, ok.structured_content, write_try.structured_content, outside.structured_content

    names, ok, write_try, outside = asyncio.run(go())
    assert names == {"run_tshark"}
    assert ok["returncode"] == 0 and ok["stdout"].split()[:1] == ["1"]
    assert "error" in write_try and not (tmp_path / "x.pcap").exists()
    assert outside["error"]["type"] == "path_not_allowed"
