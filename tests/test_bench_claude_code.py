"""PcapBench's claude-code driver: the stream-json transcript becomes scored calls, without a network.

A stand-in ``claude`` on PATH prints a canned transcript, so the whole path (bench CLI, harness,
driver, scoring, usage and reported cost) runs in CI for free.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from evals import bench, claude_code

ROOT = Path(__file__).resolve().parent.parent


def _ev(kind: str, **kw) -> str:
    return json.dumps({"type": kind, **kw})


def transcript(tool: str, args: dict, result: dict, answer: str, *, is_error: bool = False,
               subtype: str = "success") -> list[str]:
    use = {"type": "tool_use", "id": "toolu_1", "name": f"mcp__pcap__{tool}", "input": args}
    res = {"type": "tool_result", "tool_use_id": "toolu_1", "content": json.dumps(result), "is_error": is_error}
    return [
        _ev("system", subtype="init"),
        _ev("assistant", message={"content": [use]}),
        _ev("user", message={"content": [res]}),
        _ev("assistant", message={"content": [{"type": "text", "text": answer}]}),
        _ev("result", subtype=subtype, is_error=subtype != "success", result=answer, num_turns=2,
            total_cost_usd=0.0123, usage={"input_tokens": 4, "cache_creation_input_tokens": 100,
                                          "cache_read_input_tokens": 900, "output_tokens": 50}),
    ]


def test_parse_transcript_reads_calls_answer_and_usage():
    lines = transcript("pcap_info", {"path": "/c/a.pcap"}, {"packets": 7, "tokens_estimate": 40}, "7 packets")
    calls, answer, usage, problems = claude_code.parse_transcript(["not json", *lines])
    assert [(c.tool, c.args, c.result["packets"], c.is_error) for c in calls] == [("pcap_info", {"path": "/c/a.pcap"}, 7, False)]
    assert answer == "7 packets" and problems == []
    assert usage == {"input_tokens": 1004, "output_tokens": 50, "turns": 2, "reported_cost_usd": 0.0123}


def test_parse_transcript_marks_errors_and_failed_sessions():
    lines = transcript("pcap_info", {}, {"error": {"type": "not_found"}}, "", subtype="error_max_turns")
    calls, _, _, problems = claude_code.parse_transcript(lines)
    assert calls[0].is_error and "error_max_turns" in problems[0]
    assert claude_code.parse_transcript([])[3] == ["claude session gave no result"]


def test_text_block_results_and_non_json_results():
    assert claude_code._result_data([{"type": "text", "text": '{"a": 1}'}]) == {"a": 1}
    assert claude_code._result_data("plain words") == {"text": "plain words"}


def test_session_is_closed_to_everything_but_the_arm_server():
    argv = claude_code.claude_argv("sonnet", "/tmp/mcp.json", "SYS", 12)
    for flag in ("--strict-mcp-config", "--no-session-persistence", "--setting-sources"):
        assert flag in argv
    assert argv[argv.index("--tools") + 1] == "" and argv[argv.index("--allowedTools") + 1] == "mcp__pcap"
    assert argv[-2:] == ["--model", "sonnet"] and "--model" not in claude_code.claude_argv(None, "c", "s", 3)
    base = claude_code.arm_server(None, "/caps")
    assert base["args"][:4] == ["-m", "tshark_mcp.server", "--allow-dir", "/caps"]
    assert claude_code.ROOT in base["env"]["PYTHONPATH"]  # the baseline arm imports evals from any cwd


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    """A `claude` that answers every question with one pcap_info call and the packet count."""
    script = tmp_path / "bin" / "claude"
    script.parent.mkdir()
    lines = transcript("pcap_info", {"path": "x"}, {"packets": 3, "tokens_estimate": 10}, "3 packets")
    script.write_text(f"#!{sys.executable}\nimport sys\nsys.stdin.read()\nprint({chr(10).join(lines)!r})\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{script.parent}{os.pathsep}{os.environ['PATH']}")
    return script


def test_bench_runs_both_arms_through_the_driver(fake_claude, tmp_path, capsys):
    out = tmp_path / "r.json"
    qid = bench.questions("scenarios")[0].id
    with pytest.raises(SystemExit):  # a model driver must state its run cap
        bench.main(["--driver", "claude-code", "--only", qid])
    assert bench.main(["--driver", "claude-code", "--only", qid, "--max-runs", "2", "--out", str(out)]) == 0
    data = json.loads(out.read_text())
    assert data["meta"]["driver"] == "claude-code" and [r["arm"] for r in data["rows"]] == ["tshark-mcp", "tshark-only"]
    row = data["rows"][0]
    assert row["tools"] == ["pcap_info"] and row["input_tokens"] == 1004 and row["reported_cost_usd"] == 0.0123
    assert data["summary"]["tshark-mcp"]["reported_cost_usd"] == 0.0123
    assert "(reported)" in capsys.readouterr().out


def test_reported_cost_feeds_the_cap():
    budget = bench.Budget(max_usd=0.02)
    budget.add({"input_tokens": 1, "output_tokens": 1, "reported_cost_usd": 0.015})
    assert not budget.exhausted()
    budget.add({"input_tokens": 1, "output_tokens": 1, "reported_cost_usd": 0.015})
    assert budget.exhausted()
