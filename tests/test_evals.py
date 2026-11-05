"""The task-success evaluation suite (evals/): the harness, the scenarios over the real stdio
server, and the model driver with its offline stand-in."""

from __future__ import annotations

import asyncio
import dataclasses
from pathlib import Path

import pytest

from evals import __main__ as cli
from evals.harness import Check, Scenario, Step, build_captures, check, fill, resolve, run_all
from evals.llm import ScriptedModel
from evals.scenarios import SCENARIOS

from .conftest import requires_tshark
from .test_mcp_client import EXPECTED_TOOLS

AIR = next(s for s in SCENARIOS if s.id == "unanswered_air")
DOC = Path(__file__).resolve().parent.parent / "docs" / "EVALS.md"


# --------------------------------------------------------------------------- the harness alone

RESULT = {"rows": [{"k": "a", "n": 1, "tags": ["x"]}, {"k": "b", "n": 2, "ok": False}], "verdict": "fine"}


def test_resolve_paths() -> None:
    assert resolve(RESULT, "verdict") == ["fine"]
    assert resolve(RESULT, "rows[1].n") == [2]
    assert resolve(RESULT, "rows[-1].k") == ["b"]
    assert resolve(RESULT, "rows[*].n") == [1, 2]
    assert resolve(RESULT, "rows[k=b].n") == [2]
    assert resolve(RESULT, "rows[ok=False].k") == ["b"]
    assert resolve(RESULT, "rows[k=z].n") == []
    assert resolve(RESULT, "rows[5]") == [] and resolve(RESULT, "nothing.here") == []


@pytest.mark.parametrize(("c", "holds"), [
    (Check("verdict", "eq", "fine"), True),
    (Check("verdict", "eq", "bad"), False),
    (Check("rows[*].n", "eq", 2), True),          # any element
    (Check("rows[0].tags", "contains", "x"), True),
    (Check("verdict", "startswith", "fi"), True),
    (Check("verdict", "regex", "^f.n"), True),
    (Check("rows[1].n", "ge", 3), False),
    (Check("rows[0].n", "le", 1), True),
    (Check("rows[0].ok", "present"), False),
    (Check("rows[0].ok", "absent"), True),
    (Check("verdict", "ge", 3), False),           # a type mismatch fails, never raises
])
def test_check_ops(c: Check, holds: bool) -> None:
    assert check(RESULT, c) is holds


def test_fill_references_keep_type() -> None:
    results = [{"next_offset": 3, "id": "imsi:00ff"}]
    assert fill({"offset": "{step0:next_offset}"}, "/c", results) == {"offset": 3}
    assert fill({"p": "{captures}/x.pcap", "q": "id={step0:id}"}, "/c", results) == {"p": "/c/x.pcap", "q": "id=imsi:00ff"}
    with pytest.raises(LookupError):
        fill("{step0:missing}", "/c", results)


def test_scenarios_are_well_formed() -> None:
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids)) and len(ids) >= 15
    for s in SCENARIOS:
        assert s.expected_tools <= EXPECTED_TOOLS, s.id
        assert {st.tool for st in s.steps} <= EXPECTED_TOOLS, s.id
        assert len(s.steps) <= s.max_calls and s.reference_answer, s.id
        assert all(st.checks or st.expect_error for st in s.steps), s.id


def test_cli_lists_scenarios(capsys) -> None:
    assert cli.main(["--list"]) == 0
    assert capsys.readouterr().out.count("\n") == len(SCENARIOS)
    with pytest.raises(SystemExit):
        cli.main(["--only", "no_such_scenario"])


def test_docs_name_every_scenario() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert cli.REPORT_BEGIN in text and cli.REPORT_END in text
    for s in SCENARIOS:
        assert f"`{s.id}`" in text, s.id


# --------------------------------------------------------------------------- over the stdio server

@pytest.fixture(scope="module")
def captures(tmp_path_factory: pytest.TempPathFactory) -> str:
    return str(build_captures(tmp_path_factory.mktemp("evals")))


@requires_tshark
def test_every_scenario_passes_over_stdio(captures: str) -> None:
    results = asyncio.run(run_all(SCENARIOS, captures=captures))
    failed = {r.id: r.failures for r in results if not r.passed}
    assert not failed
    assert all(r.tokens > 0 for r in results)


BROKEN = [
    # a wrong fact
    dataclasses.replace(AIR, id="wrong_fact", steps=(
        Step("diameter_transactions", {"path": "{captures}/diameter.pcap"}, (Check("summary.unanswered", "eq", 0),)),)),
    # a tool that does not exist
    Scenario("no_such_tool", "q", (Step("not_a_tool", {}, (Check("x", "present"),)),), reference_answer="a"),
    # an answer that says what the scenario forbids
    dataclasses.replace(AIR, id="forbidden_answer",
                        reference_answer="Every request was answered."),
    # an expected error that does not come
    Scenario("missing_error", "q", (Step("pcap_info", {"path": "{captures}/diameter.pcap"}, (), expect_error="path_not_allowed"),),
             reference_answer="a"),
    # over budget
    dataclasses.replace(AIR, id="over_budget", max_tokens=10),
]


@requires_tshark
def test_broken_scenarios_fail(captures: str) -> None:
    results = {r.id: r for r in asyncio.run(run_all(BROKEN, captures=captures))}
    assert not any(r.passed for r in results.values())
    assert any("summary.unanswered eq 0" in f for f in results["wrong_fact"].failures)
    assert any("not in tools/list" in f for f in results["no_such_tool"].failures)
    assert any("forbidden" in f for f in results["forbidden_answer"].failures)
    assert any("expected error path_not_allowed, got success" in f for f in results["missing_error"].failures)
    assert any("budget 10" in f for f in results["over_budget"].failures)


@requires_tshark
def test_model_driver_with_the_offline_model(captures: str) -> None:
    """The tool-use loop: tool_use blocks become tools/call, results return as tool_result,
    the final text is scored against answer and forbidden."""
    results = asyncio.run(run_all(SCENARIOS, captures=captures, driver="llm", model="scripted"))
    failed = {r.id: r.failures for r in results if not r.passed}
    assert not failed
    assert all(r.answer for r in results)


@requires_tshark
def test_model_driver_scores_the_answer(captures: str) -> None:
    wrong = dataclasses.replace(AIR, reference_answer="Every request got answered.")
    [r] = asyncio.run(run_all([wrong], captures=captures, driver="llm", model="scripted"))
    assert not r.passed and any("frame 5" in f for f in r.failures)


def test_scripted_model_message_shapes() -> None:
    s = SCENARIOS[0]
    m = ScriptedModel(s, "/c")
    first = m.create("sys", [], [{"role": "user", "content": s.question}])
    assert first["stop_reason"] == "tool_use"
    use = first["content"][0]
    assert use["type"] == "tool_use" and use["name"] == "sip_dialogs" and use["input"]["path"].startswith("/c/")
    second = m.create("sys", [], [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": use["id"], "content": '{"dialogs": [{"call_id": "c-1"}]}'}]}])
    assert second["content"][0]["input"]["call_id"] == "c-1"
    final = m.create("sys", [], [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "call_2", "content": "{}"}]}])
    assert final["stop_reason"] == "end_turn" and final["content"][0]["text"] == s.reference_answer
