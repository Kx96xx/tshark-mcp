"""The mcp-builder XML evaluation set (evals/tshark_mcp_eval.xml) and its bridge to the harness."""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from evals import __main__ as cli
from evals.harness import build_captures, run_all
from evals.xml_bridge import DEFAULT_XML, XmlEvalError, answer_pattern, load

from .conftest import requires_tshark
from .test_mcp_client import EXPECTED_TOOLS

DOC = Path(__file__).resolve().parent.parent / "docs" / "EVALS.md"


def test_file_parses_as_the_reference_harness_reads_it():
    """mcp-builder's scripts/evaluation.py: ET.parse, then question and answer of every qa_pair."""
    root = ET.parse(str(DEFAULT_XML)).getroot()
    pairs = root.findall("qa_pair")
    assert root.tag == "evaluation" and len(pairs) >= 15
    for pair in pairs:
        question, answer = pair.findtext("question"), pair.findtext("answer")
        assert question and question.strip() and answer and answer.strip() and "\n" not in answer.strip()
        assert pair.get("id") and pair.findall("verify")


def test_bridge_scenarios():
    scenarios = load()
    ids = [s.id for s in scenarios]
    assert len(ids) == len(set(ids)) == len(ET.parse(str(DEFAULT_XML)).getroot().findall("qa_pair"))
    for s in scenarios:
        assert {st.tool for st in s.steps} <= EXPECTED_TOOLS, s.id
        assert all(st.args["path"].startswith("{captures}/") for st in s.steps if "path" in st.args), s.id
        assert re.match(s.answer[0], s.reference_answer) and re.match(s.answer[0], f"  {s.reference_answer}\n")
        assert not re.match(s.answer[0], s.reference_answer + " because"), s.id  # exact answer, nothing else
    assert any(len(s.steps) >= 2 for s in scenarios)  # multi-hop questions: two tools in sequence
    # verifies of the same call become one step with several checks
    assert any(len(st.checks) >= 2 for s in scenarios for st in s.steps)


def test_answer_pattern_is_literal():
    assert re.match(answer_pattern("100.64.0.7"), "100.64.0.7")
    assert not re.match(answer_pattern("100.64.0.7"), "100x64.0.7")


@pytest.mark.parametrize(("body", "message"), [
    ("<evaluation/>", "no <qa_pair>"),
    ("<evaluation><qa_pair><question>q</question><answer>a</answer></qa_pair></evaluation>", "no id"),
    ("<evaluation><qa_pair id='x'><question>q</question><answer>a</answer></qa_pair></evaluation>", "no <verify>"),
    ("<evaluation><qa_pair id='x'><question>q</question><answer>a</answer>"
     "<verify tool='pcap_info' check='packets' op='near'/></qa_pair></evaluation>", "op in"),
    ("<evaluation><qa_pair id='x'><question>q</question><answer>a</answer>"
     "<verify tool='pcap_info' args='{bad' check='packets'/></qa_pair></evaluation>", "not JSON"),
    ("<evaluation><qa_pair id='x'><question>q</question><answer>a</answer>"
     "<verify tool='pcap_info' check='packets' value='unquoted'/></qa_pair></evaluation>", "quote strings"),
])
def test_bridge_refuses_bad_files(tmp_path: Path, body: str, message: str):
    p = tmp_path / "e.xml"
    p.write_text(body)
    with pytest.raises(XmlEvalError, match=re.escape(message)):
        load(p)


def test_cli_lists_the_xml_questions(capsys):
    assert cli.main(["--xml", str(DEFAULT_XML), "--list"]) == 0
    assert capsys.readouterr().out.count("\n") == len(load())


def test_docs_describe_the_xml_set():
    text = DOC.read_text(encoding="utf-8")
    assert "evals/tshark_mcp_eval.xml" in text and "--xml" in text and "scripts/evaluation.py" in text


@pytest.fixture(scope="module")
def captures(tmp_path_factory: pytest.TempPathFactory) -> str:
    return str(build_captures(tmp_path_factory.mktemp("xml-evals")))


@requires_tshark
def test_every_xml_answer_is_in_the_tool_output(captures: str):
    """Scripted driver over the real stdio server: every verify holds, so every answer still holds."""
    results = asyncio.run(run_all(load(), captures=captures))
    failed = {r.id: r.failures for r in results if not r.passed}
    assert not failed


@requires_tshark
def test_xml_set_through_the_model_loop_offline(captures: str):
    """The llm driver's tool-use loop with the offline stand-in: the reference answer passes the exact match."""
    results = asyncio.run(run_all(load(), captures=captures, driver="llm", model="scripted"))
    failed = {r.id: r.failures for r in results if not r.passed}
    assert not failed
