"""Load the mcp-builder XML evaluation set into harness scenarios.

``evals/tshark_mcp_eval.xml`` is in the format of Anthropic's mcp-builder skill
(``<evaluation><qa_pair><question/><answer/></qa_pair>...``): its ``scripts/evaluation.py``
reads only ``<question>`` and ``<answer>`` and scores the agent's response by exact string
match. Each ``<qa_pair>`` here also has an ``id`` and ``<verify>`` children that the skill's
script ignores:

    <verify tool="gtp_sessions" args='{"path": "all.pcap"}' check="transactions[imsi=...].cause"
            op="eq" value="78"/>

:func:`load` turns every pair into a :class:`~evals.harness.Scenario`: consecutive verifies with
the same tool and arguments become one :class:`~evals.harness.Step` with several checks, a path
argument is prefixed with ``{captures}/``, ``value`` is JSON, and the answer becomes an anchored
regex on the model's final answer. So ``python -m evals --xml evals/tshark_mcp_eval.xml`` runs
the set on the scripted driver (CI: every answer is still in the tool output) and
``--driver llm`` scores a model on it.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .harness import Check, Scenario, Step

DEFAULT_XML = Path(__file__).resolve().parent / "tshark_mcp_eval.xml"
PATH_ARGS = ("path", "path_a", "path_b")
OPS = frozenset({"eq", "ne", "contains", "startswith", "regex", "ge", "le", "present", "absent"})
# A multi-hop question reads a few whole results: more calls and tokens than a one-step scenario.
MAX_CALLS = 8
MAX_TOKENS = 40_000


class XmlEvalError(ValueError):
    """The XML file breaks the format (a missing id, question, answer or verify, a bad check)."""


def _args(raw: str, where: str) -> dict:
    try:
        args = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise XmlEvalError(f"{where}: args is not JSON: {exc}") from None
    if not isinstance(args, dict):
        raise XmlEvalError(f"{where}: args must be a JSON object")
    for key in PATH_ARGS:
        if isinstance(args.get(key), str) and not args[key].startswith(("/", "{captures}")):
            args[key] = "{captures}/" + args[key]
    return args


def _value(raw: str | None, where: str):
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise XmlEvalError(f"{where}: value {raw!r} is not JSON (quote strings: &quot;...&quot;)") from None


def answer_pattern(answer: str) -> str:
    """The regex the final answer must match: the exact answer, alone, ignoring outer space."""
    return rf"^\s*{re.escape(answer)}\s*$"


def load(path: Path | str = DEFAULT_XML) -> list[Scenario]:
    """Every ``<qa_pair>`` of ``path`` as a scenario, in file order."""
    root = ET.parse(str(path)).getroot()
    if root.tag != "evaluation":
        raise XmlEvalError(f"root element is <{root.tag}>, not <evaluation>")
    out: list[Scenario] = []
    seen: set[str] = set()
    for n, pair in enumerate(root.findall("qa_pair"), 1):
        pid = (pair.get("id") or "").strip()
        where = f"qa_pair {pid or n}"
        if not pid:
            raise XmlEvalError(f"{where}: no id attribute")
        if pid in seen:
            raise XmlEvalError(f"{where}: duplicate id")
        seen.add(pid)
        question = " ".join((pair.findtext("question") or "").split())
        answer = (pair.findtext("answer") or "").strip()
        if not question or not answer or "\n" in answer:
            raise XmlEvalError(f"{where}: needs a question and a one-line answer")
        steps: list[Step] = []
        for v in pair.findall("verify"):
            tool, op = v.get("tool") or "", v.get("op") or "eq"
            if not tool or not v.get("check") or op not in OPS:
                raise XmlEvalError(f"{where}: a verify needs tool, check and an op in {sorted(OPS)}")
            args = _args(v.get("args", "{}"), where)
            check = Check(v.get("check"), op, _value(v.get("value"), where))
            if steps and steps[-1].tool == tool and steps[-1].args == args:
                steps[-1] = Step(tool, args, (*steps[-1].checks, check))
            else:
                steps.append(Step(tool, args, (check,)))
        if not steps:
            raise XmlEvalError(f"{where}: no <verify>")
        out.append(Scenario(id=pid, question=question, steps=tuple(steps), answer=(answer_pattern(answer),),
                            reference_answer=answer, max_calls=max(MAX_CALLS, len(steps)), max_tokens=MAX_TOKENS))
    if not out:
        raise XmlEvalError("no <qa_pair> in the file")
    return out
