"""Generated docs (scripts/gen_docs.py): the committed README/TOOLS/llms tool tables, the
spelled-out tool counts and the MCPB manifest match the server's tool registry, and every
registered tool has its docs/tools/<name>.md."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from tshark_mcp import server

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("gen_docs_script", ROOT / "scripts" / "gen_docs.py")
gen = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = gen
_spec.loader.exec_module(gen)


def test_committed_copies_are_current():
    stale = [str(p.relative_to(ROOT)) for p, want in gen.expected().items() if p.read_text(encoding="utf-8") != want]
    assert not stale, f"run python scripts/gen_docs.py: stale {stale}"


def test_cli_check_passes():
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_docs.py"), "--check"],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


def test_every_tool_has_one_doc_and_appears_in_every_list():
    docs = gen.load_docs(server.TOOLS)
    assert sorted(d.name for d in docs) == sorted(server.tool_names())
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
    reference = (ROOT / "docs" / "TOOLS.md").read_text(encoding="utf-8")
    for name in server.tool_names():
        assert f"| `{name}` |" in readme, name
        assert f"- `{name}(" in llms, name
        assert f"| `{name}(" in reference, name
    count = gen.spelled(len(server.TOOLS))
    for rel in gen.COUNTED:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert f"<!-- tool-count -->{count[:1].upper() + count[1:]}<!-- /tool-count -->" in text, rel


@pytest.mark.parametrize(("n", "word"), [(7, "seven"), (19, "nineteen"), (20, "twenty"), (55, "fifty-five"),
                                         (56, "fifty-six"), (90, "ninety"), (99, "ninety-nine"), (120, "120")])
def test_spelled(n, word):
    assert gen.spelled(n) == word


def test_signatures_leave_out_the_arguments_every_tool_gets():
    sig = gen.signature(server.TOOLS["conversations"], defaults=True)
    assert sig == 'path, layer="ip", filter=None, limit=200, offset=0'
    assert gen.signature(server.TOOLS["conversations"], defaults=False) == "path, layer, filter, limit, offset"
    # capture_index keeps its own start/end (it takes no window): they are real arguments.
    assert "start" in gen.signature(server.TOOLS["capture_index"], defaults=False)


GOOD = "---\norder: 10\nreadme: One line.\nllms: what it does\n---\n\nReference text\nwrapped.\n"


def test_doc_parsing(tmp_path):
    p = tmp_path / "x.md"
    p.write_text(GOOD)
    d = gen.parse_doc(p)
    assert (d.name, d.order, d.readme, d.llms, d.reference) == ("x", 10, "One line.", "what it does",
                                                                "Reference text wrapped.")
    for bad, why in [(GOOD.replace("order: 10", "order: ten"), "whole number"),
                     (GOOD.replace("llms: what it does\n", ""), "missing llms"),
                     (GOOD.replace("readme:", "summary:"), "keys are"),
                     (GOOD.replace("One line.", "a | b"), "unescaped"),
                     ("no front matter\n", "front matter"),
                     (GOOD.split("---\n\n")[0] + "---\n\n\n", "no reference text")]:
        p.write_text(bad)
        with pytest.raises(ValueError, match=why):
            gen.parse_doc(p)


def test_missing_and_orphan_docs_are_named(tmp_path):
    (tmp_path / "pcap_info.md").write_text(GOOD)
    (tmp_path / "gone_tool.md").write_text(GOOD)
    with pytest.raises(SystemExit) as exc:
        gen.load_docs({"pcap_info": server.TOOLS["pcap_info"], "conversations": server.TOOLS["conversations"]},
                      tmp_path)
    assert "tool conversations has no docs/tools/conversations.md" in str(exc.value)
    assert "docs/tools/gone_tool.md: no registered tool" in str(exc.value)


def test_blocks_and_counts_are_rewritten_in_place():
    text = ("Intro <!-- tool-count -->Three<!-- /tool-count --> tools, <!-- tool-count -->three<!-- /tool-count -->.\n\n"
            + gen.BEGIN.format(block="llms-tools") + "\nold\n" + gen.END.format(block="llms-tools") + "\nafter\n")
    out = gen.apply(text, {"llms-tools": ["- `a()`: new"]}, ("llms-tools",), 56, "t")
    assert out.startswith("Intro <!-- tool-count -->Fifty-six<!-- /tool-count --> tools, "
                          "<!-- tool-count -->fifty-six<!-- /tool-count -->.")
    assert "\n\n- `a()`: new\n\n" + gen.END.format(block="llms-tools") + "\nafter\n" in out and "old" not in out
    assert gen.apply(out, {"llms-tools": ["- `a()`: new"]}, ("llms-tools",), 56, "t") == out
    with pytest.raises(SystemExit, match="needs exactly one"):
        gen.apply("nothing", {}, ("llms-tools",), None, "t")
