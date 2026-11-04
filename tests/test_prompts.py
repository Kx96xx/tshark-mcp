"""Prompts (guided workflows) and path completion, in process and through the MCP stdio client."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import PromptReference

from tshark_mcp import prompts
from tshark_mcp.limits import Allowlist
from tshark_mcp.search import CAPTURE_SUFFIXES

from .conftest import TSHARK, requires_tshark

EXPECTED_PROMPTS = {"one_way_audio", "subscriber_cannot_attach", "trust_this_capture", "working_vs_failing",
                    "ims_registration_or_sms", "slow_data_session"}


@pytest.fixture
def tree(tmp_path: Path) -> tuple[Path, Path]:
    """An allowed directory with captures, a subdirectory, a hidden file, a text file and a
    symlink pointing outside, plus a directory outside the allowlist."""
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    (allowed / "day1").mkdir(parents=True)
    outside.mkdir()
    for name in ("attach_fail.pcap", "attach_ok.pcapng", "voice.cap", "notes.txt", ".hidden.pcap"):
        (allowed / name).write_bytes(b"")
    (allowed / "day1" / "a.pcap").write_bytes(b"")
    (outside / "secret.pcap").write_bytes(b"")
    (allowed / "link.pcap").symlink_to(outside / "secret.pcap")
    (allowed / "linkdir").symlink_to(outside)
    return allowed.resolve(), outside.resolve()


def _complete(allowed: Path, partial: str) -> tuple[list[str], bool]:
    return prompts.complete_path(Allowlist((allowed,)), partial, CAPTURE_SUFFIXES)


def test_completion_lists_captures_and_directories_only(tree):
    allowed, _ = tree
    values, more = _complete(allowed, "")
    assert values == [f"{allowed}/attach_fail.pcap", f"{allowed}/attach_ok.pcapng", f"{allowed}/day1/",
                      f"{allowed}/voice.cap"]
    assert more is False


def test_completion_by_prefix_absolute_and_relative(tree):
    allowed, _ = tree
    assert _complete(allowed, "attach") == ([f"{allowed}/attach_fail.pcap", f"{allowed}/attach_ok.pcapng"], False)
    assert _complete(allowed, f"{allowed}/day1/") == ([f"{allowed}/day1/a.pcap"], False)
    assert _complete(allowed, f"{allowed}/v") == ([f"{allowed}/voice.cap"], False)


def test_completion_never_leaves_the_allowlist(tree):
    allowed, outside = tree
    assert _complete(allowed, f"{outside}/") == ([], False)
    assert _complete(allowed, f"{allowed}/../outside/") == ([], False)
    assert _complete(allowed, "/etc/") == ([], False)
    everything, _ = _complete(allowed, "")
    assert not any("link" in v or "secret" in v or "hidden" in v or "notes" in v for v in everything)
    assert _complete(allowed, f"{allowed}/linkdir/") == ([], False)


def test_completion_above_the_allowed_directory_offers_the_root(tree):
    allowed, _ = tree
    assert _complete(allowed, str(allowed)[:5]) == ([f"{allowed}/"], False)


def test_completion_is_bounded(tmp_path: Path):
    for i in range(prompts.MAX_COMPLETIONS + 7):
        (tmp_path / f"c{i:03d}.pcap").write_bytes(b"")
    values, more = prompts.complete_path(Allowlist((tmp_path.resolve(),)), "c", CAPTURE_SUFFIXES)
    assert len(values) == prompts.MAX_COMPLETIONS and more is True


def test_completion_refuses_odd_input(tree):
    allowed, _ = tree
    assert _complete(allowed, "a\x00b") == ([], False)
    assert _complete(allowed, "/" + "a" * 5000) == ([], False)
    assert prompts.complete_path(None, "", CAPTURE_SUFFIXES) == ([], False)


def test_prompt_arguments_are_bounded_in_the_text():
    text = prompts.trust_this_capture("/p/" + "x" * 5000)
    assert "x" * 600 not in text and "x" * 500 in text


def test_each_prompt_names_its_tools_and_answer_shape():
    for name, (_, fn) in prompts.PROMPTS.items():
        args = {"path_a": "/a.pcap", "path_b": "/b.pcap"} if name == "working_vs_failing" else {"path": "/a.pcap"}
        text = fn(**args)
        assert len(prompts.tools_named(text)) >= 3, name
        assert "frame" in text and "verdict" in text and "near_capture_end" in text, name


# ------------------------------------------------------------------ through the MCP stdio client
async def _client(allowed: Path) -> dict[str, Any]:
    env = dict(os.environ)
    env["TSHARK_MCP_TSHARK"] = TSHARK
    params = StdioServerParameters(command=sys.executable, args=["-m", "tshark_mcp.server", "--allow-dir", str(allowed)],
                                   env=env)
    out: dict[str, Any] = {}
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            out["capabilities"] = init.capabilities
            out["tools"] = {t.name for t in (await session.list_tools()).tools}
            out["prompts"] = {p.name: p for p in (await session.list_prompts()).prompts}
            out["texts"] = {}
            for name in out["prompts"]:
                args = ({"path_a": f"{allowed}/attach_ok.pcapng", "path_b": f"{allowed}/attach_fail.pcap"}
                        if name == "working_vs_failing" else {"path": f"{allowed}/attach_fail.pcap"})
                got = await session.get_prompt(name, args)
                out["texts"][name] = "\n".join(m.content.text for m in got.messages)
            out["complete"] = await session.complete(PromptReference(type="ref/prompt", name="one_way_audio"),
                                                     {"name": "path", "value": "attach"})
            out["complete_other"] = await session.complete(PromptReference(type="ref/prompt", name="one_way_audio"),
                                                           {"name": "call_id", "value": "a"})
    return out


@requires_tshark
def test_prompts_and_completion_over_stdio(tree):
    allowed, _ = tree
    out = asyncio.run(_client(allowed))
    assert out["capabilities"].prompts is not None and out["capabilities"].completions is not None
    assert set(out["prompts"]) == EXPECTED_PROMPTS
    for name, prompt in out["prompts"].items():
        assert prompt.description and prompt.title, name
        required = {a.name for a in prompt.arguments if a.required}
        assert required == ({"path_a", "path_b"} if name == "working_vs_failing" else {"path"}), name
    for name, text in out["texts"].items():
        assert str(allowed) in text, name
        unknown = prompts.tools_named(text) - out["tools"]
        assert not unknown, (name, unknown)  # every tool a prompt names exists in tools/list
    completion = out["complete"].completion
    assert completion.values == [f"{allowed}/attach_fail.pcap", f"{allowed}/attach_ok.pcapng"]
    assert out["complete_other"].completion.values == []
