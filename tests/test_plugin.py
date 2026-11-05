"""The Claude Code plugin (plugin/) and its marketplace entry (.claude-plugin/marketplace.json):
the manifests agree with the package, every MCP prompt has a skill, every tool a skill names
exists, the plugin's server arguments start the real server over stdio, and (where the
`claude` CLI is installed, as in the CI plugin job) `claude plugin validate` passes."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from tshark_mcp import __version__
from tshark_mcp.prompts import PROMPTS, tools_named

from . import pcapgen
from .conftest import TSHARK, requires_tshark
from .test_mcp_client import EXPECTED_TOOLS

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugin"
MANIFEST = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
MARKET = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
SKILLS = {p.parent.name: p.read_text(encoding="utf-8") for p in sorted((PLUGIN / "skills").glob("*/SKILL.md"))}
SERVER = MANIFEST["mcpServers"]["tshark-mcp"]


def _frontmatter(text: str) -> dict[str, str]:
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert m, "SKILL.md must start with a --- frontmatter block"
    return dict(line.split(": ", 1) for line in m.group(1).splitlines())


def test_manifest_and_marketplace_agree_with_the_package() -> None:
    assert MANIFEST["name"] == "tshark-mcp" and MANIFEST["version"] == __version__
    [entry] = MARKET["plugins"]
    assert entry["name"] == MANIFEST["name"] and (ROOT / entry["source"] / ".claude-plugin" / "plugin.json").is_file()
    assert entry["source"] == "./plugin"


def test_every_prompt_has_a_skill_and_every_skill_is_well_formed() -> None:
    assert {name.replace("_", "-") for name in PROMPTS} <= set(SKILLS)
    for name, text in SKILLS.items():
        meta = _frontmatter(text)
        assert meta["name"] == name and 0 < len(meta["description"]) <= 1024, name
        prompt = name.replace("-", "_")
        if prompt in PROMPTS:
            assert f"`{prompt}` prompt" in text, f"{name} should point at the server's {prompt} prompt"


def test_every_tool_a_skill_names_exists() -> None:
    for name, text in SKILLS.items():
        named = tools_named(text)
        assert named and named <= EXPECTED_TOOLS, (name, named - EXPECTED_TOOLS)


def test_server_config_uses_only_declared_settings() -> None:
    refs = set(re.findall(r"\$\{user_config\.(\w+)\}", json.dumps(SERVER)))
    assert refs == set(MANIFEST["userConfig"])
    assert MANIFEST["userConfig"]["capture_dir"] == {**MANIFEST["userConfig"]["capture_dir"], "type": "directory", "required": True}
    assert MANIFEST["userConfig"]["redact"]["options"] == ["off", "ids", "ids+ips"]
    # The released package from PyPI (not the main branch), at least the first release with the plugin.
    assert SERVER["command"] == "uvx" and SERVER["args"][:3] == ["--from", "tshark-mcp-server>=0.2.0", "tshark-mcp"]


@requires_tshark
def test_plugin_server_arguments_start_the_server(tmp_path: Path) -> None:
    """The arguments after `tshark-mcp`, with the settings filled in, against the real server."""
    captures = tmp_path / "captures"
    pcapgen.write_all(captures)
    args = [a.replace("${user_config.capture_dir}", str(captures)).replace("${user_config.redact}", "ids")
            for a in SERVER["args"][3:]]
    params = StdioServerParameters(command=sys.executable, args=["-m", "tshark_mcp.server", *args],
                                   env=dict(os.environ, TSHARK_MCP_TSHARK=TSHARK))

    async def run():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = {t.name for t in (await session.list_tools()).tools}
                prompts = {p.name for p in (await session.list_prompts()).prompts}
                info = await session.call_tool("trace_subscriber", {"path": str(captures / "diameter.pcap"),
                                                                     "imsi": pcapgen.IMSI})
                return tools, prompts, info

    tools, prompts, info = asyncio.run(run())
    assert tools == EXPECTED_TOOLS and prompts == set(PROMPTS)
    data = getattr(info, "structured_content", None) or getattr(info, "structuredContent", None)
    assert data["identity"]["imsi"].startswith("imsi:")  # redact=ids from the plugin settings


CLAUDE = shutil.which("claude")


@pytest.mark.skipif(not CLAUDE, reason="needs the claude CLI (the CI plugin job installs it)")
@pytest.mark.parametrize("target", ["plugin", "."])
def test_claude_plugin_validate(target: str) -> None:
    out = subprocess.run([CLAUDE, "plugin", "validate", str(ROOT / target)], capture_output=True, text=True,
                         timeout=120, env=dict(os.environ, NO_COLOR="1"))
    assert out.returncode == 0 and "Validation passed" in out.stdout, out.stdout + out.stderr
