"""The MCPB desktop bundle: the manifest is current, the host's argument expansion reaches the
server as one --allow-dir per directory, and (where uv is installed, as in the CI mcpb job)
the built bundle starts over stdio and answers."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import shutil
from pathlib import Path

import pytest

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from . import pcapgen
from .conftest import TSHARK, requires_tshark
from .test_mcp_client import EXPECTED_TOOLS

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = json.loads((ROOT / "mcpb" / "manifest.json").read_text(encoding="utf-8"))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = _load("mcpb_build", ROOT / "mcpb" / "build.py")
entry = _load("mcpb_entry", ROOT / "mcpb" / "server" / "main.py")


def test_manifest_is_current() -> None:
    """Version from __version__, one entry per registered tool: `python mcpb/build.py --update`."""
    assert build.main(["--check"]) == 0
    assert {t["name"] for t in MANIFEST["tools"]} == EXPECTED_TOOLS
    assert all(t["description"].endswith(".") and len(t["description"]) <= 300 for t in MANIFEST["tools"])


def test_manifest_shape() -> None:
    assert MANIFEST["server"]["type"] == "uv" and MANIFEST["server"]["entry_point"] == "server/main.py"
    dirs = MANIFEST["user_config"]["allow_dirs"]
    assert dirs["type"] == "directory" and dirs["multiple"] is True and dirs["required"] is True
    assert MANIFEST["user_config"]["redact"]["default"] == "off"
    assert MANIFEST["compatibility"]["runtimes"]["python"] == ">=3.10"
    assert (ROOT / "mcpb" / "server" / "main.py").is_file()


def _expand(args: list[str], dirname: str, dirs: list[str], redact: str = "off") -> list[str]:
    """What the host does: substitute ${__dirname} and settings, one argument per directory."""
    out: list[str] = []
    for a in args:
        if a == "${user_config.allow_dirs}":
            out += dirs
        else:
            out.append(a.replace("${__dirname}", dirname).replace("${user_config.redact}", redact))
    return out


def test_host_expansion_reaches_the_server_as_allow_dirs() -> None:
    args = _expand(MANIFEST["server"]["mcp_config"]["args"], "/b", ["/p one", "/p2"], "ids")
    assert args[:4] == ["run", "--directory", "/b", "server/main.py"]
    assert entry.server_argv(args[4:]) == ["--redact", "ids", "--allow-dir", "/p one", "--allow-dir", "/p2"]
    assert entry.server_argv(["--redact", "off", "--", "", "/x"]) == ["--redact", "off", "--allow-dir", "/x"]
    assert entry.server_argv([]) == []


def test_server_refuses_to_start_without_a_directory() -> None:
    try:
        code = entry.main(entry.server_argv(["--redact", "off", "--"]))
    except SystemExit as exc:
        code = exc.code
    assert code not in (0, None)


def test_build_copies_only_the_package(tmp_path: Path) -> None:
    out = build.build(tmp_path / "bundle")
    names = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}
    assert {"manifest.json", "server/main.py", "pyproject.toml", "README.md", "LICENSE",
            "src/tshark_mcp/server.py"} <= names
    assert not any(n.startswith(("tests/", "evals/", "examples/")) or "__pycache__" in n for n in names)


def test_find_tshark_falls_back_to_the_wireshark_app(monkeypatch) -> None:
    """Claude Desktop has no Homebrew PATH; the macOS app bundle's tshark is found anyway."""
    from tshark_mcp import runner

    app = "/Applications/Wireshark.app/Contents/MacOS/tshark"
    monkeypatch.delenv("TSHARK_MCP_TSHARK", raising=False)
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    monkeypatch.setattr(runner.os, "access", lambda path, mode: path == app)
    assert runner.find_tshark() == app


UV = shutil.which("uv")


@requires_tshark
@pytest.mark.skipif(not UV or not os.environ.get("TSHARK_MCP_TEST_BUNDLE"),
                    reason="needs uv and TSHARK_MCP_TEST_BUNDLE=1 (the CI mcpb job): uv run resolves dependencies")
def test_built_bundle_answers_over_stdio(tmp_path: Path) -> None:
    out = build.build(tmp_path / "bundle")
    captures = tmp_path / "captures"
    pcapgen.write_all(captures)
    args = _expand(MANIFEST["server"]["mcp_config"]["args"], str(out), [str(captures)])
    env = dict(os.environ, TSHARK_MCP_TSHARK=TSHARK)
    params = StdioServerParameters(command=UV, args=args, env=env)

    async def run():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = {t.name for t in (await session.list_tools()).tools}
                info = await session.call_tool("pcap_info", {"path": str(captures / "diameter.pcap")})
                return names, info

    names, info = asyncio.run(asyncio.wait_for(run(), 300))
    assert names == EXPECTED_TOOLS
    data = getattr(info, "structured_content", None) or getattr(info, "structuredContent", None)
    assert data["packets"] == 7
