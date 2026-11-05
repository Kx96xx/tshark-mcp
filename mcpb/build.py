"""Build the MCPB desktop bundle (Claude Desktop extension) of tshark-mcp.

    python mcpb/build.py                  # write build/mcpb/ (the bundle directory)
    python mcpb/build.py --check          # exit 1 if mcpb/manifest.json is out of date
    python mcpb/build.py --update         # rewrite the manifest's version and tools list
    npx -y @anthropic-ai/mcpb@2.1.2 pack build/mcpb build/tshark-mcp.mcpb

The bundle uses the ``uv`` server type: the host installs Python and the dependencies from
the bundled pyproject.toml, so nothing compiled is shipped. Its version and tools list come
from the package (``__version__`` and the server's own tool registry); ``--check`` (run by
tests/test_mcpb.py) fails when they drift.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "mcpb"
MANIFEST = HERE / "manifest.json"
SRC = ROOT / "src" / "tshark_mcp"


def tool_entries() -> list[dict[str, str]]:
    """Name and first sentence of every registered tool, in registration order."""
    sys.path.insert(0, str(ROOT / "src"))
    from tshark_mcp import server  # noqa: PLC0415

    out = []
    for tool in asyncio.run(server.app.list_tools()):
        text = " ".join((tool.description or "").split())
        first = re.split(r"(?<=\.)\s", text, maxsplit=1)[0].rstrip(".") + "."
        if len(first) > 300:
            first = first[:296].rsplit(" ", 1)[0] + " ..."
        out.append({"name": tool.name, "description": first})
    return out


def package_version() -> str:
    text = (SRC / "__init__.py").read_text(encoding="utf-8")
    return re.search(r'__version__ = "([^"]+)"', text).group(1)


def expected_manifest() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest["version"] = package_version()
    manifest["tools"] = tool_entries()
    return manifest


def build(out: Path) -> Path:
    if out.exists():
        shutil.rmtree(out)
    (out / "server").mkdir(parents=True)
    shutil.copy2(MANIFEST, out / "manifest.json")
    shutil.copy2(HERE / ".mcpbignore", out / ".mcpbignore")
    shutil.copy2(HERE / "server" / "main.py", out / "server" / "main.py")
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(ROOT / name, out / name)
    shutil.copytree(SRC, out / "src" / "tshark_mcp", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", type=Path, default=ROOT / "build" / "mcpb")
    p.add_argument("--check", action="store_true", help="exit 1 if the manifest's version or tools are stale")
    p.add_argument("--update", action="store_true", help="rewrite mcpb/manifest.json from the package")
    args = p.parse_args(argv)
    want = expected_manifest()
    have = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if args.update:
        MANIFEST.write_text(json.dumps(want, indent=2) + "\n", encoding="utf-8")
        return 0
    if have != want:
        stale = [k for k in want if have.get(k) != want[k]]
        print(f"mcpb/manifest.json is stale ({', '.join(stale)}): run python mcpb/build.py --update", file=sys.stderr)
        return 1
    if args.check:
        return 0
    print(build(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
