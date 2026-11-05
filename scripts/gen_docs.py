"""Generate the tool tables, tool lists and tool counts from the server's tool registry.

    python scripts/gen_docs.py            # rewrite every generated block and the MCPB manifest
    python scripts/gen_docs.py --check    # exit 1 if a committed copy differs (CI runs this)

The tool set and the signatures come from ``tshark_mcp.server.TOOLS`` (every tool the server
registers, including the modules of src/tshark_mcp/tools/). The words come from one file per
tool, ``docs/tools/<name>.md`` (format in docs/tools/README.md). Generated regions:

- ``<!-- BEGIN GENERATED: <block> ... -->`` ... ``<!-- END GENERATED: <block> -->``:
  the README tool table, the docs/TOOLS.md reference table and the llms.txt tool list;
- ``<!-- tool-count -->Fifty-five<!-- /tool-count -->``: the spelled-out number of tools
  (README.md, AGENTS.md, llms.txt);
- ``mcpb/manifest.json``: version and tools list (as ``python mcpb/build.py --update``).

After a rebase that conflicts inside a generated region, take either side and run this script.
"""

from __future__ import annotations

import argparse
import difflib
import importlib.util
import inspect
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL_DOCS = ROOT / "docs" / "tools"
KEYS = ("order", "readme", "llms")

BEGIN = "<!-- BEGIN GENERATED: {block} (python scripts/gen_docs.py; edit docs/tools/<name>.md, not here) -->"
END = "<!-- END GENERATED: {block} -->"
COUNT = re.compile(r"(<!-- tool-count -->)([^<]*)(<!-- /tool-count -->)")

# file -> generated blocks it holds
BLOCKS = {
    "README.md": ("readme-tools",),
    "docs/TOOLS.md": ("tools-reference",),
    "llms.txt": ("llms-tools",),
}
COUNTED = ("README.md", "AGENTS.md", "llms.txt")

_ONES = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven",
         "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"]
_TENS = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]


def spelled(n: int) -> str:
    """55 -> "fifty-five"; 100 and more stay digits."""
    if n < 20:
        return _ONES[n]
    if n < 100:
        tens, ones = divmod(n, 10)
        return _TENS[tens] + (f"-{_ONES[ones]}" if ones else "")
    return str(n)


@dataclass(frozen=True)
class ToolDoc:
    name: str
    order: int
    readme: str
    llms: str
    reference: str


def parse_doc(path: Path) -> ToolDoc:
    """``---`` front matter (order, readme, llms: one line each), a blank line, then the
    reference text (wrapped lines are joined with one space)."""
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if not m:
        raise ValueError(f"{path.name}: must start with a --- front matter block")
    meta: dict[str, str] = {}
    for line in m[1].splitlines():
        key, sep, value = line.partition(": ")
        if not sep or key not in KEYS:
            raise ValueError(f"{path.name}: front matter line {line!r}: keys are {', '.join(KEYS)}")
        if key in meta:
            raise ValueError(f"{path.name}: {key} given twice")
        meta[key] = value.strip()
    missing = [k for k in KEYS if not meta.get(k)]
    if missing:
        raise ValueError(f"{path.name}: missing {', '.join(missing)}")
    if not meta["order"].isdigit():
        raise ValueError(f"{path.name}: order must be a whole number")
    reference = " ".join(m[2].split())
    if not reference:
        raise ValueError(f"{path.name}: no reference text after the front matter")
    for key, value in (("readme", meta["readme"]), ("reference", reference)):
        if re.search(r"(?<!\\)\|", value):
            raise ValueError(f"{path.name}: {key} has an unescaped | (write \\|)")
    return ToolDoc(path.stem, int(meta["order"]), meta["readme"], meta["llms"], reference)


def registry() -> dict:
    sys.path.insert(0, str(ROOT / "src"))
    from tshark_mcp import server  # noqa: PLC0415
    return server.TOOLS


def load_docs(tools: dict, directory: Path = TOOL_DOCS) -> list[ToolDoc]:
    """One doc per registered tool, in README order (``order``, then name)."""
    files = {p.stem: p for p in directory.glob("*.md") if p.name != "README.md"}
    problems = []
    for name in tools:
        if name not in files:
            problems.append(f"tool {name} has no docs/tools/{name}.md (copy another one and edit it)")
    for name in files:
        if name not in tools:
            problems.append(f"docs/tools/{name}.md: no registered tool {name} (renamed or removed?)")
    docs = []
    for name in tools:
        if name in files:
            try:
                docs.append(parse_doc(files[name]))
            except ValueError as exc:
                problems.append(str(exc))
    if problems:
        raise SystemExit("\n".join(problems))
    return sorted(docs, key=lambda d: (d.order, d.name))


def signature(fn, defaults: bool) -> str:
    """The tool's own arguments (not the redact/window/output ones every tool gets)."""
    out = []
    for p in inspect.signature(inspect.unwrap(fn)).parameters.values():
        if not defaults or p.default is inspect.Parameter.empty:
            out.append(p.name)
        else:
            d = p.default
            out.append(f'{p.name}="{d}"' if isinstance(d, str) else f"{p.name}={d!r}")
    return ", ".join(out)


def render_blocks(tools: dict, docs: list[ToolDoc]) -> dict[str, list[str]]:
    return {
        "readme-tools": ["| Tool | One line |", "| --- | --- |",
                         *(f"| `{d.name}` | {d.readme} |" for d in docs)],
        "tools-reference": ["| Tool | What it returns |", "| --- | --- |",
                            *(f"| `{d.name}({signature(tools[d.name], False)})` | {d.reference} |" for d in docs)],
        "llms-tools": [f"- `{d.name}({signature(tools[d.name], True)})`: {d.llms}" for d in docs],
    }


def apply(text: str, blocks: dict[str, list[str]], names: tuple[str, ...], count: int | None, where: str) -> str:
    for block in names:
        begin, end = BEGIN.format(block=block), END.format(block=block)
        if text.count(begin) != 1 or text.count(end) != 1:
            raise SystemExit(f"{where}: needs exactly one {begin!r} and one {end!r} line")
        head, rest = text.split(begin, 1)
        _, tail = rest.split(end, 1)
        text = head + begin + "\n\n" + "\n".join(blocks[block]) + "\n\n" + end + tail
    if count is not None:
        if not COUNT.search(text):
            raise SystemExit(f"{where}: no <!-- tool-count --> marker")

        def word(m: re.Match) -> str:
            w = spelled(count)
            return m[1] + (w[:1].upper() + w[1:] if m[2][:1].isupper() else w) + m[3]
        text = COUNT.sub(word, text)
    return text


def mcpb_manifest() -> tuple[Path, str]:
    spec = importlib.util.spec_from_file_location("mcpb_build", ROOT / "mcpb" / "build.py")
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    return build.MANIFEST, json.dumps(build.expected_manifest(), indent=2) + "\n"


def expected(root: Path = ROOT) -> dict[Path, str]:
    """Every generated file with the content it should have."""
    tools = registry()
    docs = load_docs(tools)
    blocks = render_blocks(tools, docs)
    out: dict[Path, str] = {}
    for rel in sorted(set(BLOCKS) | set(COUNTED)):
        path = root / rel
        out[path] = apply(path.read_text(encoding="utf-8"), blocks, BLOCKS.get(rel, ()),
                          len(tools) if rel in COUNTED else None, rel)
    manifest, text = mcpb_manifest()
    out[manifest] = text
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--check", action="store_true", help="exit 1 if a generated copy is stale; write nothing")
    args = p.parse_args(argv)
    stale = []
    for path, want in expected().items():
        have = path.read_text(encoding="utf-8")
        if have == want:
            continue
        stale.append(path)
        if args.check:
            rel = str(path.relative_to(ROOT))
            sys.stderr.writelines(list(difflib.unified_diff(have.splitlines(True), want.splitlines(True),
                                                            f"{rel} (committed)", f"{rel} (generated)", n=1))[:40])
        else:
            path.write_text(want, encoding="utf-8")
    names = ", ".join(str(p.relative_to(ROOT)) for p in stale)
    if args.check and stale:
        print(f"gen_docs: stale: {names}. Run python scripts/gen_docs.py and commit the result.", file=sys.stderr)
        return 1
    print(f"gen_docs: {'updated ' + names if stale else 'everything current'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
