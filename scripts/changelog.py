"""CHANGELOG fragments: one file per pull request in changelog.d/, assembled at release.

    python scripts/changelog.py --check                 # fragment names and format, Unreleased left empty
    python scripts/changelog.py --check --base origin/main
                                                        # ... and a fragment exists when src/ changed
    python scripts/changelog.py --preview               # print the section the next release would get
    python scripts/changelog.py --release 0.3.0 [--date 2026-11-30]
                                                        # move every fragment into CHANGELOG.md, delete them

A fragment is ``changelog.d/<topic>.<section>.md`` where section is one of added, changed,
deprecated, removed, fixed or security (the Keep a Changelog headings), holding one or more
Markdown bullets ("- ..."). Every pull request writes its own file, so no two pull requests
edit the same lines of CHANGELOG.md; only the release commit does.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRAGMENTS = ROOT / "changelog.d"
CHANGELOG = ROOT / "CHANGELOG.md"
SECTIONS = ("added", "changed", "deprecated", "removed", "fixed", "security")
NAME = re.compile(r"^(?P<topic>[a-z0-9][a-z0-9._-]*)\.(?P<section>[a-z]+)\.md$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.]+)?$")
NOT_FRAGMENTS = {"README.md", ".gitkeep"}
UNRELEASED = "## Unreleased"
POINTER = ("Changes merged since the last release are fragments in "
           "[changelog.d/](https://github.com/Kx96xx/tshark-mcp/tree/main/changelog.d); "
           "`python scripts/changelog.py --release X.Y.Z` moves them here.")
# Paths whose change needs a fragment: what users install and run.
NEEDS_FRAGMENT = ("src/",)


@dataclass(frozen=True)
class Fragment:
    path: Path
    topic: str
    section: str
    text: str


def fragments(directory: Path = FRAGMENTS) -> tuple[list[Fragment], list[str]]:
    """Every fragment in section order, then topic; and the problems found on the way."""
    found: list[Fragment] = []
    problems: list[str] = []
    if not directory.is_dir():
        return found, problems
    for path in sorted(directory.iterdir()):
        if path.name in NOT_FRAGMENTS or path.is_dir():
            continue
        m = NAME.match(path.name)
        if not m:
            problems.append(f"{path.name}: name must be <topic>.<section>.md, e.g. fix-dns-pairing.fixed.md")
            continue
        if m["section"] not in SECTIONS:
            problems.append(f"{path.name}: section {m['section']!r} is not one of {', '.join(SECTIONS)}")
            continue
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            problems.append(f"{path.name}: empty")
            continue
        if not text.startswith("- "):
            problems.append(f"{path.name}: must be Markdown bullets, each starting with '- '")
            continue
        if re.search(r"^#", text, re.M):
            problems.append(f"{path.name}: no headings; the release script writes them")
            continue
        found.append(Fragment(path, m["topic"], m["section"], text))
    found.sort(key=lambda f: (SECTIONS.index(f.section), f.topic))
    return found, problems


def render(found: list[Fragment]) -> str:
    """The ``### Added`` ... blocks of one release, in Keep a Changelog order."""
    out: list[str] = []
    for section in SECTIONS:
        items = [f.text for f in found if f.section == section]
        if items:
            out += [f"### {section.capitalize()}", "", *items, ""]
    return "\n".join(out)


def unreleased_problems(text: str) -> list[str]:
    """CHANGELOG.md's Unreleased section holds only the pointer to changelog.d/."""
    lines = text.splitlines()
    if UNRELEASED not in lines:
        return [f"CHANGELOG.md has no '{UNRELEASED}' heading"]
    start = lines.index(UNRELEASED) + 1
    body = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        body.append(line)
    content = [ln for ln in body if ln.strip() and ln.strip() != POINTER]
    if content:
        return ["CHANGELOG.md: write the entry as a fragment in changelog.d/ instead of under "
                f"'{UNRELEASED}' (found: {content[0][:80]!r})"]
    return []


def release(version: str, date: str, changelog: Path = CHANGELOG, directory: Path = FRAGMENTS) -> str:
    """Insert the ``## <version> - <date>`` section after Unreleased and delete the fragments."""
    if not VERSION.match(version):
        raise SystemExit(f"not a version: {version!r}")
    found, problems = fragments(directory)
    if problems:
        raise SystemExit("\n".join(problems))
    if not found:
        raise SystemExit("no fragments in changelog.d/: nothing to release")
    text = changelog.read_text(encoding="utf-8")
    if re.search(rf"^## {re.escape(version)}\b", text, re.M):
        raise SystemExit(f"CHANGELOG.md already has a {version} section")
    lines = text.splitlines()
    if UNRELEASED not in lines:
        raise SystemExit(f"CHANGELOG.md has no '{UNRELEASED}' heading")
    at = lines.index(UNRELEASED) + 1
    while at < len(lines) and not lines[at].startswith("## "):
        at += 1
    section = [f"## {version} - {date}", "", *render(found).splitlines(), ""]
    body = lines[:lines.index(UNRELEASED) + 1] + ["", POINTER, ""] + section + lines[at:]
    changelog.write_text("\n".join(body).rstrip("\n") + "\n", encoding="utf-8")
    for f in found:
        f.path.unlink()
    return "\n".join(section)


def changed_files(base: str, cwd: Path = ROOT) -> list[tuple[str, str]]:
    """(status, path) of every file this branch changed since it left ``base``."""
    out = subprocess.run(["git", "-C", str(cwd), "diff", "--name-status", "--no-renames", f"{base}...HEAD"],
                         check=True, capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        status, _, path = line.partition("\t")
        rows.append((status[:1], path))
    return rows


def missing_fragment(changes: list[tuple[str, str]]) -> str | None:
    """Why the branch needs a fragment it does not have, or None."""
    touched = sorted(p for _, p in changes if p.startswith(NEEDS_FRAGMENT))
    if not touched:
        return None
    added = [p for s, p in changes if p.startswith("changelog.d/") and s in "AM"
             and Path(p).name not in NOT_FRAGMENTS]
    if added:
        return None
    return (f"{len(touched)} file(s) under {', '.join(NEEDS_FRAGMENT)} changed ({touched[0]}, ...) but no fragment "
            "was added: write changelog.d/<topic>.<section>.md (see changelog.d/README.md), or label "
            "the pull request no-changelog if users cannot see the change")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="validate fragments and the Unreleased section")
    g.add_argument("--preview", action="store_true", help="print the next release's section")
    g.add_argument("--release", metavar="VERSION", help="assemble the fragments into CHANGELOG.md")
    p.add_argument("--base", help="with --check: also require a fragment when src/ changed since this ref")
    p.add_argument("--date", default=dt.date.today().isoformat(), help="with --release (default: today)")
    args = p.parse_args(argv)

    if args.release:
        print(release(args.release, args.date))
        return 0
    found, problems = fragments()
    if args.preview:
        print(render(found) if found else "(no fragments)")
        return 1 if problems else 0
    problems += unreleased_problems(CHANGELOG.read_text(encoding="utf-8"))
    if args.base:
        why = missing_fragment(changed_files(args.base))
        if why:
            problems.append(why)
    for problem in problems:
        print(f"changelog: {problem}", file=sys.stderr)
    if not problems:
        print(f"changelog: {len(found)} fragment(s) OK")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
