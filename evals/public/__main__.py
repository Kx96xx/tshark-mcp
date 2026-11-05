"""Re-run the public-capture validation (opt-in; not part of CI).

    python -m evals.public --dir ~/pubcaps --fetch           # download what is missing, verify SHA-256, run
    python -m evals.public --dir ~/pubcaps                   # run on captures already there (verified first)
    python -m evals.public --dir ~/pubcaps --report docs/VALIDATION.md   # rewrite the results table

The captures are public samples under GPL or LGPL (Wireshark wiki and test captures, nDPI): they
are downloaded by URL into --dir and checked against the SHA-256 in captures.json, never
committed to this repository. A file whose hash differs is refused, so a changed upstream sample
cannot silently change the result. Each scenario replays the call that showed one validation
defect and checks the facts the fixed tool must report (see docs/VALIDATION.md).
"""

from __future__ import annotations

import argparse
import asyncio
import gzip
import hashlib
import json
import re
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from ..harness import CaseResult, run_all
from .scenarios import DEFECTS, SCENARIOS, TEXT_CHECKS

MANIFEST = Path(__file__).with_name("captures.json")
REPORT_BEGIN = "<!-- public-validation:begin -->"
REPORT_END = "<!-- public-validation:end -->"
MAX_BYTES = 50 * 1024 * 1024  # every sample used here is well under this


def manifest() -> list[dict[str, Any]]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["captures"]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(entry: dict[str, Any], directory: Path) -> Path:
    """Download one capture (gunzipped when the URL is a .gz) into ``directory/<file>`` and verify it.
    Only https URLs are followed; the download is size-capped and written to a temporary file first."""
    target = directory / entry["file"]
    if target.exists():
        return verify(entry, target)
    if not entry["url"].startswith("https://"):
        raise ValueError(f"{entry['file']}: refusing a non-https URL")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
        with urllib.request.urlopen(entry["url"], timeout=60) as resp:  # noqa: S310 (https only, checked above)
            data = resp.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError(f"{entry['file']}: larger than {MAX_BYTES} bytes")
        tmp.write(gzip.decompress(data) if entry.get("gunzip") else data)
    tmp_path = Path(tmp.name)
    try:
        verify(entry, tmp_path)
    except ValueError:
        tmp_path.unlink(missing_ok=True)
        raise
    shutil.move(str(tmp_path), target)
    return target


def verify(entry: dict[str, Any], path: Path) -> Path:
    got = sha256(path)
    if got != entry["sha256"]:
        raise ValueError(f"{entry['file']}: SHA-256 {got} differs from captures.json ({entry['sha256']}); "
                         "the upstream sample changed, refusing it")
    return path


def text_failures(result: CaseResult) -> list[str]:
    must, must_not = TEXT_CHECKS.get(result.id, ((), ()))
    text = json.dumps([c.result for c in result.calls], default=str)
    out = [f"text lacks /{p}/" for p in must if not re.search(p, text)]
    out += [f"text holds /{p}/" for p in must_not if re.search(p, text)]
    return out


def table(results: list[CaseResult]) -> str:
    by_id = {s.id: s for s in SCENARIOS}
    lines = ["| Defect | Check | Result | Calls |", "| --- | --- | --- | --- |"]
    for r in results:
        verdict = "pass" if r.passed else "FAIL: " + "; ".join(r.failures)[:200].replace("|", "/")
        lines.append(f"| {DEFECTS[r.id]} | {by_id[r.id].question} | {verdict} | "
                     f"{', '.join(sorted({c.tool for c in r.calls}))} |")
    passed = sum(1 for r in results if r.passed)
    lines.append("")
    lines.append(f"{passed} of {len(results)} checks pass.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m evals.public", description=__doc__.splitlines()[0])
    p.add_argument("--dir", type=Path, required=True, help="where the public captures are (or are downloaded to)")
    p.add_argument("--fetch", action="store_true", help="download the captures that are missing (network)")
    p.add_argument("--only", action="append", default=[], metavar="ID", help="run only these scenario ids")
    p.add_argument("--report", type=Path, default=None, help="rewrite the table between the markers in this file")
    p.add_argument("--json", type=Path, default=None, help="write per-scenario results as JSON")
    args = p.parse_args(argv)

    directory = args.dir.expanduser().resolve()
    for entry in manifest():
        path = directory / entry["file"]
        if args.fetch:
            fetch(entry, directory)
        elif not path.exists():
            p.error(f"{path} is missing: run with --fetch, or place the file there")
        else:
            verify(entry, path)
    scenarios = [s for s in SCENARIOS if not args.only or s.id in args.only]
    results = asyncio.run(run_all(scenarios, captures=str(directory)))
    for r in results:
        extra = text_failures(r)
        if extra:
            r.failures.extend(extra)
            r.passed = False
    for r in results:
        print(f"{'PASS' if r.passed else 'FAIL'} {r.id}" + ("" if r.passed else f": {'; '.join(r.failures)}"))
    if args.json:
        args.json.write_text(json.dumps([r.row() for r in results], indent=1), encoding="utf-8")
    if args.report:
        text = args.report.read_text(encoding="utf-8")
        start, end = text.index(REPORT_BEGIN) + len(REPORT_BEGIN), text.index(REPORT_END)
        args.report.write_text(text[:start] + "\n" + table(results) + text[end:], encoding="utf-8")
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
