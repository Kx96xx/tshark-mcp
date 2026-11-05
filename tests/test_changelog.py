"""CHANGELOG fragments (scripts/changelog.py): the repository's fragments are valid, the
release step assembles them in Keep a Changelog order, and the pull-request check asks for a
fragment exactly when src/ changed."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("changelog_script", ROOT / "scripts" / "changelog.py")
changelog = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = changelog
_spec.loader.exec_module(changelog)

HEAD = """# Changelog

Intro.

## Unreleased

{pointer}

## 0.1.0 - 2026-01-01

### Added

- The first tool.
"""


def test_repository_fragments_and_unreleased_are_valid():
    found, problems = changelog.fragments()
    assert problems == []
    assert changelog.unreleased_problems(changelog.CHANGELOG.read_text(encoding="utf-8")) == []
    assert all(f.section in changelog.SECTIONS for f in found)


def test_cli_check_passes_on_the_repository():
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "changelog.py"), "--check"],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


def _setup(tmp_path: Path, files: dict[str, str]) -> tuple[Path, Path]:
    d = tmp_path / "changelog.d"
    d.mkdir()
    (d / "README.md").write_text("# not a fragment\n")
    for name, text in files.items():
        (d / name).write_text(text)
    log = tmp_path / "CHANGELOG.md"
    log.write_text(HEAD.format(pointer=changelog.POINTER))
    return d, log


def test_bad_fragments_are_named(tmp_path):
    d, _ = _setup(tmp_path, {"Bad Name.md": "- x\n", "x.misc.md": "- x\n", "e.fixed.md": "\n",
                             "p.added.md": "plain text\n", "h.added.md": "- x\n### Added\n"})
    found, problems = changelog.fragments(d)
    assert found == []
    assert len(problems) == 5
    assert any("Bad Name.md" in p and "<topic>.<section>.md" in p for p in problems)
    assert any("'misc' is not one of" in p for p in problems)


def test_release_assembles_in_section_order_and_deletes(tmp_path):
    d, log = _setup(tmp_path, {
        "zz-dns.fixed.md": "- dns fix.\n",
        "b-tool.added.md": "- tool b.\n  continued line.\n",
        "a-tool.added.md": "- tool a.\n",
        "sec.security.md": "- a cap.\n",
    })
    changelog.release("0.2.0", "2026-02-02", log, d)
    text = log.read_text()
    assert text.index("## Unreleased") < text.index(changelog.POINTER) < text.index("## 0.2.0 - 2026-02-02") \
        < text.index("## 0.1.0")
    new = text[text.index("## 0.2.0"):text.index("## 0.1.0")]
    assert new == ("## 0.2.0 - 2026-02-02\n\n### Added\n\n- tool a.\n- tool b.\n  continued line.\n\n"
                   "### Fixed\n\n- dns fix.\n\n### Security\n\n- a cap.\n\n")
    assert [p.name for p in d.iterdir()] == ["README.md"]
    assert changelog.unreleased_problems(text) == []
    with pytest.raises(SystemExit, match="nothing to release"):
        changelog.release("0.3.0", "2026-03-03", log, d)


def test_release_refuses_a_duplicate_version(tmp_path):
    d, log = _setup(tmp_path, {"a.added.md": "- a.\n"})
    with pytest.raises(SystemExit, match="already has a 0.1.0"):
        changelog.release("0.1.0", "2026-02-02", log, d)
    assert (d / "a.added.md").exists()


def test_entry_under_unreleased_is_refused():
    text = HEAD.format(pointer=changelog.POINTER + "\n\n### Added\n\n- written by hand")
    assert "write the entry as a fragment" in changelog.unreleased_problems(text)[0]


def test_missing_fragment_only_when_src_changes():
    assert changelog.missing_fragment([("M", "README.md"), ("M", "tests/test_x.py")]) is None
    assert "no fragment" in changelog.missing_fragment([("M", "src/tshark_mcp/server.py")])
    assert changelog.missing_fragment([("M", "src/tshark_mcp/server.py"), ("A", "changelog.d/x.fixed.md")]) is None
    # The README of changelog.d/ or a deleted fragment does not count.
    assert changelog.missing_fragment([("M", "src/a.py"), ("M", "changelog.d/README.md"),
                                       ("D", "changelog.d/y.fixed.md")])


def test_check_against_a_base_in_a_real_repository(tmp_path):
    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n")
    git("add", ".")
    git("commit", "-qm", "base")
    git("checkout", "-qb", "feature")
    (tmp_path / "src" / "a.py").write_text("x = 2\n")
    git("commit", "-qam", "change")
    assert changelog.missing_fragment(changelog.changed_files("main", tmp_path))
    (tmp_path / "changelog.d").mkdir()
    (tmp_path / "changelog.d" / "a.changed.md").write_text("- x is 2.\n")
    git("add", ".")
    git("commit", "-qm", "fragment")
    assert changelog.missing_fragment(changelog.changed_files("main", tmp_path)) is None
