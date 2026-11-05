"""README.md is the PyPI long description, where relative links resolve to nothing.

Every Markdown link and image in it must be absolute (http/https/mailto) or an
in-page anchor, and every link into this repository must name a file that exists.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
REPO = "https://github.com/Kx96xx/tshark-mcp/"


def _links():
    return re.findall(r"\]\(([^)\s]+)\)", README.read_text(encoding="utf-8"))


def test_readme_links_are_absolute():
    bad = [u for u in _links() if not re.match(r"(https?:|mailto:|#)", u)]
    assert not bad, f"relative links break on PyPI: {bad}"


def test_readme_repo_links_point_at_existing_files():
    missing = []
    for url in _links():
        for kind in ("blob/main/", "tree/main/"):
            prefix = REPO + kind
            if url.startswith(prefix):
                path = url[len(prefix):].split("#", 1)[0].rstrip("/")
                if path and not (ROOT / path).exists():
                    missing.append(url)
    assert not missing, f"links to files that do not exist on main: {missing}"
