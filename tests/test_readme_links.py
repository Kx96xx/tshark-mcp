"""README.md is the PyPI long description, where relative links resolve to nothing.

Every Markdown link and image in it must be absolute (http/https/mailto) or an
in-page anchor, and every link into this repository must name a file that exists.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
REPO = "https://github.com/Kx96xx/tshark-mcp/"
RAW = "https://raw.githubusercontent.com/Kx96xx/tshark-mcp/main/"  # images, so they render on PyPI


def _links():
    return re.findall(r"\]\(([^)\s]+)\)", README.read_text(encoding="utf-8"))


def test_readme_links_are_absolute():
    bad = [u for u in _links() if not re.match(r"(https?:|mailto:|#)", u)]
    assert not bad, f"relative links break on PyPI: {bad}"


def test_readme_repo_links_point_at_existing_files():
    missing = []
    for url in _links():
        prefixes = [REPO + kind for kind in ("blob/main/", "tree/main/")]
        prefixes.append(RAW)
        for prefix in prefixes:
            if url.startswith(prefix):
                path = url[len(prefix):].split("#", 1)[0].rstrip("/")
                if path and not (ROOT / path).exists():
                    missing.append(url)
    assert not missing, f"links to files that do not exist on main: {missing}"


def test_readme_images_are_absolute_raw_urls_that_exist():
    images = re.findall(r"!\[[^\]]*\]\(([^)\s]+)\)", README.read_text(encoding="utf-8"))
    local = [u for u in images if u.startswith(RAW)]
    assert local, "the demo GIF should be referenced by its raw.githubusercontent URL"
    for url in local:
        assert (ROOT / url[len(RAW):]).is_file(), url
