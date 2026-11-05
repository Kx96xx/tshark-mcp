"""The Docker image: the Dockerfile keeps its safety properties, and (where docker is
installed, as in the CI docker job) the image starts and answers over stdio.

CI's docker job also runs every task-success scenario against `docker run -i` of the image
(`python -m evals --server-dir /captures -- docker run ...`)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
IMAGE = "tshark-mcp:ci"


def _instructions(name: str) -> list[str]:
    return [m.group(1).strip() for m in re.finditer(rf"^{name}\s+(.+)$", DOCKERFILE, re.M)]


def test_runs_as_a_non_root_user() -> None:
    users = _instructions("USER")
    assert users and users[-1].split(":")[0] not in ("root", "0")
    # USER comes after the last RUN, so nothing installed later runs as root at start
    assert DOCKERFILE.rindex("\nUSER ") > DOCKERFILE.rindex("\nRUN ")


def test_tshark_is_pinned_to_a_series_and_checked() -> None:
    [series] = re.findall(r"^ARG TSHARK_SERIES=(\d+\.\d+)$", DOCKERFILE, re.M)
    assert tuple(int(x) for x in series.split(".")) >= (4, 2)
    assert '"tshark=${TSHARK_SERIES}.*"' in DOCKERFILE
    assert 'grep -q "TShark (Wireshark) ${TSHARK_SERIES}\\."' in DOCKERFILE
    assert "--no-install-recommends" in DOCKERFILE and "rm -rf /var/lib/apt/lists/*" in DOCKERFILE


def test_entrypoint_healthcheck_and_capture_mount() -> None:
    assert _instructions("ENTRYPOINT") == ['["tshark-mcp"]']
    assert _instructions("CMD")[-1] == '["--allow-dir", "/captures"]'
    assert any(h.startswith("--interval=") for h in _instructions("HEALTHCHECK"))
    assert "/captures:ro" in DOCKERFILE and "--read-only" in DOCKERFILE and "--cap-drop ALL" in DOCKERFILE
    assert not _instructions("EXPOSE")  # stdio only: no port


def test_build_context_is_only_the_package() -> None:
    lines = [ln for ln in (ROOT / ".dockerignore").read_text().splitlines() if ln and not ln.startswith("#")]
    assert lines[0] == "*"
    assert {ln for ln in lines if ln.startswith("!")} == {"!pyproject.toml", "!README.md", "!LICENSE", "!src/"}
    copied = " ".join(_instructions("COPY"))
    assert "tests" not in copied and "examples" not in copied and ".git" not in copied


def _have_image() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0


needs_image = pytest.mark.skipif(not _have_image(), reason=f"docker image {IMAGE} not built (CI docker job builds it)")


@needs_image
def test_image_user_tshark_and_refusal() -> None:
    def run(*args: str, entrypoint: str | None = None) -> subprocess.CompletedProcess:
        cmd = ["docker", "run", "--rm", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--network", "none"]
        if entrypoint:
            cmd += ["--entrypoint", entrypoint]
        return subprocess.run([*cmd, IMAGE, *args], capture_output=True, text=True, timeout=120)

    assert run("-u", entrypoint="id").stdout.strip() == "10001"
    version = re.search(r"TShark \(Wireshark\) (\d+)\.(\d+)", run("--version", entrypoint="tshark").stdout)
    assert version and (int(version.group(1)), int(version.group(2))) >= (4, 2)
    assert run("--version").stdout.startswith("tshark-mcp ")
    refused = subprocess.run(["docker", "run", "--rm", "--entrypoint", "tshark-mcp", IMAGE],
                             capture_output=True, text=True, timeout=120)
    assert refused.returncode != 0  # no --allow-dir: the server refuses to start
    health = subprocess.run(["docker", "inspect", "--format", "{{json .Config.Healthcheck.Test}}", IMAGE],
                            capture_output=True, text=True).stdout
    assert "tshark_mcp" in health
