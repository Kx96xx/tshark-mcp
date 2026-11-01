from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from tshark_mcp.limits import Limits
from tshark_mcp import server as server_module

from . import pcapgen

TSHARK = os.environ.get("TSHARK_MCP_TSHARK") or shutil.which("tshark") or "/opt/homebrew/bin/tshark"
HAVE_TSHARK = os.access(TSHARK, os.X_OK)

requires_tshark = pytest.mark.skipif(not HAVE_TSHARK, reason="tshark is not installed")


@pytest.fixture(scope="session")
def pcap_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Synthetic captures, generated once per session with scapy."""
    directory = tmp_path_factory.mktemp("pcaps")
    pcapgen.write_all(directory)
    pcapgen.write_merged_pcap(directory / "all.pcap", directory)
    return directory


@pytest.fixture
def configure(pcap_dir: Path, tmp_path: Path):
    """Configure the server for one test; returns a callable accepting Limits overrides."""
    def _configure(limits: Limits | None = None, allow: list[str] | None = None, log: bool = False):
        server_module.configure(
            allow or [str(pcap_dir)],
            limits=limits or Limits(),
            tshark=TSHARK,
            log_path=(tmp_path / "audit.jsonl") if log else None,
        )
        return server_module
    yield _configure
    server_module._STATE = None


@pytest.fixture
def server(configure):
    configure()
    return server_module
