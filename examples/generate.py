"""Regenerate the sample captures in this directory.

The captures are synthetic: built packet by packet from the protocol specifications by
``tests/pcapgen.py`` with documentation addresses (RFC 5737), the test PLMN 001/01 and
reserved telephone numbers. Nothing in them comes from a real network.

    python examples/generate.py            # rewrite examples/*.pcap
    python examples/generate.py /some/dir  # write them elsewhere

``tests/test_examples.py`` fails when the committed files differ from a fresh generation,
so the README examples cannot drift from the files.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.pcapgen import write_example_pcaps  # noqa: E402

if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    for name, path in write_example_pcaps(target).items():
        print(f"{name}: {path} ({path.stat().st_size} bytes)")
