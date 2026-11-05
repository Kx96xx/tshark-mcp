"""The PcapBench baseline arm: an MCP server with one tool, ``run_tshark(path, args)``.

It answers the question "what do the 55 tools add over a model driving tshark itself?". The
model gets plain tshark with the same safety as tshark-mcp: the capture must be inside an
allowed directory, the argv goes through :func:`tshark_mcp.runner.assert_read_only` (no capture,
no write, no extension flags), the same time, output and concurrency caps apply, and stdout is
cut to the same 30 KB a tshark-mcp result may use.

    python -m evals.tshark_only --allow-dir /captures
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from pydantic import Field
from typing_extensions import Annotated

from tshark_mcp.limits import Allowlist, Limits, ToolError
from tshark_mcp.runner import Runner

try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]

MAX_OUTPUT_CHARS = 30 * 1024
INSTRUCTIONS = ("One tool: run_tshark(path, args) runs `tshark -n -r <path> <args>` on a capture inside the "
                "allowed directories and returns stdout (cut to 30 KB) and stderr. Use display filters (-Y), "
                "fields (-T fields -e ...), statistics (-q -z ...) or -V for detail.")

app = _Server("tshark-only", instructions=INSTRUCTIONS)
_STATE: dict[str, Any] = {}


@app.tool()
def run_tshark(path: Annotated[str, Field(description="Capture file, absolute path in an allowed dir")],
               args: Annotated[list[str], Field(description="tshark arguments after -n -r <path>, such as "
                                                             "[\"-Y\", \"diameter\", \"-T\", \"fields\", \"-e\", \"frame.number\"]")]
               ) -> dict[str, Any]:
    """Run tshark read-only on one capture: `tshark -n -r <path> <args>`. Returns `stdout` (at most 30 KB,
    `truncated` when cut), `stderr` and `returncode`."""
    try:
        allow: Allowlist = _STATE["allow"]
        limits: Limits = _STATE["limits"]
        capture = allow.resolve(path, limits)
        result = _STATE["runner"].read_capture(capture, [str(a) for a in args])
    except ToolError as exc:
        return exc.to_dict()
    out = result.stdout
    data: dict[str, Any] = {"returncode": result.returncode, "stdout": out[:MAX_OUTPUT_CHARS],
                            "stderr": result.stderr[:2000]}
    if len(out) > MAX_OUTPUT_CHARS:
        data["truncated"] = True
        data["stdout_chars"] = len(out)
    data["tokens_estimate"] = int(len(str(data)) / 3.6) + 1
    return data


def configure(allow_dirs: list[str], tshark: str | None = None) -> None:
    limits = Limits.from_env()
    _STATE.update(allow=Allowlist.from_strings(allow_dirs), limits=limits, runner=Runner(limits, tshark=tshark))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m evals.tshark_only", description=__doc__.splitlines()[0])
    p.add_argument("--allow-dir", action="append", default=[], required=True)
    p.add_argument("--tshark", default=None)
    p.add_argument("--toolsets", default=None, help="ignored (accepted so the harness can start either arm)")
    args = p.parse_args(argv)
    configure(args.allow_dir, args.tshark)
    print(f"tshark-only: allow={_STATE['allow'].describe()}", file=sys.stderr)
    app.run(transport="stdio")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
