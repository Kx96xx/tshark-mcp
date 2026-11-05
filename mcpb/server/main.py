"""Entry point of the MCPB desktop bundle.

The host passes the directories picked in the extension settings after ``--``, one argument
each; this turns them into one ``--allow-dir`` per directory and starts the server over stdio.
Everything before ``--`` is passed to the server unchanged (``--redact off``, ...).
"""

from __future__ import annotations

import sys

from tshark_mcp.server import main


def server_argv(argv: list[str]) -> list[str]:
    head, sep, dirs = (argv, "", []) if "--" not in argv else (
        argv[:argv.index("--")], "--", argv[argv.index("--") + 1:])
    out = [a for a in head if a != ""]
    for d in dirs:
        if d.strip():  # an unset optional setting arrives as an empty string
            out += ["--allow-dir", d]
    return out


if __name__ == "__main__":
    sys.exit(main(server_argv(sys.argv[1:])))
