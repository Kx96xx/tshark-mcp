"""The README demo: a real MCP client session against the published PyPI package.

It starts `uvx --from tshark-mcp-server tshark-mcp` over stdio, lists the tools, then asks two
questions about examples/sip_one_way_audio.pcap and prints fields of the real results
(nothing is canned). docs/media/demo.tape records it with vhs:

    vhs docs/media/demo.tape     # writes docs/media/demo.gif

Run it by hand from the repository root: `uv run --with mcp python docs/media/demo_client.py`.
"""
import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

EXAMPLES = Path("examples").resolve()
PCAP = EXAMPLES / "sip_one_way_audio.pcap"
SERVER = os.environ.get("DEMO_SERVER", "uvx --from tshark-mcp-server tshark-mcp").split()

DIM, BOLD, GREEN, RED, CYAN, OFF = "\033[2m", "\033[1m", "\033[32m", "\033[31m", "\033[36m", "\033[0m"


def attr(obj, snake: str, camel: str):
    """mcp 2.x names fields in snake_case; older releases used the protocol's camelCase."""
    return getattr(obj, snake) if hasattr(obj, snake) else getattr(obj, camel)


def show_call(tool: str, **args: str) -> None:
    shown = ", ".join(f'{k}="{Path(v).relative_to(Path.cwd()) if v.startswith("/") else v}"' for k, v in args.items())
    print(f"\n{CYAN}tools/call{OFF} {BOLD}{tool}{OFF}({shown})")


async def main() -> None:
    params = StdioServerParameters(command=SERVER[0], args=[*SERVER[1:], "--allow-dir", str(EXAMPLES)])
    print(f"{DIM}server: {' '.join(SERVER)} --allow-dir examples{OFF}")
    async with stdio_client(params, errlog=open(os.devnull, "w")) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools = (await session.list_tools()).tools
            info = attr(init, "server_info", "serverInfo")
            print(f"{DIM}connected: {info.name} {info.version}, {len(tools)} tools{OFF}")

            show_call("sip_dialogs", path=str(PCAP))
            dialogs = attr(await session.call_tool("sip_dialogs", {"path": str(PCAP)}),
                           "structured_content", "structuredContent")
            d = dialogs["dialogs"][0]
            print(f"  call {d['call_id']}: {d['initial_method']} answered {d['final_status']}"
                  f" after {d['time_to_final_ms']:.0f} ms, {d['message_count']} messages")
            for m in d["messages"]:
                what = m.get("method") or m.get("status")
                print(f"    frame {m['frame']:>3}  {what!s:<6} {m['dir']}")

            show_call("media_path_check", path=str(PCAP), call_id=d["call_id"])
            r = attr(await session.call_tool("media_path_check", {"path": str(PCAP), "call_id": d["call_id"]}),
                     "structured_content", "structuredContent")
            for side in ("offer", "answer"):
                s = r[side]
                print(f"  {side:<6} frame {s['sdp_frame']}  media {s['media_endpoint']}  {s['codecs'][0]}")
            for leg in r["directions"]:
                ok = leg["status"] != "missing"
                colour = GREEN if ok else RED
                extra = ""
                if leg["streams"]:
                    st = leg["streams"][0]
                    extra = f" ({st['packets']} RTP packets from frame {st['first_frame']})"
                print(f"  {leg['direction']:<20} {colour}{leg['status']}{OFF}{extra}")
            print(f"  {BOLD}verdict:{OFF} {r['verdict']}")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
