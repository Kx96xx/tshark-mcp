"""call_ladder: Mermaid/text ladders with frame numbers, roles, determinism, escaping and the MCP Apps view."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from tshark_mcp import ladder, ladder_ui

from . import pcapgen
from .conftest import requires_tshark


class TestUnit:
    def test_labels_cannot_break_mermaid_or_html(self):
        evil = '<script>alert(1)</script>; P1->>P2: "x" %%{init}%% #59;\nend'
        out = ladder.clean(evil)
        assert "<" not in out and ">" not in out and ";" not in out and "\n" not in out and "%" not in out
        arrows = [{"frame": 7, "src": "a", "dst": "b", "label": ladder.clean(evil), "kind": "request"}]
        parts = ladder.participants(arrows, {}, True)
        diagram = ladder.mermaid(arrows, parts)
        assert diagram.count("\n") == 5 and "script" in diagram and "<script>" not in diagram

    def test_trace_rows_become_request_and_answer_arrows_with_roles(self):
        rows = [{"protocol": "diameter", "message": "ULR/ULA", "result": "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION",
                 "src": "192.0.2.10", "dst": "192.0.2.20", "request_frame": 3, "answer_frame": 4, "failed": True},
                {"protocol": "pfcp", "message": "Session Establishment Request", "src": "192.0.2.90",
                 "dst": "192.0.2.91", "request_frame": 9, "unanswered": True}]
        arrows, hints = ladder.from_trace(rows)
        assert [(a["frame"], a["kind"]) for a in arrows] == [(3, "request"), (4, "answer"), (9, "request")]
        assert arrows[1]["failed"] and arrows[2]["note"] == "no answer"
        assert hints["192.0.2.10"]["role"] == "MME" and hints["192.0.2.91"]["role"] == "UPF"
        diagram = ladder.mermaid(arrows, ladder.participants(arrows, hints, True))
        assert "participant P1 as MME 192.0.2.10" in diagram and "P1->>P2: #3 ULR" in diagram
        assert "    rect rgb(255, 228, 225)\n        P2-->>P1: #4 ULA DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION" in diagram


@pytest.fixture(scope="module")
def caps(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("ladder")
    pcapgen.write_all(d)
    pcapgen.write_merged_pcap(d / "all.pcap", d)
    pcapgen.write_voice_pcaps(d / "voice")
    return d


@pytest.fixture
def srv(configure, caps: Path):
    return configure(allow=[str(caps)])


@requires_tshark
class TestTool:
    def test_call_ladder_from_call_legs(self, srv, caps: Path):
        out = srv.call_ladder(str(caps / "voice" / "call_legs.pcap"), call_id="legs-a1@ue.example")
        d = out["diagram"]
        assert d.startswith("sequenceDiagram\n    autonumber\n    participant P1 as caller 198.51.100.70\n")
        assert "    P1->>P2: #1 INVITE\n" in d and "Note over P4,P3: failed here: 480 Temporarily Unavailable" in d
        assert out["verdict"].startswith("failed on leg 2: 480") and out["failures"] == 3
        frames = [a["frame"] for a in out["arrows"]]
        assert all(f"#{f} " in d for f in frames) and out["rows_dropped"] == 0
        assert "diagram" in out["untrusted_text_fields"]

    def test_subscriber_ladder_text_and_json(self, srv, caps: Path):
        path = str(caps / "all.pcap")
        text = srv.call_ladder(path, imsi=pcapgen.IMSI, format="text")
        assert "MME 192.0.2.10 ---> HSS 192.0.2.20  ULR" in text["diagram"]
        assert "!!#5" in text["diagram"] and "[no answer]" in text["diagram"]
        js = srv.call_ladder(path, imsi=pcapgen.IMSI, format="json")
        assert "diagram" not in js and js["arrows"] == text["arrows"]
        roles = {p["address"]: p.get("role") for p in js["participants"]}
        assert roles["192.0.2.30"] == "SGW" and roles["192.0.2.40"] == "PGW"

    def test_deterministic_and_capped(self, srv, caps: Path):
        path = str(caps / "voice" / "call_legs.pcap")
        a = srv.call_ladder(path, call_id="legs-a1@ue.example")
        b = srv.call_ladder(path, call_id="legs-a1@ue.example")
        assert a["diagram"] == b["diagram"]
        small = srv.call_ladder(path, call_id="legs-a1@ue.example", max_rows=4)
        assert small["rows_included"] == 4 and small["rows_dropped"] == a["rows_included"] - 4
        assert small["diagram"].count("->>") == 4

    def test_arguments(self, srv, caps: Path):
        path = str(caps / "all.pcap")
        assert srv.call_ladder(path)["error"]["type"] == "invalid_argument"
        assert srv.call_ladder(path, imsi=pcapgen.IMSI, max_rows=0)["error"]["type"] == "invalid_argument"
        assert srv.call_ladder(path, source="call_legs", imsi=pcapgen.IMSI)["error"]["type"] == "invalid_argument"
        assert srv.call_ladder(str(caps / "voice" / "call_legs.pcap"), call_id="nope@x")["error"]["type"] == "not_found"

    def test_redaction_reaches_the_diagram(self, srv, caps: Path):
        out = srv.call_ladder(str(caps / "all.pcap"), imsi=pcapgen.IMSI, redact="ids+ips")
        text = json.dumps(out)
        assert "192.0.2.10" not in text and pcapgen.IMSI not in text and "#1 ULR" in out["diagram"]


def test_viewer_html_is_self_contained_and_escapes():
    html = ladder_ui.HTML
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "innerHTML" not in html and "src=" not in html and "http://" not in html.replace(
        "http://www.w3.org/2000/svg", "")
    assert "textContent" in html and "fetch(" not in html and "XMLHttpRequest" not in html


@requires_tshark
def test_mcp_apps_resource_and_tool_meta_over_stdio(caps: Path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async def go():
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--allow-dir", str(caps),
                                             "--toolsets", "all"])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = {t.name: t for t in (await session.list_tools()).tools}
                resources = {str(r.uri): r for r in (await session.list_resources()).resources}
                body = await session.read_resource(ladder_ui.URI)
                res = await session.call_tool("call_ladder", {"path": str(caps / "voice" / "call_legs.pcap"),
                                                              "call_id": "legs-a1@ue.example"})
                return tools["call_ladder"], resources, body, res.structured_content
    tool, resources, body, out = asyncio.run(go())
    meta = getattr(tool, "meta", None) or getattr(tool, "_meta", None) or {}
    assert meta.get("ui", {}).get("resourceUri") == ladder_ui.URI
    res = resources[ladder_ui.URI]
    mime = getattr(res, "mime_type", None) or getattr(res, "mimeType", None)
    assert mime == ladder_ui.MIME_TYPE
    content = body.contents[0]
    assert content.text.startswith("<!doctype html>") and "createElementNS" in content.text
    assert out["diagram"].startswith("sequenceDiagram\n")
