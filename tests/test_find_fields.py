"""find_fields and check_filter: build and check display filters without a capture."""

from __future__ import annotations

import pytest

from tshark_mcp.fields import glossary_row
from tshark_mcp.server import _filter_errors

from .conftest import requires_tshark


def test_glossary_row_columns():
    line = "F\tTEID\tgtp.teid\tFT_UINT32\tgtp\tBASE_HEX_DEC\t0x0\tTunnel Endpoint Identifier"
    assert glossary_row(line) == {"field": "gtp.teid", "name": "TEID", "type": "FT_UINT32", "protocol": "gtp",
                                  "display": "BASE_HEX_DEC", "description": "Tunnel Endpoint Identifier"}
    assert glossary_row("P\tDiameter Protocol\tdiameter") == {"field": "diameter", "name": "Diameter Protocol",
                                                              "type": "protocol", "protocol": "diameter"}
    assert glossary_row("F\tSource Address\tip.src\tFT_IPv4\tip\t\t0x0\t")["field"] == "ip.src"
    assert glossary_row("junk") is None


def test_filter_errors_and_caret_span():
    stderr = 'tshark: "0x100000000" too big for this field, maximum 4294967295.\n' \
             "    gtp.teid == 0x100000000\n" \
             "                ^~~~~~~~~~~\n"
    errors, at = _filter_errors(stderr)
    assert errors == ['"0x100000000" too big for this field, maximum 4294967295.']
    assert at == {"offset": 12, "length": 11}
    assert _filter_errors("tshark: Unexpected end of filter expression.\n") == (
        ["Unexpected end of filter expression."], None)


@requires_tshark
class TestFindFields:
    def test_exact_abbreviation_ranks_first(self, server):
        out = server.find_fields("gtp.teid")
        assert out["fields"][0]["field"] == "gtp.teid" and out["fields"][0]["type"] == "FT_UINT32"

    def test_every_word_must_match_and_protocol_narrows(self, server):
        out = server.find_fields("result code", protocol="diameter")
        assert out["fields"][0]["field"] == "diameter.Result-Code"
        assert all(r["protocol"] == "diameter" for r in out["fields"])
        for r in out["fields"]:
            text = f'{r["field"]} {r.get("name", "")} {r.get("description", "")}'.lower()
            assert "result" in text and "code" in text

    def test_protocols_are_listed_too(self, server):
        out = server.find_fields("diameter", protocol="diameter")
        assert out["fields"][0] == {"field": "diameter", "name": out["fields"][0]["name"], "type": "protocol",
                                    "protocol": "diameter"}

    def test_paging_contract(self, server):
        full = server.find_fields("retransmission", protocol="tcp", limit=500)
        page = server.find_fields("retransmission", protocol="tcp", limit=1, offset=1)
        assert page["fields"] == full["fields"][1:2] and page["total_matched"] == full["total_matched"] >= 2

    def test_no_match_is_empty(self, server):
        out = server.find_fields("zzzznosuchthing")
        assert out["fields"] == [] and out["total_matched"] == 0

    @pytest.mark.parametrize("query", ["", "   ", "x" * 101, "a\nb"])
    def test_bad_queries_are_rejected(self, server, query):
        assert server.find_fields(query)["error"]["type"] == "invalid_argument"

    def test_bad_protocol_is_rejected(self, server):
        assert server.find_fields("teid", protocol="gtp; rm")["error"]["type"] == "invalid_field"


@requires_tshark
class TestCheckFilter:
    def test_valid_filter_lists_its_fields(self, server):
        out = server.check_filter('diameter.cmd.code == 316 && ip.addr == 192.0.2.1 && sip.Method == "INVITE"')
        assert out["valid"] is True and "errors" not in out
        assert [f["field"] for f in out["fields"]] == ["diameter.cmd.code", "ip.addr", "sip.Method"]
        assert out["fields"][0]["type"] == "FT_UINT32"

    def test_tshark_error_with_span(self, server):
        out = server.check_filter("gtp.teid == 0x100000000")
        assert out["valid"] is False and out["rejected_by"] == "tshark"
        assert "too big" in out["errors"][0] and out["error_at"] == {"offset": 12, "length": 11}

    def test_unknown_field(self, server):
        out = server.check_filter("nosuch.field == 1")
        # tshark 4.4+ names the field; 4.2 says "Constant expression is invalid."
        assert out["valid"] is False and out["errors"] and out["rejected_by"] == "tshark"

    def test_server_lint_comes_first(self, server):
        out = server.check_filter("diameter; rm -rf /")
        assert out["valid"] is False and out["rejected_by"] == "server lint"

    def test_quoted_text_is_not_read_as_fields(self, server):
        out = server.check_filter('frame contains "ip.src"')
        assert [f["field"] for f in out["fields"]] == ["frame"]

    def test_deprecated_names_when_dftest_is_installed(self, server):
        out = server.check_filter("ssl")
        assert out["valid"] is True
        if out["warnings_checked"]:
            assert any("ssl" in w for w in out["filter_warnings"])
        else:
            assert "filter_warnings" not in out

    def test_no_capture_is_needed(self, configure, tmp_path):
        srv = configure(allow=[str(tmp_path)])  # an empty allowed directory
        assert srv.check_filter("tcp.port == 80")["valid"] is True


@requires_tshark
def test_without_dftest_warnings_are_not_claimed(server, monkeypatch):
    monkeypatch.setattr(server.state().runner, "dftest", None)
    out = server.check_filter("ssl")
    assert out["valid"] is True and out["warnings_checked"] is False and "filter_warnings" not in out
