"""cause_lookup: names from tshark's value strings, curated meaning and references."""

from __future__ import annotations

import pytest

from tshark_mcp import causedata, causes
from tshark_mcp.limits import Limits, ToolError
from tshark_mcp.runner import Runner, assert_read_only

from .conftest import TSHARK, requires_tshark


def test_parse_values_reads_decimal_hex_and_ranges():
    text = ("V\tgtpv2.cause\t78\tMissing or unknown APN\n"
            "V\tsccp.return_cause\t0x1\tNo translation for this specific address\n"
            "R\tfoo.cause\t3\t15\tReserved\n"
            "E\tgtpv2.cause\t132\tgtpv2_cause_vals\t[Direct]\n"
            "V\tbroken\tnot-a-number\tx\n")
    names = causes.parse_values(text)
    assert names["gtpv2.cause"].get(78) == "Missing or unknown APN"
    assert names["sccp.return_cause"].get(1).startswith("No translation")
    assert names["foo.cause"].get(7) == "Reserved" and names["foo.cause"].get(16) is None
    assert "broken" not in names


def test_unexplained_spec_expands_ranges_and_groups():
    assert {2, 3, 4, 15}.issubset(causedata.UNEXPLAINED["gtpv2"])
    assert "radioNetwork:0" in causedata.UNEXPLAINED["s1ap"]


def test_values_dump_stays_read_only():
    # The glossary dump needs no capture; capture or write flags are still refused next to it.
    assert_read_only(["-G", "values"])
    with pytest.raises(ToolError):
        assert_read_only(["-G", "values", "-w", "/tmp/x"])
    with pytest.raises(ToolError):
        assert_read_only(["-G", "values", "-i", "any"])


@pytest.fixture(scope="module")
def values():
    causes._VALUES_CACHE.clear()
    return causes.tshark_values(Runner(Limits(), tshark=TSHARK))


@requires_tshark
class TestTsharkTables:
    def test_line_filter_keeps_the_stdout_cap_on_kept_lines(self):
        # The full dump is about 100 MB; a 1 MB stdout cap still works because only the
        # cause fields are kept while tshark writes.
        runner = Runner(Limits(max_stdout_bytes=1024 * 1024), tshark=TSHARK)
        result = runner.list_values(lambda line: line.startswith(b"V\tgtpv2.cause\t"))
        assert result.returncode == 0
        lines = result.stdout.splitlines()
        assert lines and all(ln.startswith("V\tgtpv2.cause\t") for ln in lines)

    def test_every_tshark_code_is_explained_or_listed(self, values):
        """A tshark release that names a new code fails here until it is curated or listed."""
        missing: dict[str, list] = {}
        for key, table in causes.TABLES.items():
            for fld in table.fields:
                names = values.get(fld)
                if names is None:
                    continue
                group = fld.split(".", 1)[1]
                for code, name in names.values.items():
                    if causes.RESERVED.match(name):
                        continue
                    k = f"{group}:{code}" if key in ("s1ap", "ngap") else code
                    if k not in table.curated and k not in causedata.UNEXPLAINED.get(key, ()):
                        missing.setdefault(key, []).append((k, name))
            for code in table.names:
                if code not in table.curated and code not in causedata.UNEXPLAINED.get(key, ()):
                    missing.setdefault(key, []).append((code, table.names[code]))
        assert not missing, missing

    def test_every_curated_code_is_one_tshark_names(self, values):
        """Guards against a meaning filed under the wrong number."""
        wrong = []
        for key, table in causes.TABLES.items():
            if not table.fields:
                continue
            for code in table.curated:
                group, value = (code.split(":")[0], int(code.split(":")[1])) if isinstance(code, str) else (None, code)
                name = causes._name(table, values, value, group)
                if name[1] != "tshark" or causes.RESERVED.match(name[0]):
                    wrong.append((key, code, name))
        assert not wrong, wrong

    def test_tables_without_tshark_values_carry_names(self):
        for key in ("sip", "map", "cp", "tp_status"):
            table = causes.TABLES[key]
            assert not table.fields
            for code, raw in table.curated.items():
                assert causes._entry(raw).get("name") or code in table.names, (key, code)


@requires_tshark
class TestCauseLookupTool:
    def test_gtpv2_cause_by_number_and_hex(self, server):
        out = server.cause_lookup(protocol="gtpv2", code=78)
        assert out["name"] == "Missing or unknown APN" and out["name_source"] == "tshark"
        assert out["ref"].startswith("TS 29.274") and out["explained"] and out["known"]
        assert out["tshark_field"] == "gtpv2.cause" and out["typical_causes"]
        assert any("gtpv2.cause == 78" in step for step in out["check_next"])
        assert server.cause_lookup(protocol="gtpv2", code="0x4e")["code"] == 78

    def test_diameter_base_and_experimental_readings(self, server):
        base = server.cause_lookup(protocol="diameter", code=5004)
        assert base["avp"] == "Result-Code" and base["name"] == "DIAMETER_INVALID_AVP_VALUE"
        assert base["also"]["name"] == "DIAMETER_ERROR_ROAMING_NOT_ALLOWED"
        s6a = server.cause_lookup(protocol="diameter", code=5004, application="s6a")
        assert s6a["avp"] == "Experimental-Result-Code" and s6a["ref"].startswith("TS 29.272")
        assert "ODB" in s6a["application_note"]
        cx = server.cause_lookup(protocol="diameter", code=5004, application="cx")
        assert cx["ref"].startswith("TS 29.229") and "IMS" in cx["application_note"]
        # Only an Experimental-Result-Code: found there without an application.
        eps = server.cause_lookup(protocol="diameter", code=5420)
        assert eps["avp"] == "Experimental-Result-Code" and eps["name"] == "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION"
        assert eps["ref"].startswith("TS 29.272") and "5004" in eps["related"]
        # A base code asked under an application falls back with a note.
        relay = server.cause_lookup(protocol="diameter", code=3002, application="s6a")
        assert relay["avp"] == "Result-Code" and "base Result-Code" in relay["note"]

    def test_groups_messages_and_string_codes(self, server):
        s1 = server.cause_lookup(protocol="s1ap", code="radioNetwork:21")
        assert s1["name"] == "radio-connection-with-ue-lost" and s1["tshark_field"] == "s1ap.radioNetwork"
        assert server.cause_lookup(protocol="s1ap", code="NAS/2")["name"] == "detach"
        reg = server.cause_lookup(protocol="sip", code=403, message="REGISTER")
        assert reg["name"] == "Forbidden" and "Cx" in reg["message_note"]
        assert "by_message" in server.cause_lookup(protocol="sip", code=403)
        sbi = server.cause_lookup(protocol="http_sbi", code="user_not_found")
        assert sbi["name"] == "USER_NOT_FOUND" and sbi["ref"].startswith("TS 29.503")
        q = server.cause_lookup(protocol="isup", code=16)
        assert q["name"] == "Normal call clearing" and q["ref"].startswith("ITU-T Q.850")
        assert server.cause_lookup(protocol="map", code=6)["name"] == "absentSubscriberSM"

    def test_unknown_reserved_and_unexplained(self, server):
        unknown = server.cause_lookup(protocol="gtpv2", code=250)
        assert unknown["known"] is False and unknown["name"] is None and "query" in unknown["note"]
        reserved = server.cause_lookup(protocol="gtpv2", code=71)
        assert reserved["known"] is False and "reserved" in reserved["note"]
        plain = server.cause_lookup(protocol="gtpv2", code=128)
        assert plain["known"] and plain["explained"] is False and "meaning" not in plain

    def test_search_pages(self, server):
        out = server.cause_lookup(protocol="gtpv2", query="apn")
        codes = [r["code"] for r in out["codes"]]
        assert 78 in codes and 93 in codes and out["total_matched"] == len(codes)
        page = server.cause_lookup(protocol="gtpv2", query="apn", limit=1, offset=1)
        assert page["codes"] == out["codes"][1:2] and page["next_offset"] == 2
        roam = server.cause_lookup(protocol="diameter", query="roaming not allowed")
        assert {(r["avp"], r["code"]) for r in roam["codes"]} >= {("Experimental-Result-Code", 5004)}

    @pytest.mark.parametrize("args, needle", [
        ({"protocol": "rtcp_xr", "code": 1}, "rtp_streams"),
        ({"protocol": "nosuch", "code": 1}, "one of"),
        ({"protocol": "gtpv2"}, "exactly one"),
        ({"protocol": "gtpv2", "code": 78, "query": "apn"}, "exactly one"),
        ({"protocol": "gtpv2", "code": "seventy"}, "number"),
        ({"protocol": "gtpv2", "code": 78, "application": "s6a"}, "diameter"),
        ({"protocol": "diameter", "code": 5001, "application": "zz"}, "application"),
        ({"protocol": "s1ap", "code": 21}, "group"),
        ({"protocol": "s1ap", "code": "radio:21"}, "group"),
        ({"protocol": "http_sbi", "code": "bad cause!"}, "ProblemDetails"),
        ({"protocol": "sip", "code": 403, "message": "x" * 100}, "message"),
        ({"protocol": "gtpv2", "query": "a\x00b"}, "printable"),
    ])
    def test_bad_arguments(self, server, args, needle):
        out = server.cause_lookup(**args)
        assert out["error"]["type"] == "invalid_argument" and needle in out["error"]["message"], out
