"""call_legs: stitch B2BUA, SBC and CSCF legs of one call with a confidence per link."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tshark_mcp import calllegs

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark


def test_parse_headers_reads_escaped_crlf_and_compact_names():
    raw = ("v: SIP/2.0/UDP a;branch=1, SIP/2.0/UDP b;branch=2\\r\\nVia: SIP/2.0/UDP c\\r\\n"
           "i: x@y\\r\\nP-Charging-Vector: icid-value=\"abc\";orig-ioi=o\\r\\nX-CID: 77\\r\\n\\r\\n")
    headers = calllegs.parse_headers(raw)
    assert calllegs._via_count(headers["via"]) == 3 and headers["call-id"] == ["x@y"]
    keys = calllegs.link_keys(headers)
    assert keys["icid"] == "abc" and keys["x_ids"] == {"77"}


def _leg(cid: str, t0: float, src: str = "a", dst: str = "b", called: str | None = None, **keys) -> dict:
    base = {"icid": None, "session_ids": set(), "x_ids": set(), "replaces": None, "target_dialog": None}
    base.update(keys)
    return {"call_id": cid, "t0": t0, "src": src, "dst": dst, "called": called, "media": set(), "keys": base}


def test_links_replaces_target_dialog_and_null_session_uuid():
    null = "0" * 32
    legs = [_leg("one", 0.0, session_ids=set()), _leg("two", 100.0, replaces="one"),
            _leg("three", 200.0, target_dialog="two"), _leg("four", 300.0), _leg("five", 400.0)]
    # A null Session-ID UUID never links (RFC 7989 uses it before the far end is known).
    legs[3]["keys"]["session_ids"] = calllegs.link_keys({"session-id": [f"{null};remote={null}"]})["session_ids"]
    legs[4]["keys"]["session_ids"] = set(legs[3]["keys"]["session_ids"])
    links = calllegs.find_links(legs, 5.0)
    assert {(a, b, m) for a, b, m, _ in links} == {(0, 1, "replaces"), (1, 2, "target_dialog")}


def test_number_link_needs_hop_adjacency_and_window():
    legs = [_leg("in", 0.0, src="ue", dst="sbc", called="15550100700"),
            _leg("out", 0.1, src="sbc", dst="carrier", called="015550100700"),
            _leg("elsewhere", 0.2, src="other", dst="carrier", called="15550100700"),
            _leg("late", 9.0, src="sbc", dst="carrier", called="15550100700")]
    links = calllegs.find_links(legs, 5.0)
    assert [(a, b, m) for a, b, m, _ in links] == [(0, 1, "number_and_time")]


def test_fork_keeps_both_branches():
    legs = [_leg("in", 0.0, src="ue", dst="sbc", icid="i"), _leg("b1", 0.1, src="sbc", dst="x", icid="i"),
            _leg("b2", 0.2, src="sbc", dst="y", icid="i")]
    for leg in legs:
        leg.update({"frame": 1, "hops": [], "from": None, "to": None, "request_uri": None, "status": None,
                    "final_frame": None, "final_time": None, "responder": None, "reason": None, "first_18x": None,
                    "p_asserted_identity": None, "privacy": None, "codecs": None, "via_count": 1,
                    "record_route_count": 0})
    legs[0]["status"], legs[1]["status"], legs[2]["status"] = 486, 486, 487
    (call,) = calllegs.stitch(legs, calllegs.find_links(legs, 5.0))
    assert [r["linked_by"]["leg"] for r in call["legs"][1:]] == [0, 0]
    assert [r["depth"] for r in call["legs"]] == [0, 1, 1]
    assert {m["downstream_leg"] for m in call["status_mapping"]} == {1, 2}


@pytest.fixture
def legs_capture(configure, pcap_dir: Path):
    srv = configure()
    return srv, str(pcap_dir / "voice" / "call_legs.pcap")


@requires_tshark
class TestCallLegs:
    def test_stitches_five_calls(self, legs_capture):
        srv, path = legs_capture
        out = srv.call_legs(path)
        assert out["total_matched"] == 5
        assert [c["legs_count"] for c in out["calls"]] == [3, 2, 2, 2, 1]
        assert [c.get("confidence") for c in out["calls"]] == ["high", "high", "medium", "low", None]
        s = out["summary"]
        assert s["legs"] == 10 and s["multi_leg_calls"] == 4 and s["rewritten_statuses"] == 1
        assert s["links_by_method"] == {"icid": 1, "session_id": 1, "x_call_id": 1, "same_media_endpoint": 1,
                                        "number_and_time": 1}
        assert set(out["method"]) >= set(calllegs.CONFIDENCE)

    def test_b2bua_rewrote_480_to_503(self, legs_capture):
        srv, path = legs_capture
        call = srv.call_legs(path)["calls"][0]
        assert [leg["call_id"] for leg in call["legs"]] == ["legs-a1@ue.example", "legs-a2@sbc.example",
                                                           "legs-a3@scscf.example"]
        assert [leg.get("linked_by", {}).get("method") for leg in call["legs"]] == [None, "icid", "session_id"]
        assert call["caller_status"] == 503 and call["caller_q850_cause"] == 34
        where = call["where_it_failed"]
        assert (where["leg"], where["status"], where["q850_cause"], where["responder"]) == (2, 480, 18, g.CARRIER_X)
        # The explanations come from cause_lookup.
        assert where["sip"]["name"] == "Temporarily Unavailable" and where["q850"]["ref"].startswith("ITU-T Q.850")
        rewritten = [m for m in call["status_mapping"] if m["rewritten"]]
        assert len(rewritten) == 1
        (m,) = rewritten
        assert m["element"] == g.SBC_IP and m["received"]["status"] == 480 and m["sent"]["status"] == 503
        assert "rewrote the status" in m["note"]
        assert call["legs"][1]["added_delay_ms"] == {"invite": 30.0, "final_response": 150.0}
        assert {"header": "codecs", "upstream": ["AMR-WB/16000", "PCMU/8000"],
                "downstream": ["PCMU/8000"]} in call["legs"][1]["header_changes"]
        assert {"header": "Privacy", "upstream": None, "downstream": "id"} in call["legs"][2]["header_changes"]

    def test_other_link_methods(self, legs_capture):
        srv, path = legs_capture
        b, c, d, e = srv.call_legs(path)["calls"][1:]
        assert b["legs"][1]["linked_by"] == {"leg": 0, "method": "x_call_id", "confidence": "high",
                                             "evidence": "legs-b1@peer.example"}
        assert b["legs"][1]["added_delay_ms"] == {"invite": 40.0, "final_response": 30.0}
        assert "where_it_failed" not in b
        assert c["legs"][1]["linked_by"]["method"] == "same_media_endpoint"
        assert c["legs"][1]["linked_by"]["evidence"] == f"{g.LEGS_UE}:40000"
        assert d["legs"][1]["linked_by"]["confidence"] == "low"
        assert d["status_mapping"][0]["rewritten"] is False and d["where_it_failed"]["q850"]["name"]
        assert e["legs_count"] == 1 and e["legs"][0]["call_id"] == "legs-e1@sbc.example"

    def test_call_id_selects_the_whole_call_with_a_ladder(self, legs_capture):
        srv, path = legs_capture
        out = srv.call_legs(path, call_id="legs-a3@scscf.example")
        (call,) = out["calls"]
        assert call["legs_count"] == 3
        ladder = call["ladder"]
        assert {r["leg"] for r in ladder} == {0, 1, 2}
        assert [r["frame"] for r in ladder] == sorted(r["frame"] for r in ladder)
        assert ladder[0] == {"frame": 1, "time": ladder[0]["time"], "src": g.LEGS_UE, "dst": g.SBC_IP,
                             "message": "INVITE", "leg": 0}
        assert "ladder" not in srv.call_legs(path)["calls"][0]

    def test_number_window_and_paging(self, legs_capture):
        srv, path = legs_capture
        by_number = srv.call_legs(path, number=g.LEGS_NUMBER)
        assert [c["legs_count"] for c in by_number["calls"]] == [2, 1]
        # A zero window keeps the identifier links and drops the media and number ones.
        tight = srv.call_legs(path, window_s=0)
        assert [c["legs_count"] for c in tight["calls"]] == [3, 2, 1, 1, 1, 1, 1]
        page = srv.call_legs(path, limit=2, offset=1)
        assert page["returned"] == 2 and page["next_offset"] == 3 and page["calls"][0]["first_frame"] == 16

    def test_counts_match_raw_tshark(self, legs_capture):
        _, path = legs_capture
        out = subprocess.run([TSHARK, "-n", "-r", path, "-Y", 'sip.Method == "INVITE"', "-T", "fields",
                              "-e", "sip.Call-ID"], capture_output=True, text=True, check=True).stdout
        assert len(set(out.split())) == 10
        icid = subprocess.run([TSHARK, "-n", "-r", path, "-Y", f'sip.P-Charging-Vector contains "{g.LEGS_ICID}"',
                               "-T", "fields", "-e", "sip.Call-ID"], capture_output=True, text=True, check=True).stdout
        assert set(icid.split()) == {"legs-a1@ue.example", "legs-a2@sbc.example"}

    def test_redaction_hides_numbers(self, legs_capture):
        srv, path = legs_capture
        text = str(srv.call_legs(path, redact="ids"))
        assert g.LEGS_NUMBER not in text and "15550100500" not in text

    @pytest.mark.parametrize("args", [{"window_s": -1}, {"window_s": 301}, {"window_s": "x"}, {"number": "12a"},
                                      {"call_id": 'a"b'}])
    def test_bad_arguments(self, legs_capture, args):
        srv, path = legs_capture
        assert srv.call_legs(path, **args)["error"]["type"] == "invalid_argument"
