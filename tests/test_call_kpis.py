"""call_kpis: ASR, SER, NER, PDD and ACD per group on a synthetic mix of ten calls."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tshark_mcp import callkpi

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark


def test_normalise_number():
    assert callkpi.normalise_number("+447700900001") == "447700900001"
    assert callkpi.normalise_number("00447700900003") == "447700900003"
    assert callkpi.normalise_number("+1-555-0100;npdi;rn=+15550199") == "15550100"
    assert callkpi.normalise_number("tel:+15550100") == "15550100"
    assert callkpi.normalise_number("alice") is None and callkpi.normalise_number(None) is None


def test_kpis_definitions_on_hand_built_calls():
    def call(status, alerted=False, **kw):
        return {"call_id": "x", "frame": 1, "time": "", "t0": 0.0, "src": "a", "dst": "b", "to": None,
                "from_user": None, "user_agent": None, "status": status, "alerted": alerted, **kw}
    calls = [call(200, True, pdd_ms=100.0, duration_s=10.0), call(302), call(487, True), call(487, False),
             call(486), call(480, False), call(None, no_final_response=True),
             call(None, no_final_response=True, near_capture_end=True)]
    k = callkpi.kpis(calls)
    assert k["calls"] == 8 and k["near_capture_end"] == 1 and k["no_final_response"] == 1
    # 7 decided calls, 1 answered, 1 redirected, 2 cancelled with 487.
    assert k["asr_pct"] == pytest.approx(14.3) and k["ser_pct"] == pytest.approx(16.7)
    assert k["ser_without_487_pct"] == pytest.approx(25.0)
    # NER: answered + 487 after alerting + 486 (480 without alerting is a network failure).
    assert k["ner_pct"] == pytest.approx(42.9)
    assert k["failure_codes"] == {"487": 2, "302": 1, "480": 1, "486": 1}


@pytest.fixture
def mix(configure, pcap_dir: Path):
    srv = configure()
    return srv, str(pcap_dir / "voice" / "call_mix.pcap")


@requires_tshark
class TestCallKpis:
    def test_per_peer(self, mix):
        srv, path = mix
        out = srv.call_kpis(path)
        assert out["group_by"] == "peer" and out["total_matched"] == 2
        x, y = (next(r for r in out["groups"] if r["peer"] == ip) for ip in (g.CARRIER_X, g.CARRIER_Y))
        assert (x["calls"], x["answered"], x["failed"]) == (5, 2, 3)
        assert (x["asr_pct"], x["ser_pct"], x["ser_without_487_pct"], x["ner_pct"]) == (40.0, 40.0, 50.0, 80.0)
        assert x["pdd_ms"]["p50"] == 550.0 and x["pdd_ms"]["max"] == 800.0 and x["pdd_ms"]["calls"] == 4
        assert x["answer_without_ringing_ms"]["p50"] == 1200.0 and x["ringing_ms"]["p50"] == 4200.0
        assert x["acd_s"] == {"mean": 45.0, "median": 45.0, "calls": 2}
        assert x["failure_codes"] == {"486": 1, "487": 1, "503": 1}
        assert x["q850_causes"] == {"17 User busy": 1, "34 No circuit/channel available": 1}
        # Carrier Y: the last INVITE is still open when the capture stops, so it is left
        # out of the ratios; the one never answered 130 s earlier counts as a failure.
        assert (y["calls"], y["near_capture_end"], y["no_final_response"]) == (5, 1, 1)
        assert y["asr_pct"] == 50.0 and y["ner_pct"] == 50.0
        # The 407 challenge and the retry are one call; PDD runs from the first INVITE.
        assert y["pdd_ms"]["p50"] == 900.0 and y["ringing_ms"]["calls"] == 2
        assert y["acd_s"]["mean"] == 65.0
        s = out["summary"]
        assert (s["calls"], s["answered"], s["asr_pct"]) == (10, 4, 44.4)
        assert "RFC 6076" in out["method"]["ser_pct"] and "Timer B" in out["method"]["undecided"]

    def test_worst_calls_point_at_frames(self, mix):
        srv, path = mix
        worst = srv.call_kpis(path)["worst_calls"]
        statuses = [w.get("status") for w in worst]
        assert set(statuses[:5]) == {486, 487, 503, 404, None}
        unanswered = next(w for w in worst if w.get("no_final_response"))
        assert unanswered["call_id"] == "mix-8@sbc.example" and unanswered["frame"] > 0
        assert all("near_capture_end" not in w for w in worst)

    def test_other_groupings(self, mix):
        srv, path = mix
        by_prefix = srv.call_kpis(path, group_by="destination_prefix")["groups"]
        assert {r["destination_prefix"]: r["calls"] for r in by_prefix} == {"4477": 5, "1555": 5}
        six = srv.call_kpis(path, group_by="destination_prefix", prefix_len=6)["groups"]
        assert {r["destination_prefix"] for r in six} == {"447700", "155501"}
        ua = srv.call_kpis(path, group_by="user_agent")
        assert {r["user_agent"]: r["answered"] for r in ua["groups"]} == {"SBC-A/1.0": 2, "SBC-B/2.1": 2}
        assert "user_agent" in ua["untrusted_text_fields"]
        trunk = srv.call_kpis(path, group_by="trunk")["groups"]
        assert {r["trunk"] for r in trunk} == {f"{g.SBC_IP} > {g.CARRIER_X}", f"{g.SBC_IP} > {g.CARRIER_Y}"}
        intervals = srv.call_kpis(path, group_by="interval", interval=60)["groups"]
        assert [r["calls"] for r in intervals] == [3, 3, 3, 1]
        assert intervals[0]["interval_start"] < intervals[1]["interval_start"]

    def test_number_filter_and_paging(self, mix):
        srv, path = mix
        out = srv.call_kpis(path, number="447700900003")
        assert out["summary"]["calls"] == 1 and out["groups"][0]["failure_codes"] == {"486": 1}
        page = srv.call_kpis(path, limit=1)
        assert page["returned"] == 1 and page["next_offset"] == 1
        filtered = srv.call_kpis(path, filter=f"ip.addr == {g.CARRIER_X}")
        assert filtered["summary"]["calls"] == 5

    def test_counts_match_raw_tshark(self, mix):
        _, path = mix
        out = subprocess.run([TSHARK, "-n", "-r", path, "-Y", 'sip.Method == "INVITE"',
                              "-T", "fields", "-e", "sip.Call-ID"], capture_output=True, text=True, check=True).stdout
        assert len(set(out.split())) == 10
        ok = subprocess.run([TSHARK, "-n", "-r", path, "-Y", 'sip.Status-Code == 200 && sip.CSeq.method == "INVITE"',
                             "-T", "fields", "-e", "sip.Call-ID"], capture_output=True, text=True, check=True).stdout
        assert len(set(ok.split())) == 4

    @pytest.mark.parametrize("args", [{"group_by": "codec"}, {"prefix_len": 0}, {"prefix_len": "x"},
                                      {"interval": 0.5}, {"number": "12a"}])
    def test_bad_arguments(self, mix, args):
        srv, path = mix
        assert srv.call_kpis(path, **args)["error"]["type"] == "invalid_argument"
