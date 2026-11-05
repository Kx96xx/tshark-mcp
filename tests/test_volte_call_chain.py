"""volte_call_chain: one VoLTE call through SIP, Rx, Gx, GTPv2-C, PFCP and RTP."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tshark_mcp import volte

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark


def _sip(frame: int, t: float, **kw) -> dict:
    row = {"kind": "sip", "frame": frame, "time": t, "src": "ue", "dst": "p", "call_id": "c", "method": None,
           "status": None, "cseq_method": "INVITE", "icid": None, "sdp_addrs": [], "sdp_ports": [], "precondition": False}
    row.update(kw)
    return row


def test_missing_versus_not_captured():
    rows = [_sip(1, 0.0, method="INVITE", sdp_addrs=["10.0.0.1"], sdp_ports=[4000]), _sip(2, 1.0, status=200)]
    idx = volte.build_index(rows)
    (call,) = volte.calls(rows)
    out = volte.chain(call, idx, None, 10.0, lambda *a: None)
    assert out["links"][1] == {"link": "rx_aar", "status": "not_captured"}
    assert "first_broken_link" not in out and out["verdict"].startswith("no broken link")
    # With Rx in the capture but not for this call the link is missing and is the first broken one.
    other = {"kind": "diameter", "frame": 3, "time": 0.5, "src": "a", "dst": "b", "cmd": 265, "request": True,
             "app": volte.RX_APP, "hbh": "0x1", "session": "s", "result": None, "exp_result": None,
             "framed_ip": "10.9.9.9", "af_charging_id": "other", "qci": [], "install": False, "remove": False, "rules": []}
    idx = volte.build_index([*rows, other])
    out = volte.chain(call, idx, None, 10.0, lambda *a: None)
    assert out["first_broken_link"] == "rx_aar" and out["links"][1]["status"] == "missing"


def test_bearer_after_the_200_is_late():
    rows = [_sip(1, 0.0, method="INVITE", sdp_addrs=["10.0.0.1"], icid="i"), _sip(2, 1.0, status=200)]
    diam = dict(kind="diameter", src="p", dst="r", app=volte.RX_APP, session="rx", result=None, exp_result=None,
                framed_ip="10.0.0.1", af_charging_id="i", qci=[], install=False, remove=False, rules=[])
    rows += [{**diam, "frame": 3, "time": 0.1, "cmd": 265, "request": True, "hbh": "1"},
             {**diam, "frame": 4, "time": 0.2, "cmd": 265, "request": False, "hbh": "1", "result": 2001},
             {**diam, "frame": 5, "time": 0.3, "cmd": 258, "request": True, "hbh": "2", "app": volte.GX_APP,
              "install": True, "qci": [1], "framed_ip": None},
             {**diam, "frame": 6, "time": 0.4, "cmd": 258, "request": False, "hbh": "2", "app": volte.GX_APP,
              "result": 2001, "framed_ip": None},
             {"kind": "gtp", "frame": 7, "time": 0.5, "src": "s", "dst": "m", "msg": 95, "teid": 1, "seq": 9,
              "cause": None, "ebi": [5], "qci": [1], "paa": None},
             {"kind": "gtp", "frame": 8, "time": 1.5, "src": "m", "dst": "s", "msg": 96, "teid": 2, "seq": 9,
              "cause": 16, "ebi": [6], "qci": [], "paa": None}]
    rows.sort(key=lambda r: r["time"])
    idx = volte.build_index(rows)
    (call,) = volte.calls(rows)
    out = volte.chain(call, idx, None, 10.0, lambda *a: None)
    assert out["first_broken_link"] == "gtp_create_bearer" and "after the 200 OK" in out["verdict"]


@pytest.fixture
def volte_capture(configure, pcap_dir: Path):
    srv = configure()
    return srv, str(pcap_dir / "volte" / "volte_chain.pcap")


@requires_tshark
class TestVolteCallChain:
    def test_three_calls(self, volte_capture):
        srv, path = volte_capture
        out = srv.volte_call_chain(path)
        assert "error" not in out, out
        ok, rx, bearer = out["calls"]
        assert [c["call_id"] for c in out["calls"]] == [g.VOLTE_CALL[k] for k in ("ok", "rx", "bearer")]
        assert "first_broken_link" not in ok and ok["verdict"].startswith("every link present")
        names = [lk["link"] for lk in ok["links"]]
        assert names == ["invite", "sip_183", "rx_aar", "gx_rar_install", "gtp_create_bearer", "pfcp_modification",
                         "sip_prack", "sip_update", "sip_180", "sip_final", "rtp_to_ue", "rtp_from_ue", "bye",
                         "rx_str", "gx_rar_remove", "gtp_delete_bearer"]
        by = {lk["link"]: lk for lk in ok["links"]}
        assert by["rx_aar"]["found_by"] == "icid" and by["gx_rar_install"]["found_by"] == "ue_ip"
        assert by["gx_rar_install"]["rules"] == ["volte-voice"] and by["gx_rar_install"]["qci"] == 1
        legs = by["gtp_create_bearer"]["legs"]
        assert [leg["found_by"] for leg in legs] == ["time", "ue_ip"] and {leg["ebi"] for leg in legs} == {6}
        assert by["rtp_from_ue"]["after_dedicated_bearer"] is True and ok["ue_ip"] == g.VOLTE_UE["ok"]
        assert by["rx_aar"]["delay_ms"] == 10.0  # after the 183
        assert rx["first_broken_link"] == "rx_aar" and rx["final_status"] == 503
        rx_link = next(lk for lk in rx["links"] if lk["link"] == "rx_aar")
        assert rx_link["result_code"] == 5065 and rx_link["explained"]["name"]
        assert "PCRF refused" in rx["verdict"]
        assert bearer["first_broken_link"] == "gtp_create_bearer"
        assert "cause 73" in bearer["verdict"] and "the UE sent no RTP" in bearer["verdict"]
        assert out["summary"] == {"calls": 3, "intact": 1, "first_broken_link": {"rx_aar": 1, "gtp_create_bearer": 1},
                                  "protocols_captured": ["rx", "gx", "gtp", "pfcp", "rtp"]}

    def test_selectors(self, volte_capture):
        srv, path = volte_capture
        assert [c["call_id"] for c in srv.volte_call_chain(path, ue_ip=g.VOLTE_UE["rx"])["calls"]] == [g.VOLTE_CALL["rx"]]
        assert srv.volte_call_chain(path, call_id=g.VOLTE_CALL["ok"])["total_matched"] == 1
        page = srv.volte_call_chain(path, limit=1, offset=2)
        assert page["calls"][0]["call_id"] == g.VOLTE_CALL["bearer"] and "next_offset" not in page

    def test_frames_match_raw_tshark(self, volte_capture):
        srv, path = volte_capture
        raw = subprocess.run([TSHARK, "-r", path, "-Y", "gtpv2.message_type == 96 && gtpv2.cause == 73",
                              "-T", "fields", "-e", "frame.number"], capture_output=True, text=True).stdout.split()
        (bearer,) = srv.volte_call_chain(path, call_id=g.VOLTE_CALL["bearer"])["calls"]
        link = next(lk for lk in bearer["links"] if lk["link"] == "gtp_create_bearer")
        assert sorted(str(leg["answer_frame"]) for leg in link["legs"]) == sorted(raw)

    def test_redaction_hides_the_ue_address(self, volte_capture):
        srv, path = volte_capture
        text = str(srv.volte_call_chain(path, redact="ids+ips"))
        assert g.VOLTE_UE["ok"] not in text

    @pytest.mark.parametrize("args", [{"ue_ip": "not-an-ip"}, {"window_s": 0}, {"call_id": 'a"b'},
                                      {"filter": "frame.number =="}])
    def test_bad_arguments(self, volte_capture, args):
        srv, path = volte_capture
        out = srv.volte_call_chain(path, **args)
        assert out["error"]["type"] in ("invalid_argument", "invalid_filter")
