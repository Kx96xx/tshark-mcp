"""sms_delivery: MAP and SGs SMS chains with an outcome per message, content-free."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tshark_mcp import smsdelivery

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark


def _map_row(frame: int, t: float, **kw) -> dict:
    row = {f: None for f in ("otid", "dtid", "p_abort", "component", "local", "failure_cause", "absent_diag", "imsi",
                             "msisdn", "sgs", "service_indicator", "sgs_cause", "cp", "cp_cause", "rp", "rp_mr",
                             "rp_cause", "tp_mti", "tp_mr")}
    row.update(frame=frame, time=t, src="a", dst="b")
    row.update(kw)
    return row


def test_unanswered_forward_sm_ages_from_in_progress_to_no_response():
    rows = [_map_row(1, 0.0, otid="01", component=1, local=44, imsi="001010000000999")]
    (att,) = smsdelivery.map_attempts(rows, lambda *a: None, capture_end=5.0)
    assert att["verdict"] == "in_progress"
    (att,) = smsdelivery.map_attempts(rows, lambda *a: None, capture_end=50.0)
    assert att["verdict"] == "no_response" and att["direction"] == "mt"


def test_tcap_abort_rejects():
    rows = [_map_row(1, 0.0, otid="01", component=1, local=46, imsi="001010000000999"),
            _map_row(2, 0.1, dtid="01", p_abort=1)]
    (att,) = smsdelivery.map_attempts(rows, lambda *a: None, capture_end=1.0)
    assert att["verdict"] == "rejected" and att["direction"] == "mo" and "tcap abort" in att["reasons"][0]


@pytest.fixture
def smsd(configure, pcap_dir: Path):
    srv = configure()
    return srv, str(pcap_dir / "smsd" / "sms_delivery.pcap")


@requires_tshark
class TestSmsDelivery:
    def test_six_attempts(self, smsd):
        srv, path = smsd
        out = srv.sms_delivery(path)
        assert "error" not in out, out
        rows = out["attempts"]
        assert [(a["path"], a["direction"], a["verdict"]) for a in rows] == [
            ("map", "mt", "delivered"), ("map", "mt", "absent_subscriber"), ("map", "mt", "rejected"),
            ("sgs", "mt", "delivered"), ("sgs", "mt", "paging_failed"), ("sgs", "mo", "rejected")]
        ok, absent, full, sgs_ok, paging, mo = rows
        assert [s["step"] for s in ok["steps"]] == ["sendRoutingInfoForSM", "mt-forwardSM"]
        assert ok["imsi"] == g.SMS_IMSI["map_ok"] and ok["msisdn"] == g.SMS_MSISDN["map_ok"]
        assert ok["steps"][0]["routed_to_imsi"] == g.SMS_IMSI["map_ok"] and ok["steps"][1]["rtt_ms"] == 400.0
        assert absent["steps"][0]["error_code"] == 6 and absent["steps"][0]["explained"]["name"]
        assert absent["steps"][1]["step"] == "reportSM-DeliveryStatus" and "message waiting" in absent["reasons"][1]
        assert full["steps"][1]["delivery_failure_cause"] == "memoryCapacityExceeded" and full["ref"]
        assert [s.get("rp") for s in sgs_ok["steps"]][2:5] == ["RP-DATA (network to MS)", None, "RP-ACK (MS to network)"]
        assert sgs_ok["steps"][2]["tpdu"] == "SMS-DELIVER" and sgs_ok["steps"][2]["rp_mr"] == 7
        assert paging["steps"][1]["sgs_cause"] == 6 and "29.118" in paging["ref"]
        assert mo["steps"][0]["tpdu"] == "SMS-SUBMIT" and mo["steps"][2]["rp_cause"] == 21 and "24.011" in mo["ref"]
        assert out["summary"] == {"attempts": 6, "verdicts": {"delivered": 2, "absent_subscriber": 1, "rejected": 2,
                                                              "paging_failed": 1}, "paths": {"map": 3, "sgs": 3}}

    def test_content_free(self, smsd):
        srv, path = smsd
        text = str(srv.sms_delivery(path))
        # The other party's number (TP-DA of the MO submit, TP-OA of the deliveries) never appears.
        assert g.MSISDN_OTHER not in text and g.SMSC not in text

    def test_selectors_and_redaction(self, smsd):
        srv, path = smsd
        assert srv.sms_delivery(path, imsi=g.SMS_IMSI["sgs_mo"])["attempts"][0]["direction"] == "mo"
        assert srv.sms_delivery(path, msisdn=g.SMS_MSISDN["map_full"])["total_matched"] == 1
        assert srv.sms_delivery(path, via="map")["total_matched"] == 3
        text = str(srv.sms_delivery(path, redact="ids"))
        assert g.SMS_IMSI["map_ok"] not in text and g.SMS_MSISDN["map_ok"] not in text

    def test_counts_match_raw_tshark(self, smsd):
        srv, path = smsd
        raw = subprocess.run([TSHARK, "-r", path, "-Y", "gsm_map || sgsap", "-T", "fields", "-e", "frame.number"],
                             capture_output=True, text=True).stdout.split()
        out = srv.sms_delivery(path)
        assert sum(len(a["steps"]) for a in out["attempts"]) + 6 == len(raw) == 24  # the 6 MAP answers ride on their steps

    @pytest.mark.parametrize("args", [{"imsi": "12ab"}, {"msisdn": "x"}, {"via": "ims"}, {"filter": "frame.number =="}])
    def test_bad_arguments(self, smsd, args):
        srv, path = smsd
        out = srv.sms_delivery(path, **args)
        assert out["error"]["type"] in ("invalid_argument", "invalid_filter")
