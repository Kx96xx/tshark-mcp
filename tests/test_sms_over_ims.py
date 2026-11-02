"""sms_over_ims: SIP MESSAGE with 3GPP SMS, RP-ACK/RP-ERROR pairing and verdicts."""

from __future__ import annotations

import json
from pathlib import Path

from tshark_mcp import sms
from tshark_mcp.limits import Limits

from . import pcapgen
from .conftest import requires_tshark


def _sms(pcap_dir: Path) -> str:
    return str(pcap_dir / "ims" / "ims_sms.pcap")


def _by_call(out: dict) -> dict[str, dict]:
    return {r["call_id"].split("@")[0]: r for r in out["messages"]}


class TestHelpers:
    def test_rp_header_and_status_report(self):
        assert sms.rp_header(bytes([0x05, 0x07, 0x01, 0x15])) == {"type": 5, "mr": 7, "cause": 21}
        assert sms.rp_header(bytes([0x03, 0x11])) == {"type": 3, "mr": 17}
        assert sms.rp_header(b"\x00") == {}
        tpdu = pcapgen._tp_status_report(9, pcapgen.SMS_PEER, 0x46)
        assert sms.status_report(tpdu) == {"tp_mr": 9, "tp_ra": pcapgen.SMS_PEER, "tp_st": 0x46}
        assert sms.status_report(pcapgen._tp_deliver(pcapgen.SMS_PEER)) is None
        assert sms.tp_status_name(0x46) == "validity period expired"
        assert sms.tp_status_name(0x5A) == "permanent error, SC stopped trying"

    def test_pdu_from_raw_body_when_undecoded(self):
        rec = {"sip.Content-Type": "application/vnd.3gpp.sms", "sip.msg_body": "05:07:01:16"}
        assert sms._pdu(rec) == {"rp_type": 5, "mr": 7, "cause": 22, "body_present": True}
        assert sms._pdu({"sip.Content-Type": "text/plain", "sip.msg_body": "68:69"}) is None

    def test_matches(self):
        row = {"from": "sip:+15550100201@ims.example.com", "to": "sip:+15550100900@ims.example.com",
               "tpdu": {"tp_da": "15550100300"}, "ue_registration": {"impu": "sip:001010000000201@ims.example.com"}}
        assert sms.matches(row, "15550100300", None) and sms.matches(row, None, "001010000000201")
        assert not sms.matches(row, "15550100999", None)


@requires_tshark
class TestSmsOverIms:
    def test_verdicts(self, server, pcap_dir):
        out = server.sms_over_ims(_sms(pcap_dir))
        rows = _by_call(out)
        assert {k: (r.get("direction"), r["verdict"]) for k, r in rows.items()} == {
            "mo1": ("MO", "accepted"), "sr1": ("MT", "delivered"), "mo2": ("MO", "rejected"),
            "mo3": ("MO", "ack_not_delivered"), "mt4": ("MT", "delivered"), "mt5": ("MT", "not_registered_for_sms"),
            "mt6": ("MT", "rejected"), "mo7": ("MO", "no_rp_ack"), "orphan8": (None, "orphan_ack"),
            "nobody10": (None, "rp_unknown"), "mo11": ("MO", "in_progress"),
        }
        assert out["summary"] == {"mo": 5, "mt": 4, "other_messages": 1, "registrations_seen": 2, "by_verdict": {
            "accepted": 1, "delivered": 2, "rejected": 2, "ack_not_delivered": 1, "not_registered_for_sms": 1,
            "no_rp_ack": 1, "orphan_ack": 1, "rp_unknown": 1, "in_progress": 1}}
        assert all("reasons" in r for r in out["messages"])

    def test_mo_with_ack_and_status_report(self, server, pcap_dir):
        rows = _by_call(server.sms_over_ims(_sms(pcap_dir)))
        mo = rows["mo1"]
        assert (mo["frame"], mo["rp_mr"], mo["smsc_digits"], mo["sip_response"], mo["legs"]) == (5, 5, pcapgen.SMSC, 202, 2)
        assert mo["tpdu"]["type"] == "SMS-SUBMIT" and mo["tpdu"]["tp_mr"] == 9 and mo["tpdu"]["status_report_requested"]
        assert mo["tpdu"]["tp_da"] == pcapgen.SMS_PEER and "text" not in json.dumps(mo["tpdu"])
        ack = mo["ack"]
        assert (ack["frame"], ack["rp_message"], ack["sip_response"], ack["tpdu"]["type"]) == (
            9, "RP-ACK (network to MS)", 200, "SMS-SUBMIT-REPORT")
        assert mo["status_report"] == {"frame": 11, "time": rows["sr1"]["time"], "tp_st": 0,
                                       "status": "received by the recipient"}
        assert rows["sr1"]["status_report_of_frame"] == 5 and rows["sr1"]["tpdu"]["type"] == "SMS-STATUS-REPORT"
        assert mo["ue_registration"] == {"impu": f"sip:{pcapgen.SMS_A}@{pcapgen.IMS_DOMAIN}", "first_frame": 1,
                                         "verdict": "registered", "smsip": True}
        assert mo["reasons"] == []

    def test_failures_are_explained(self, server, pcap_dir):
        rows = _by_call(server.sms_over_ims(_sms(pcap_dir)))
        assert rows["mo2"]["ack"]["rp_cause"] == 21 and "Short message transfer rejected" in rows["mo2"]["reasons"][0]
        mo3 = rows["mo3"]
        assert "coded MS to network (type 2) although the network sends it" in mo3["reasons"][0]
        assert mo3["ack"]["sip_response"] == 408 and mo3["ack"]["retransmissions"] == 2
        assert "answered 408" in mo3["reasons"][1]
        assert rows["mt4"]["ack"]["frame"] == 27  # answered from the IMSI-based identity of the same registration
        mt5 = rows["mt5"]
        assert mt5["ue_registration"]["smsip"] is False and "488" in mt5["reasons"][0]
        assert "without +g.3gpp.smsip" in mt5["reasons"][1]
        assert rows["mt6"]["ack"]["rp_cause_name"] == "Memory capacity exceeded"
        assert "no RP-ACK or RP-ERROR with RP-MR 50" in rows["mo7"]["reasons"][0]
        assert "body is not in the capture" in rows["nobody10"]["reasons"][0]
        assert "capture ends 5.0 s after it" in rows["mo11"]["reasons"][0]

    def test_filters_paging_and_lint(self, server, pcap_dir):
        by_number = server.sms_over_ims(_sms(pcap_dir), number=pcapgen.SMS_B_MSISDN)
        assert [r["call_id"].split("@")[0] for r in by_number["messages"]] == ["mt5"]
        by_imsi = server.sms_over_ims(_sms(pcap_dir), imsi=pcapgen.SMS_A)
        assert by_imsi["count"] == 8
        page = server.sms_over_ims(_sms(pcap_dir), limit=4, offset=4)
        assert page["returned"] == 4 and page["next_offset"] == 8 and page["total_matched"] == 11
        assert server.sms_over_ims(_sms(pcap_dir), number="12ab")["error"]["type"] == "invalid_argument"
        assert server.sms_over_ims(_ims_register(pcap_dir))["count"] == 0

    def test_untrusted_and_redaction(self, server, pcap_dir):
        out = server.sms_over_ims(_sms(pcap_dir), redact="ids")
        assert {"from", "to", "request_uri"} <= set(out["untrusted_text_fields"])
        text = json.dumps(out["messages"])
        for value in (pcapgen.SMS_A, pcapgen.SMS_A_MSISDN, pcapgen.SMS_PEER, pcapgen.SMSC):
            assert value not in text
        assert _by_call(out)["mo3"]["verdict"] == "ack_not_delivered"

    def test_output_cap_pages_rows(self, configure, pcap_dir):
        srv = configure(Limits(max_output_bytes=4096))
        out = srv.sms_over_ims(_sms(pcap_dir))
        assert out["truncated"] and out["returned"] < 11 and out["next_offset"] == out["returned"]


def _ims_register(pcap_dir: Path) -> str:
    return str(pcap_dir / "ims" / "ims_register.pcap")
