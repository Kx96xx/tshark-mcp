"""trace_subscriber: one merged timeline across Diameter, GTPv2-C, MAP and SIP."""

from __future__ import annotations

import pytest

from . import pcapgen
from .conftest import requires_tshark

pytestmark = requires_tshark


def _messages(result, protocol):
    return [r["message"] for r in result["timeline"] if r["protocol"] == protocol]


def test_timeline_merges_all_protocols_in_time_order(server, pcap_dir):
    result = server.trace_subscriber(str(pcap_dir / "all.pcap"), imsi=pcapgen.IMSI, msisdn=pcapgen.MSISDN)
    assert "error" not in result
    assert result["identity"] == {"imsi": pcapgen.IMSI, "msisdn": pcapgen.MSISDN}
    times = [r["time"] for r in result["timeline"]]
    assert times == sorted(times)
    assert result["by_protocol"] == {"diameter": 2, "gtpv2": 2, "sip": 1, "map": 3}

    # Diameter: only this IMSI's sessions, including the unanswered AIR and not the other IMSI's AIR.
    assert _messages(result, "diameter") == ["ULR/ULA", "AIR/-"]
    air = next(r for r in result["timeline"] if r["message"] == "AIR/-")
    assert air["unanswered"] is True and air["identity"] == pcapgen.IMSI

    # GTPv2: the Create Session for this IMSI plus the Delete Session found by following the PGW TEID.
    assert _messages(result, "gtpv2") == ["Create Session Request", "Delete Session Request"]
    csr = next(r for r in result["timeline"] if r["message"] == "Create Session Request")
    assert csr["result"] == "Request accepted" and csr["paa"] == pcapgen.UE_IP and csr["apn"] == pcapgen.APN
    dsr = next(r for r in result["timeline"] if r["message"] == "Delete Session Request")
    assert dsr["unanswered"] is True and dsr["teid"] == "0x0000c001"
    assert result["passes"]["gtpv2"]["control_teids"] == 2

    # SIP: the dialog whose P-Asserted-Identity carries the MSISDN; the other subscriber's REGISTER is absent.
    sip_rows = [r for r in result["timeline"] if r["protocol"] == "sip"]
    assert len(sip_rows) == 1
    assert sip_rows[0]["message"] == "INVITE -> 200" and sip_rows[0]["time_to_final_ms"] == pytest.approx(3500.0)
    assert sip_rows[0]["identity"] == f"<tel:+{pcapgen.MSISDN}>"

    # MAP: the whole updateLocation transaction (Begin and End) plus the unanswered mo-forwardSM Begin.
    assert _messages(result, "map") == ["begin updateLocation", "end updateLocation", "begin mo-forwardSM"]
    mo = next(r for r in result["timeline"] if r["message"] == "begin mo-forwardSM")
    assert mo["unanswered"] is True
    end = next(r for r in result["timeline"] if r["message"] == "end updateLocation")
    assert end["result"] == "returnResult" and end["rtt_ms"] == pytest.approx(200.0)

    # Three things went wrong for this subscriber: AIR, Delete Session, MO-ForwardSM never answered.
    assert result["failures"] == 3


def test_other_subscriber_sees_only_its_own_failures(server, pcap_dir):
    result = server.trace_subscriber(str(pcap_dir / "all.pcap"), imsi=pcapgen.IMSI_OTHER, msisdn=pcapgen.MSISDN_OTHER)
    assert _messages(result, "diameter") == ["AIR/AIA"]
    assert result["timeline"][0]["result"] == "DIAMETER_ERROR_USER_UNKNOWN" and result["timeline"][0]["failed"] is True
    gtp_rows = [r for r in result["timeline"] if r["protocol"] == "gtpv2"]
    assert len(gtp_rows) == 1 and gtp_rows[0]["result"] == "Missing or unknown APN" and gtp_rows[0]["failed"] is True
    sip_rows = [r for r in result["timeline"] if r["protocol"] == "sip"]
    assert len(sip_rows) == 1 and sip_rows[0]["message"] == "REGISTER -> 401" and sip_rows[0]["failed"] is True
    # The SRI-for-SM for this MSISDN sits in a segmented XUDT, so MAP cannot dissect it: nothing is invented.
    assert [r for r in result["timeline"] if r["protocol"] == "map"] == []


def test_msisdn_only_lookup(server, pcap_dir):
    result = server.trace_subscriber(str(pcap_dir / "all.pcap"), msisdn=pcapgen.MSISDN)
    protocols = {r["protocol"] for r in result["timeline"]}
    assert {"gtpv2", "sip", "map"} <= protocols
    assert result["identity"]["imsi"] is None


def test_unknown_subscriber_yields_empty_timeline(server, pcap_dir):
    result = server.trace_subscriber(str(pcap_dir / "all.pcap"), imsi="999990000000000")
    assert result["timeline"] == [] and result["count"] == 0 and result["failures"] == 0


def test_requires_an_identity(server, pcap_dir):
    result = server.trace_subscriber(str(pcap_dir / "all.pcap"))
    assert result["error"]["type"] == "invalid_argument"


def test_identity_must_be_digits(server, pcap_dir):
    result = server.trace_subscriber(str(pcap_dir / "all.pcap"), imsi='1" || frame')
    assert result["error"]["type"] == "invalid_argument"


def test_limit_truncates_timeline(server, pcap_dir):
    result = server.trace_subscriber(str(pcap_dir / "all.pcap"), imsi=pcapgen.IMSI, msisdn=pcapgen.MSISDN, limit=2)
    assert result["count"] == 2 and result["total_found"] == 8 and result["truncated"] is True
