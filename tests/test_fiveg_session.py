"""fiveg_session: 5G SA registration and PDU sessions across NGAP/NAS-5GS, PFCP and GTP-U (synthetic)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from . import pcapgen
from .conftest import requires_tshark

pytestmark = requires_tshark


@pytest.fixture(scope="module")
def ng_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("fiveg")
    pcapgen.write_fiveg_pcap(d / "fiveg.pcap")
    return d


@pytest.fixture
def srv(configure, ng_dir: Path):
    return configure(allow=[str(ng_dir)])


def _ues(out: dict) -> dict[int, dict]:
    return {u["ran_ue_ngap_id"]: u for u in out["ues"]}


def test_happy_registration_internet_session_and_vonr_without_5qi_1(srv, ng_dir: Path):
    out = srv.fiveg_session(str(ng_dir / "fiveg.pcap"))
    ue = _ues(out)[1]
    assert ue["supi"] == pcapgen.FIVEG_SUPI[1] and ue["amf_ue_ngap_id"] == 101
    assert ue["suci"] == {"mcc": "001", "mnc": "01", "routing_indicator": "0000", "protection_scheme": "null"}
    assert ue["registration"]["outcome"] == "accepted" and ue["registration"]["authentication"] == "answered"
    internet, ims = ue["pdu_sessions"]
    assert internet["dnn"] == "internet" and internet["outcome"] == "accepted" and internet["n3_consistent"] is True
    assert internet["ngap_setup"]["qos_flows"] == [{"qfi": 1, "five_qi": 9}]
    assert internet["ngap_setup"]["upf_teid"] == internet["pfcp"]["upf_teid"] == "0x00001001"
    assert internet["n3_traffic"]["uplink"]["packets"] == 3 and internet["n3_traffic"]["downlink"]["packets"] == 1
    assert [s["frame"] for s in internet["steps"]] == sorted(s["frame"] for s in internet["steps"])
    assert ims["dnn"] == "ims" and ue["vonr"]["five_qi_5"] and not ue["vonr"]["five_qi_1"]
    assert "PCF/SMF policy, not the RAN" in ue["vonr"]["assessment"]
    assert "first_failure" not in ue and ue["verdict"].startswith("registered (frame 4); 2 PDU session(s) up")


def test_registration_reject_after_authentication_failure(srv, ng_dir: Path):
    ue = _ues(srv.fiveg_session(str(ng_dir / "fiveg.pcap")))[2]
    ff = ue["first_failure"]
    assert ff["step"] == "registration" and ff["cause"] == 111 and ff["after"]["cause"] == 21
    assert ff["explained"]["ref"].startswith("TS 24.501")
    assert "after Authentication Failure" in ue["verdict"] and "frame 22" in ue["verdict"]


def test_pdu_session_reject_unknown_dnn(srv, ng_dir: Path):
    ue = _ues(srv.fiveg_session(str(ng_dir / "fiveg.pcap")))[3]
    (s,) = ue["pdu_sessions"]
    assert s["outcome"] == "rejected" and s["cause"] == 27 and s["dnn"] == "nope"
    assert ue["first_failure"]["step"] == "pdu_session_establishment"
    assert "PDU Session Establishment Reject" in ue["verdict"]


def test_pfcp_rejection_without_ngap_setup(srv, ng_dir: Path):
    ue = _ues(srv.fiveg_session(str(ng_dir / "fiveg.pcap")))[4]
    (s,) = ue["pdu_sessions"]
    assert s["pfcp"]["cause"] == 72 and "ngap_setup" not in s and s["outcome"] == "failed"
    assert ue["first_failure"]["step"] == "pfcp_establishment"
    assert "No established PFCP Association" in ue["verdict"]


def test_n3_teid_mismatch(srv, ng_dir: Path):
    out = srv.fiveg_session(str(ng_dir / "fiveg.pcap"))
    ue = _ues(out)[5]
    (s,) = ue["pdu_sessions"]
    assert s["n3_consistent"] is False and s["pfcp"]["upf_teid"] == "0x00005005"
    assert s["ngap_setup"]["upf_teid"] == "0x00005555" and ue["first_failure"]["step"] == "n3_tunnel"
    assert out["summary"]["n3_inconsistent"] == 1 and out["summary"]["ues"] == 5


def test_filters_and_arguments(srv, ng_dir: Path):
    path = str(ng_dir / "fiveg.pcap")
    assert [u["ran_ue_ngap_id"] for u in srv.fiveg_session(path, supi=pcapgen.FIVEG_SUPI[3])["ues"]] == [3]
    ims = srv.fiveg_session(path, dnn="ims")["ues"]
    assert len(ims) == 1 and [s["dnn"] for s in ims[0]["pdu_sessions"]] == ["ims"]
    assert {u["ran_ue_ngap_id"] for u in srv.fiveg_session(path, pdu_session_id=5)["ues"]} == {1, 3, 4, 5}
    assert srv.fiveg_session(path, pdu_session_id=300)["error"]["type"] == "invalid_argument"
    assert srv.fiveg_session(path, dnn="a b")["error"]["type"] == "invalid_argument"


def test_redaction_hides_supi_and_keeps_rows_joined(srv, ng_dir: Path):
    out = srv.fiveg_session(str(ng_dir / "fiveg.pcap"), redact="ids")
    text = json.dumps(out)
    assert all(supi not in text for supi in pcapgen.FIVEG_SUPI.values())
    # An IMSI-kind token once redact.kind_for_key maps supi (sbi_transactions); a 15-digit id token before that.
    assert all(u["supi"].startswith(("imsi:", "id:")) for u in out["ues"])


def test_capture_without_5g_has_no_rows(srv, configure, pcap_dir: Path):
    out = configure().fiveg_session(str(pcap_dir / "sip.pcap"))
    assert out["ues"] == [] and out["summary"]["ues"] == 0


def test_over_mcp_stdio(ng_dir: Path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async def go():
        params = StdioServerParameters(command=sys.executable,
                                       args=["-m", "tshark_mcp.server", "--toolsets", "all", "--allow-dir", str(ng_dir)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool("fiveg_session", {"path": str(ng_dir / "fiveg.pcap"), "dnn": "ims"})
                return res.structured_content
    out = asyncio.run(go())
    assert out["ues"][0]["vonr"]["five_qi_1"] is False
