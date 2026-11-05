"""diameter_avps key digests for Gy/Ro, Rx, Cx, Sh and S13, and what they never return."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tshark_mcp import avps

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark


def test_bare_names_and_spec_copy():
    assert avps.bare("3GPP-SIP-Authenticate") == "SIP-Authenticate"
    assert avps.bare("3GPP-SGSN-MCC-MNC") == "3GPP-SGSN-MCC-MNC"  # a real AVP name keeps its prefix
    assert avps.bare("avp-872") == "Reporting-Reason"
    tree = {"3GPP-SIP-Auth-Data-Item": [{"3GPP-SIP-Authentication-Scheme": "Digest-AKAv1-MD5"}]}
    assert avps.spec_names(tree) == {"SIP-Auth-Data-Item": [{"SIP-Authentication-Scheme": "Digest-AKAv1-MD5"}]}


def test_sh_user_data_keeps_size_and_element_names_only():
    xml = '<?xml version="1.0"?><!-- c --><Sh-Data><A><B>x</B></A><C/><A/></Sh-Data>'
    assert avps.sh_user_data(xml.encode().hex(":")) == {"bytes": len(xml), "root": "Sh-Data", "elements": ["A", "C"]}
    assert avps.sh_user_data("not xml at all") == {"bytes": 14}


def test_digest_is_picked_by_application_id_only():
    tree = {"CC-Request-Type": "INITIAL_REQUEST (1)", "Result-Code": 2001}
    assert "gy" in avps.key_view(tree, 4)
    assert "gy" not in avps.key_view(tree, 16777238) and "gy" not in avps.key_view(tree)


@pytest.fixture
def apps(configure, pcap_dir: Path):
    srv = configure()
    return srv, str(pcap_dir / "ims" / "diameter_apps.pcap")


def _tx(out: dict, request: str) -> dict:
    return next(t for t in out["transactions"] if t["request"] == request)


@requires_tshark
class TestDigests:
    def test_gy_mscc(self, apps):
        srv, path = apps
        ccr = _tx(srv.diameter_avps(path, command_code=272), "CCR")
        req = ccr["request_avps"]["gy"]
        assert req["request_type"] == "UPDATE_REQUEST (2)" and req["request_number"] == 3
        assert req["subscription_ids"] == [{"type": "END_USER_E164 (0)", "data": g.MSISDN}]
        # The empty Requested-Service-Unit asks for quota; tshark leaves an empty grouped AVP unnamed.
        assert req["mscc"] == [{"rating_group": 10, "requested": {},
                                "used": {"total_octets": 1000, "reporting_reason": "QUOTA_EXHAUSTED (3)"}}]
        (mscc,) = ccr["answer_avps"]["gy"]["mscc"]
        assert mscc["granted"] == {"total_octets": 0} and mscc["final_unit"] == {"action": "TERMINATE (0)"}
        assert mscc["validity_time_s"] == 600 and mscc["quota_holding_time_s"] == 30
        assert mscc["result"]["code"] == 4012 and mscc["result"]["name"] == "DIAMETER_CREDIT_LIMIT_REACHED"
        # Failed codes carry cause_lookup's meaning and reference; successes do not.
        assert mscc["result"]["explained"]["ref"].startswith("RFC 6733")
        assert "explained" not in ccr["answer_avps"]["gy"]["results"][0]

    def test_rx_media_and_experimental_result(self, apps):
        srv, path = apps
        aar = _tx(srv.diameter_avps(path), "AAR")
        rx = aar["request_avps"]["rx"]
        assert rx["request_type"] == "INITIAL_REQUEST (0)" and rx["framed_ip_address"] == g.UE_IP
        assert rx["af_charging_identifier"] == "icid-rx-1"
        assert rx["media_components"] == [{"number": 1, "media_type": "AUDIO (0)", "flow_status": "ENABLED (2)",
                                           "max_requested_bandwidth_ul": 41000, "max_requested_bandwidth_dl": 41000,
                                           "codec_data": ["uplink"], "sub_components": 1, "flow_descriptions": 2}]
        assert rx["specific_actions"] == ["INDICATION_OF_LOSS_OF_BEARER (2)", "INDICATION_OF_RELEASE_OF_BEARER (4)"]
        (res,) = aar["answer_avps"]["rx"]["results"]
        assert (res["code"], res["avp"], res["name"]) == (5065, "Experimental-Result-Code", "IP-CAN_SESSION_NOT_AVAILABLE")
        assert aar["result"] == "IP-CAN_SESSION_NOT_AVAILABLE"
        assert res["explained"]["ref"] == "TS 29.214 5.5.3 (Experimental-Result-Code)" and res["explained"]["meaning"]

    def test_cx_scheme_only(self, apps):
        srv, path = apps
        out = srv.diameter_avps(path)
        uar, mar = _tx(out, "UAR"), _tx(out, "MAR")
        assert uar["request_avps"]["cx"]["user_authorization_type"] == "REGISTRATION (0)"
        assert uar["request_avps"]["cx"]["visited_network"] == g.IMS_DOMAIN
        assert uar["answer_avps"]["cx"]["server_capabilities"] == {"mandatory": 2, "optional": 1, "server_names": 0}
        assert uar["answer_avps"]["cx"]["results"][0]["name"] == "DIAMETER_FIRST_REGISTRATION"
        assert mar["answer_avps"]["cx"]["auth_items"] == {"count": 1, "schemes": ["Digest-AKAv1-MD5"]}
        assert mar["request_avps"]["cx"]["impi"] == g.APPS_IMPI

    def test_sh_and_s13(self, apps):
        srv, path = apps
        out = srv.diameter_avps(path)
        udr, ecr = _tx(out, "UDR"), _tx(out, "ECR")
        assert udr["request_avps"]["sh"]["data_reference"] == ["RepositoryData (0)", "InitialFilterCriteria (13)"]
        assert udr["answer_avps"]["sh"]["user_data"] == {"bytes": len(g.APPS_SH_DATA), "root": "Sh-Data",
                                                         "elements": ["RepositoryData", "Extension"]}
        assert ecr["request_avps"]["s13"] == {"imei": g.APPS_IMEI, "software_version": "01"}
        assert ecr["answer_avps"]["s13"]["equipment_status"] == "BLACKLISTED (1)"

    @pytest.mark.parametrize("detail", ["key", "full"])
    def test_authentication_material_and_sh_body_never_returned(self, apps, detail):
        srv, path = apps
        out = srv.diameter_avps(path, detail=detail)
        text = json.dumps(out)
        secret = g.APPS_SECRET.hex()
        assert secret not in text and g.APPS_SECRET.hex(":") not in text and "5a:5a:5a:5a" not in text
        assert "private-body-text" not in text
        if detail == "full":
            item = _tx(out, "MAR")["answer_avps"]
            item = next(v for k, v in item.items() if k.endswith("SIP-Auth-Data-Item"))
            assert {k: v for k, v in item.items() if v == avps.WITHHELD}.keys() >= {
                k for k in item if k.endswith(("Authenticate", "Authorization", "Key"))}

    def test_redaction_hides_the_imei(self, apps):
        srv, path = apps
        assert g.APPS_IMEI not in json.dumps(srv.diameter_avps(path, redact="ids"))

    def test_the_secret_is_in_the_capture(self, apps):
        # The capture really carries the material the tool withholds.
        _, path = apps
        out = subprocess.run([TSHARK, "-n", "-r", path, "-Y", "diameter.cmd.code == 303 && diameter.flags.request == 0",
                              "-T", "fields", "-e", "diameter.Confidentiality-Key"], capture_output=True, text=True,
                             check=True).stdout
        assert g.APPS_SECRET.hex() in out.replace(":", "")
