"""gtp_ies: GTPv2-C information elements in a key view, with likely causes for rejects."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from tshark_mcp import gtpies

from . import pcapgen as g
from .conftest import requires_tshark

MME, SGW, PGW, ENB = g.MME_IP, g.SGW_IP, g.PGW_IP, "192.0.2.5"
SECRET_USER, SECRET_PASSWORD = "pcouser", "pcosecret"


def _plmn() -> bytes:
    """MCC 001, MNC 01 (TS 24.008 encoding)."""
    return bytes([0x00, 0xF1, 0x10])


def _pco() -> bytes:
    pap = bytes([1, 0]) + struct.pack("!H", 4 + 1 + len(SECRET_USER) + 1 + len(SECRET_PASSWORD))
    pap += bytes([len(SECRET_USER)]) + SECRET_USER.encode() + bytes([len(SECRET_PASSWORD)]) + SECRET_PASSWORD.encode()
    return (bytes([0x80]) + struct.pack("!HB", 0xC023, len(pap)) + pap
            + struct.pack("!HB", 0x000D, 0) + struct.pack("!HB", 0x000A, 0))


def _csr(seq: int, pdn_type: int, apn: str) -> bytes:
    uli = bytes([0x18]) + _plmn() + struct.pack("!H", 0x1234) + _plmn() + struct.pack("!I", 0x0012345)
    qos = bytes([0x09 << 2 | 0x01, 9]) + (1000).to_bytes(5, "big") * 2 + (0).to_bytes(5, "big") * 2
    return g._gtpv2(32, 0, seq, [
        g._ie(1, g._tbcd(g.IMSI)), g._ie(76, g._tbcd(g.MSISDN)), g._ie(75, g._tbcd("3534560012345601")),
        g._ie(86, uli), g._ie(83, _plmn()), g._ie(82, bytes([6])), g._ie(77, bytes([0x80, 0x00, 0x00])),
        g._ie(87, g._fteid(10, 0x1000 + seq, MME)), g._ie(87, g._fteid(7, 0, PGW), instance=1), g._apn_ie(apn),
        g._ie(128, bytes([0])), g._ie(99, bytes([pdn_type])),
        g._ie(79, bytes([pdn_type, 0]) + bytes(16) + bytes(4) if pdn_type == 3 else bytes([1]) + bytes(4)),
        g._ie(127, bytes([0])), g._ie(72, struct.pack("!II", 50000, 100000)), g._ie(78, _pco()),
        g._ie(93, g._ie(73, bytes([5])) + g._ie(80, qos) + g._ie(87, g._fteid(0, 0xE000 + seq, ENB))),
        g._ie(3, bytes([7])), g._ie(95, bytes([0x08, 0x00])), g._ie(114, bytes([0x40, 0])),
    ])


def gtp_ies_capture(tmp_path: Path) -> Path:
    """Create Session (IPv4v6) rejected 73 with the CS bit set and PDN Type as offending IE;
    Create Session for an unknown APN rejected 78; a Delete Session carrying EMM cause 15
    in its RAN/NAS cause, accepted."""
    t0 = 1_700_050_000.0
    frames = [
        (t0, g._udp_frame(MME, SGW, 2123, 2123, _csr(0x20, 3, "internet"))),
        (t0 + 0.1, g._udp_frame(SGW, MME, 2123, 2123, g._gtpv2(33, 0x1020, 0x20, [
            g._ie(2, bytes([73, 0x01, 99, 0, 0, 0])), g._ie(3, bytes([9]))]))),
        (t0 + 1.0, g._udp_frame(MME, SGW, 2123, 2123, _csr(0x21, 1, "nosuch.apn"))),
        (t0 + 1.1, g._udp_frame(SGW, MME, 2123, 2123, g._gtpv2(33, 0x1021, 0x21, [g._ie(2, bytes([78, 0]))]))),
        (t0 + 2.0, g._udp_frame(SGW, PGW, 2123, 2123, g._gtpv2(36, 0xC001, 0x22, [
            g._ie(73, bytes([5])), g._ie(172, bytes([0x20, 15]))]))),
        (t0 + 2.1, g._udp_frame(PGW, SGW, 2123, 2123, g._gtpv2(37, 0xA020, 0x22, [g._ie(2, bytes([16, 0]))]))),
    ]
    return g._frames_to_pcap(tmp_path / "gtp_ies.pcap", frames)


def test_ie_text_helpers():
    assert gtpies.ie_name("PDN Type: IPv4/IPv6") == "PDN Type"
    assert gtpies.ie_value_text("RAT Type: EUTRAN (6)") == "EUTRAN (6)"
    assert gtpies.ie_value_text("Charging ID: ") is None
    assert gtpies._named("RAT Type: EUTRAN", 6) == "EUTRAN (6)"


def test_likely_causes_from_the_request():
    req = {"apn": "internet", "pdn_type": "IPv4v6 (3)", "pco": ["PAP (credentials not shown)"]}
    assert any("IPv4-only" in r for r in gtpies.likely_causes(req, {"cause": {"value": 73}}))
    assert "'internet'" in gtpies.likely_causes(req, {"cause": {"value": 78}})[0]
    assert "PAP/CHAP" in gtpies.likely_causes(req, {"cause": {"value": 92}})[0]
    assert gtpies.likely_causes(req, {"cause": {"value": 16}}) == []
    relayed = gtpies.likely_causes(req, {"cause": {"value": 94, "source": "remote node: ..."}})
    assert "relayed" in relayed[-1]


@requires_tshark
class TestGtpIes:
    @pytest.fixture
    def capture(self, configure, tmp_path: Path):
        srv = configure(allow=[str(tmp_path)])
        return srv, str(gtp_ies_capture(tmp_path))

    def test_key_view_of_a_create_session(self, capture):
        srv, path = capture
        out = srv.gtp_ies(path, message="Create Session Request")
        assert out["total_matched"] == 2 and out["detail"] == "key"
        tx = out["transactions"][0]
        assert (tx["message"], tx["response"], tx["cause"]) == ("Create Session Request", "Create Session Response", 73)
        req = tx["request_ies"]
        assert (req["imsi"], req["msisdn"], req["mei"], req["apn"]) == (g.IMSI, g.MSISDN, "3534560012345601", "internet")
        assert req["pdn_type"] == "IPv4v6 (3)" and req["rat_type"] == "EUTRAN (6)" and req["serving_network"] == "001-01"
        assert req["uli"]["tai"] == {"plmn": "001-01", "tac": "0x1234"}
        assert req["uli"]["ecgi"]["eci"] == 0x12345 and req["uli"]["ecgi"]["enb_id"] == 0x123
        assert req["indication_flags"] == ["DAF"] and req["recovery"] == 7
        assert req["apn_ambr"] == {"up_kbps": 50000, "down_kbps": 100000}
        assert req["selection_mode"].endswith("(0)") and req["apn_restriction"].endswith("(0)")
        assert req["charging_characteristics"] == "0x0800"
        assert req["pco"] == ["PAP (credentials not shown)", "DNS Server IPv4 Address Request",
                              "IP address allocation via NAS signalling"]
        assert {f["interface"] for f in req["fteids"]} == {"S11 MME GTP-C", "S5/S8 PGW GTP-C"}
        bearer = req["bearer_contexts"][0]
        assert bearer["ebi"] == 5 and bearer["bearer_qos"]["qci"] == 9
        assert bearer["bearer_qos"]["arp"] == {"pl": 9, "pci": 0, "pvi": 1}
        assert bearer["fteids"][0]["interface"] == "S1-U eNodeB GTP-U"
        assert bearer.get("context") in (None, "Bearer Contexts to be Created")  # the label is tshark 4.6+
        cause = tx["response_ies"]["cause"]
        assert cause["value"] == 73 and cause["name"] == "No resources available"
        assert cause["offending_ie"] == "PDN Type (99)" and cause["source"].startswith("remote node")
        assert tx["response_ies"]["recovery"] == 9
        assert any("IPv4-only" in r for r in tx["likely_causes"])
        assert any("relayed" in r for r in tx["likely_causes"])
        second = out["transactions"][1]
        assert second["cause"] == 78 and "'nosuch.apn'" in second["likely_causes"][0]

    def test_pco_credentials_never_returned(self, capture):
        srv, path = capture
        for detail in ("key", "full"):
            text = json.dumps(srv.gtp_ies(path, detail=detail))
            assert SECRET_USER not in text and SECRET_PASSWORD not in text, detail

    def test_delete_session_ran_nas_cause_and_selectors(self, capture):
        srv, path = capture
        out = srv.gtp_ies(path, teid="0xc001")
        assert [t["message"] for t in out["transactions"]] == ["Delete Session Request"]
        ran = out["transactions"][0]["request_ies"]["ran_nas_cause"]
        assert ran == {"protocol": "EMM", "cause": 15, "cause_lookup": "cause_lookup(protocol='nas_emm', code=15)"}
        assert "likely_causes" not in out["transactions"][0]
        by_frame = srv.gtp_ies(path, frame=4)
        assert [t["answer_frame"] for t in by_frame["transactions"]] == [4]
        assert srv.gtp_ies(path, imsi=g.IMSI)["total_matched"] == 2
        assert srv.gtp_ies(path, message=36)["transactions"][0]["response"] == "Delete Session Response"
        assert srv.gtp_ies(path, message="delete session")["total_matched"] == 1

    def test_full_tree_is_capped(self, capture):
        srv, path = capture
        full = srv.gtp_ies(path, frame=1, detail="full")
        ies = full["transactions"][0]["request_ies"]
        assert any(k.startswith("Access Point Name") for k in ies)
        pco = next(v for k, v in ies.items() if k.startswith("Protocol Configuration Options"))  # "PCO: " or "PCO : "
        assert pco["options"][0].startswith("PAP")
        capped = srv.gtp_ies(path, frame=1, detail="full", max_ies=3)
        tx = capped["transactions"][0]
        assert sum(1 for k in tx["request_ies"] if ":" in k) == 3 and tx["request_ies_dropped"] > 0
        assert capped["truncated"] is True and "max_ies" in capped["truncated_reason"]

    @pytest.mark.parametrize("args", [{"detail": "all"}, {"frame": 0}, {"message": "Nosuch Request"},
                                      {"message": 300}, {"imsi": "12ab"}])
    def test_bad_arguments(self, capture, args):
        srv, path = capture
        assert srv.gtp_ies(path, **args)["error"]["type"] == "invalid_argument"
