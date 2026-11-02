"""ims_registration: IMS REGISTER flows per public identity."""

from __future__ import annotations

import json
from pathlib import Path

from tshark_mcp import ims
from tshark_mcp.limits import Limits

from . import pcapgen
from .conftest import requires_tshark


def _ims(pcap_dir: Path, name: str = "ims_register.pcap") -> str:
    return str(pcap_dir / "ims" / name)


def _by_imsi(out: dict) -> dict[str, dict]:
    return {ims.user_of(r["impu"]): r for r in out["registrations"]}


class TestHelpers:
    def test_contacts_and_feature_tags(self):
        text = ('<sip:192.0.2.9:5060>;expires=600;+g.3gpp.smsip;'
                '+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";'
                '+sip.instance="<urn:gsma:imei:00123456-000001-0>";video, <sip:192.0.2.10>;expires=0')
        (first, second) = ims.contacts(text)
        assert first["uri"] == "sip:192.0.2.9:5060" and first["params"]["expires"] == "600"
        assert ims.feature_tags(first["params"]) == [
            "+g.3gpp.smsip", "+g.3gpp.icsi-ref=urn:urn-7:3gpp-service.ims.icsi.mmtel", "+sip.instance", "video"]
        assert second == {"uri": "sip:192.0.2.10", "params": {"expires": "0"}}

    def test_user_of_and_matches(self):
        assert ims.user_of("sip:+15550100123@ims.example.com;user=phone") == "15550100123"
        assert ims.user_of("tel:+15550100123") == "15550100123"
        assert ims.user_of('"001010000000101@ims.example.com"') == "001010000000101"
        row = {"impu": "sip:001010000000101@ims.example.com", "associated_uris": ["tel:+15550100123"]}
        assert ims.matches(row, "+15550100123", None) and ims.matches(row, None, "001010000000101")
        assert not ims.matches(row, "15550100999", None)

    def test_esp_spi_from_payload_when_undissected(self):
        line = "\t".join(["7", "1700000000.5", "192.0.2.1", "192.0.2.2", "", "", "", "0000115c00000001"])
        rows = [{"verdict": "failed", "_esp_probe": {"ue_ip": "192.0.2.1", "pcscf_ip": "192.0.2.2", "after": 1.0,
                                                    "frame": 5, "final": True,
                                                    "pcscf_spis": {"spi-c": 4443, "spi-s": 4444}}}]
        ims.attach_esp(rows, line + "\n")
        assert rows[0]["esp_after_challenge"]["spis"] == [4444] and "_esp_probe" not in rows[0]
        assert "not accepting traffic on the negotiated SA" in rows[0]["reasons"][0]
        assert ims.esp_filter({"192.0.2.1", "2001:db8::1"}) == (
            "(ip.proto == 50 && ip.addr in {192.0.2.1}) || (ipv6.nxt == 50 && ipv6.addr in {2001:db8::1})")

    def test_wrong_spi_is_named(self):
        line = "\t".join(["7", "1700000000.5", "192.0.2.1", "192.0.2.2", "", "", "0x00000063", ""])
        rows = [{"_esp_probe": {"ue_ip": "192.0.2.1", "pcscf_ip": "192.0.2.2", "after": 1.0, "frame": 5,
                                "final": True, "pcscf_spis": {"spi-c": 4443, "spi-s": 4444}}}]
        ims.attach_esp(rows, line + "\n")
        assert "SPI 99, not one the P-CSCF offered" in rows[0]["reasons"][0]


@requires_tshark
class TestImsRegistration:
    def test_verdicts(self, server, pcap_dir):
        out = server.ims_registration(_ims(pcap_dir))
        rows = _by_imsi(out)
        assert {k: r["verdict"] for k, r in rows.items()} == {
            pcapgen.IMS_OK: "registered", pcapgen.IMS_LOOP: "challenge-loop", pcapgen.IMS_403: "failed",
            pcapgen.IMS_503: "failed", pcapgen.IMS_EXPIRED: "expired", pcapgen.IMS_ESP: "failed",
            pcapgen.IMS_DEREG: "deregistered", pcapgen.IMS_SILENT: "failed",
        }
        assert out["summary"] == {"users": 8, "third_party_registers": 2, "by_verdict": {
            "registered": 1, "challenge-loop": 1, "failed": 4, "expired": 1, "deregistered": 1}}
        assert "403 at frame 20: Forbidden" in rows[pcapgen.IMS_403]["reasons"][0]
        assert rows[pcapgen.IMS_503]["reasons"][0].endswith("Retry-After 120 s")
        assert rows[pcapgen.IMS_503]["transactions"][0]["retry_after"] == 120
        assert "AUTS" in rows[pcapgen.IMS_LOOP]["reasons"][1]
        assert [t["kind"] for t in rows[pcapgen.IMS_LOOP]["transactions"]] == ["initial", "authenticated", "resync"]
        silent = rows[pcapgen.IMS_SILENT]
        assert silent["transactions"][0]["no_final_response"] and silent["transactions"][0]["retransmissions"] == 2
        assert "no final response" in silent["reasons"][0]
        assert "not refreshed" in rows[pcapgen.IMS_EXPIRED]["reasons"][0]
        assert rows[pcapgen.IMS_DEREG]["transactions"][-1]["kind"] == "de-registration"

    def test_full_registration(self, server, pcap_dir):
        row = _by_imsi(server.ims_registration(_ims(pcap_dir)))[pcapgen.IMS_OK]
        first, auth, refresh = row["transactions"]
        assert (first["kind"], first["status"], first["frame"], first["status_frame"]) == ("initial", 401, 1, 4)
        assert first["challenge_algorithm"] == "AKAv1-MD5" and first["legs"] == 2 and first["copies"] == 1
        assert "retransmissions" not in first
        assert (auth["kind"], auth["status"], auth["granted_expires"], auth["retransmissions"]) == (
            "authenticated", 200, 3600, 1)
        assert auth["auth"] == "challenge response" and "call_id" not in auth
        assert refresh["kind"] == "re-registration" and row["time_to_register_ms"] == 1600.0
        assert row["impi"] == f"{pcapgen.IMS_OK}@{pcapgen.IMS_DOMAIN}"
        assert row["associated_uris"] == [f"sip:+{pcapgen.IMS_MSISDN}@{pcapgen.IMS_DOMAIN}", f"tel:+{pcapgen.IMS_MSISDN}"]
        assert row["service_route"] == [f"sip:orig@scscf.{pcapgen.IMS_DOMAIN};lr"]
        assert row["smsip"] and row["mmtel"] and "+sip.instance" in row["feature_tags"]
        assert row["sec_agree"] == ["ipsec-3gpp alg=hmac-sha-1-96 ealg=null"]
        assert [(t["application_server"].split(".")[0], t["status"]) for t in row["third_party"]] == [
            ("sip:as1", 200), ("sip:as2", 500)]
        assert "third-party REGISTER to sip:as2" in row["reasons"][0]

    def test_no_auth_material_in_result(self, server, pcap_dir):
        text = json.dumps(server.ims_registration(_ims(pcap_dir)))
        for secret in ("cmFuZGF1dG4=", "00112233445566778899aabbccddeeff", "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
                       "QVVUU1RPS0VO", "urn:gsma:imei"):
            assert secret not in text

    def test_expired_without_smsip_or_mmtel(self, server, pcap_dir):
        row = _by_imsi(server.ims_registration(_ims(pcap_dir), imsi=pcapgen.IMS_EXPIRED))[pcapgen.IMS_EXPIRED]
        assert row["smsip"] is False and row["mmtel"] is False
        assert any("+g.3gpp.smsip" in r for r in row["reasons"]) and any("MMTel" in r for r in row["reasons"])

    def test_esp_after_challenge(self, server, pcap_dir):
        row = _by_imsi(server.ims_registration(_ims(pcap_dir)))[pcapgen.IMS_ESP]
        assert row["esp_after_challenge"] == {"packets_from_ue": 3, "packets_to_ue": 0, "first_frame": 29,
                                              "last_frame": 31, "spis": [pcapgen.PCSCF_SPI_S],
                                              "pcscf_offered_spis": [pcapgen.PCSCF_SPI_C, pcapgen.PCSCF_SPI_S]}
        assert "not accepting traffic on the negotiated SA" in row["reasons"][1]

    def test_filters_paging_and_lint(self, server, pcap_dir):
        by_tel = server.ims_registration(_ims(pcap_dir), impu=f"tel:+{pcapgen.IMS_MSISDN}")
        assert [ims.user_of(r["impu"]) for r in by_tel["registrations"]] == [pcapgen.IMS_OK]
        assert server.ims_registration(_ims(pcap_dir), imsi="001010999999999")["count"] == 0
        page = server.ims_registration(_ims(pcap_dir), limit=3, offset=3)
        assert page["returned"] == 3 and page["next_offset"] == 6 and page["total_matched"] == 8
        assert server.ims_registration(_ims(pcap_dir), impu='a"b')["error"]["type"] == "invalid_argument"
        assert server.ims_registration(_ims(pcap_dir), imsi="12ab")["error"]["type"] == "invalid_argument"
        flt = server.ims_registration(_ims(pcap_dir), filter=f"ip.addr == {pcapgen.UE_IMS[pcapgen.IMS_403]}")
        assert [r["verdict"] for r in flt["registrations"]] == ["failed"]

    def test_untrusted_and_redaction(self, server, pcap_dir):
        out = server.ims_registration(_ims(pcap_dir), imsi=pcapgen.IMS_OK, redact="ids")
        assert {"impu", "impi", "associated_uris"} <= set(out["untrusted_text_fields"])
        text = json.dumps(out["registrations"])
        assert pcapgen.IMS_OK not in text and pcapgen.IMS_MSISDN not in text
        assert out["registrations"][0]["verdict"] == "registered"

    def test_output_cap_pages_rows(self, configure, pcap_dir):
        srv = configure(Limits(max_output_bytes=4096))
        out = srv.ims_registration(_ims(pcap_dir))
        assert out["truncated"] and out["returned"] < 8 and out["next_offset"] == out["returned"]
        assert len(json.dumps(out)) <= 4096 + 512

    def test_in_progress_near_capture_end(self):
        tx = {"call_id": "c1", "cseq": 1, "time_epoch": 100.0, "frame": 1, "from": "sip:u@example.com",
              "to": "sip:u@example.com", "request_uri": "sip:example.com", "third_party": False, "has_request": True,
              "requested_expires": 600, "auts": False, "auth_response": False, "feature_tags": [],
              "status": 401, "status_frame": 2, "status_time_epoch": 100.1}
        near = ims._registration({"impu": "sip:u@example.com", "own": [dict(tx)], "third": []}, 110.0)
        far = ims._registration({"impu": "sip:u@example.com", "own": [dict(tx)], "third": []}, 200.0)
        assert near["verdict"] == "in_progress" and "before the capture ends" in near["reasons"][0]
        assert far["verdict"] == "failed"
