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
            pcapgen.IMS_DEREG: "deregistered", pcapgen.IMS_SILENT: "failed", pcapgen.IMS_NOTIFY: "deregistered",
            pcapgen.IMS_SUB_403: "expired", pcapgen.IMS_SHORTENED: "expired", pcapgen.IMS_PROBATION: "deregistered",
        }
        assert out["summary"] == {"users": 12, "third_party_registers": 2, "by_verdict": {
            "registered": 1, "challenge-loop": 1, "failed": 4, "expired": 3, "deregistered": 3}}
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

    def test_network_initiated_deregistration(self, server, pcap_dir):
        rows = _by_imsi(server.ims_registration(_ims(pcap_dir)))
        row = rows[pcapgen.IMS_NOTIFY]
        assert row["verdict"] == "deregistered" and "registered_until" not in row
        assert row["reasons"][0].startswith("network-initiated de-registration: the reg-event NOTIFY at frame ")
        assert "contact event deactivated: the network de-registered the UE and expects it to re-register" in row["reasons"][0]
        assert [t["kind"] for t in row["transactions"]] == ["re-registration"]  # credentials without a challenge
        (n,) = row["reg_event_notifies"]
        assert (n["state"], n["contact_state"], n["contact_event"]) == ("terminated", "terminated", "deactivated")
        assert n["aor"] == f"sip:{pcapgen.IMS_NOTIFY}@{pcapgen.IMS_DOMAIN}" and n["frame"] and row["counts"]["reg_event_notifies"] == 1
        assert n["time"] > row["transactions"][0]["time"]
        # The active NOTIFY after IMS_OK's registration (two legs, one row) changes nothing.
        ok = rows[pcapgen.IMS_OK]
        assert ok["verdict"] == "registered" and ok["counts"]["reg_event_notifies"] == 1
        assert ok["reg_event_notifies"][0]["state"] == "active" and ok["reg_event_notifies"][0]["expires"] == 3600
        assert ok["reg_event_notifies"][0]["contact_event"] == "refreshed"
        # Users without a NOTIFY carry neither key.
        assert "reg_event_notifies" not in rows[pcapgen.IMS_403] and "reg_event_notifies" not in rows[pcapgen.IMS_403]["counts"]

    def test_reg_subscriptions(self, server, pcap_dir):
        rows = _by_imsi(server.ims_registration(_ims(pcap_dir)))
        ok = rows[pcapgen.IMS_OK]
        ue, pcscf = ok["reg_subscriptions"]
        assert (ue["subscriber"], ue["status"], ue["requested_expires"], ue["granted_expires"]) == ("ue", 200, 600000, 600000)
        assert "from" not in ue and ue["cseq"] == 5
        assert (pcscf["subscriber"], pcscf["from"], pcscf["status"]) == (
            "network", f"sip:pcscf.{pcapgen.IMS_DOMAIN}", 200)
        assert ok["counts"]["reg_subscriptions"] == 2 and ok["verdict"] == "registered"
        assert not any("SUBSCRIBE" in r for r in ok["reasons"])
        refused = rows[pcapgen.IMS_SUB_403]
        (sub,) = refused["reg_subscriptions"]
        assert (sub["subscriber"], sub["status"]) == ("ue", 403) and "granted_expires" not in sub
        assert refused["verdict"] == "expired"
        assert any(r.startswith("the UE's SUBSCRIBE to the reg event at frame ") and "refused with 403" in r
                   for r in refused["reasons"])
        # Its NOTIFY lists another device's contact (unregistered) first: its own active one is shown.
        (n,) = refused["reg_event_notifies"]
        assert (n["contact_state"], n["contact_event"], n["expires"], n["contact_matched"]) == (
            "active", "refreshed", 58, True)
        assert "reg_subscriptions" not in rows[pcapgen.IMS_403] and "reg_subscriptions" not in rows[pcapgen.IMS_403]["counts"]

    def test_notify_answers_and_contact_events(self, server, pcap_dir):
        rows = _by_imsi(server.ims_registration(_ims(pcap_dir)))
        # The earlier NOTIFY rows now carry the UE's answer.
        (n,) = rows[pcapgen.IMS_NOTIFY]["reg_event_notifies"]
        assert (n["status"], n["subscription_state"], n["contact_matched"]) == (200, "active;expires=600000", True)
        assert "no_final_response" not in n
        # Shortened to 30 s, nobody answered, no refresh: expired.
        short = rows[pcapgen.IMS_SHORTENED]
        (n,) = short["reg_event_notifies"]
        assert (n["contact_event"], n["expires"], n["no_final_response"]) == ("shortened", 30, True) and "status" not in n
        assert short["verdict"] == "expired"
        assert "shortened the registration to 30 s" in short["reasons"][0]
        assert "got no final response in the capture" in short["reasons"][1]
        assert "not refreshed before it lapsed" in short["reasons"][2]
        # Its own contact ends on probation while another device keeps the registration active.
        prob = rows[pcapgen.IMS_PROBATION]
        (n,) = prob["reg_event_notifies"]
        assert (n["state"], n["contact_state"], n["contact_event"], n["retry_after"], n["status"]) == (
            "active", "terminated", "probation", 60, 481)
        assert prob["verdict"] == "deregistered" and "registered_until" not in prob
        assert "the UE's own contact terminated" in prob["reasons"][0] and prob["reasons"][0].endswith("retry-after 60 s")
        assert "answered 481" in prob["reasons"][1]

    def test_reginfo_parser(self):
        body = ('<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="3" state="partial">'
                '<registration state="terminated" aor="tel:+15550100123" id="x"><contact event="rejected" '
                'id="1" state="terminated"><uri>sip:198.51.100.9</uri></contact></registration>'
                '<registration aor="sip:bob@example.org" id="y" state="active"><contact id="2" state="active" '
                'event="refreshed" expires="120"/></registration></reginfo>')
        regs = ims.reginfo(body)
        assert [(r["aor"], r["state"]) for r in regs] == [("tel:+15550100123", "terminated"), ("sip:bob@example.org", "active")]
        assert regs[0]["contacts"] == [{"state": "terminated", "event": "rejected", "uri": "sip:198.51.100.9"}]
        assert regs[1]["contacts"] == [{"state": "active", "event": "refreshed", "expires": 120}]
        assert ims.reginfo("not xml at all <registration") == []

    def test_reginfo_parser_uri_and_retry_after(self):
        body = ('<reginfo><registration aor="sip:a@example.org" state="active">'
                '<contact id="1" state="terminated" event="probation" retry-after="60"/>'
                '<uri>sip:stray@example.org</uri>'
                '<contact id="2" state="active" event="registered" expires="300">'
                '<uri> sip:198.51.100.7:5060;transport=udp </uri><uri>sip:second@example.org</uri></contact>'
                '</registration></reginfo>')
        (reg,) = ims.reginfo(body)
        # A self-closing contact takes no <uri>; a contact keeps its first.
        assert reg["contacts"] == [
            {"state": "terminated", "event": "probation", "retry_after": 60},
            {"state": "active", "event": "registered", "expires": 300, "uri": "sip:198.51.100.7:5060;transport=udp"}]

    def test_own_contact_decides(self):
        user = {"impu": "sip:u@example.org", "third": [],
                "own": [{"contact_uri": "sip:198.51.100.7:5060", "associated_uris": None}]}
        notify = {"time_epoch": 10.0, "frame": 5, "call_id": "c", "to": "sip:u@example.org", "status": 200,
                  "status_frame": 6, "registrations": [{"aor": "sip:u@example.org", "state": "active", "contacts": [
                      {"state": "terminated", "event": "deactivated", "uri": "sip:198.51.100.7:5060"},
                      {"state": "active", "event": "registered", "uri": "sip:198.51.100.8:5060", "expires": 60}]}]}
        (row,) = ims._notify_rows(user, [notify])
        assert row["_ends"] and row["contact_matched"] and row["contact_event"] == "deactivated"
        # Another device's contact ending does not end this UE's registration.
        notify["registrations"][0]["contacts"] = [
            {"state": "terminated", "event": "unregistered", "uri": "sip:198.51.100.9:5060"},
            {"state": "active", "event": "registered", "uri": "<sip:198.51.100.7:5060;ob>", "expires": 60}]
        (row,) = ims._notify_rows(user, [notify])
        assert not row["_ends"] and row["contact_state"] == "active" and row["contact_matched"]
        # No contact is the UE's: the registration state decides, as before.
        notify["registrations"][0]["contacts"][1]["uri"] = "sip:198.51.100.8:5060"
        (row,) = ims._notify_rows(user, [notify])
        assert not row["_ends"] and row["contact_state"] == "terminated" and "contact_matched" not in row
        notify["registrations"][0]["state"] = "terminated"
        (row,) = ims._notify_rows(user, [notify])
        assert row["_ends"]

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
        assert page["returned"] == 3 and page["next_offset"] == 6 and page["total_matched"] == 12
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
