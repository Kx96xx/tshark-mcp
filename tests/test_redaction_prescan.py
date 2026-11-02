"""Redaction pre-scan: UE addresses and short numbers are hidden in ``ids`` mode
even when the first tool to show them names them in no known field. Synthetic
captures, documentation-range addresses and test identities only."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from tshark_mcp import redact, server as server_module
from tshark_mcp.limits import Limits, ToolError
from tshark_mcp.redact import Redactor, prescan_pairs

from . import pcapgen
from .conftest import TSHARK, requires_tshark

KEY = b"test-key-0123456789abcdef"
RADIUS_HEX = pcapgen.MSISDN_RADIUS.encode().hex()


@pytest.fixture(scope="module")
def ue_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("uefirst")
    pcapgen.write_ue_first_pcap(directory / "ue_first.pcap")
    return directory


@pytest.fixture
def fresh(ue_dir: Path, tmp_path: Path):
    def _configure(mode: str = "ids", limits: Limits | None = None):
        server_module.configure([str(ue_dir)], limits=limits or Limits(), tshark=TSHARK,
                                log_path=tmp_path / "audit.jsonl", redact_mode=mode, redact_key=KEY)
        return server_module
    yield _configure
    server_module._STATE = None


@pytest.fixture
def prescan_runs(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Captures the pre-scan ran tshark on (told apart by its field aggregator)."""
    runs: list[Path] = []
    real = server_module._fields_core

    def counting(capture, display_filter, fields, max_matched, aggregator, *a, **kw):
        if aggregator == redact.PRESCAN_AGGREGATOR:
            runs.append(capture)
        return real(capture, display_filter, fields, max_matched, aggregator, *a, **kw)
    monkeypatch.setattr(server_module, "_fields_core", counting)
    return runs


def _shown(obj: Any) -> list[str]:
    text = json.dumps(obj)
    return [ip for ip in pcapgen.UE_ADDRESSES if ip in text]


# ------------------------------------------------------------------ parsing and seeding
class TestPairs:
    FIELDS = list(redact.PRESCAN_LAYOUT_FIELDS) + ["e212.imsi"]

    def _line(self, **cols: str) -> str:
        return "\t".join(cols.get(f.replace(".", "_").replace("-", "_"), "") for f in self.FIELDS)

    def test_gtpu_inner_header(self):
        a = redact.PRESCAN_AGGREGATOR
        line = self._line(frame_protocols="eth:ethertype:ip:udp:gtp:ip:udp:data",
                          ip_src=f"192.0.2.30{a}198.51.100.25", ip_dst=f"192.0.2.40{a}203.0.113.80")
        assert prescan_pairs([line], self.FIELDS) == [("inner_src", "198.51.100.25"), ("inner_src", "203.0.113.80")]

    def test_gtpv2_and_icmp_quotes_are_not_tunnels(self):
        a = redact.PRESCAN_AGGREGATOR
        gtpv2 = self._line(frame_protocols="eth:ethertype:ip:udp:gtp:gtpv2", ip_src="192.0.2.40")
        icmp = self._line(frame_protocols="eth:ethertype:ip:icmp:ip:udp:gtp:ip:udp",
                          ip_src=f"192.0.2.1{a}192.0.2.30{a}198.51.100.25")
        assert prescan_pairs([gtpv2, icmp], self.FIELDS) == []

    def test_sip_register_hosts(self):
        a = redact.PRESCAN_AGGREGATOR
        line = self._line(sip_CSeq_method="REGISTER", sip_contact_host="198.51.100.26",
                          sip_Via_sent_by_address=f"192.0.2.50{a}198.51.100.26", sip_Via_received="203.0.113.9")
        assert [v for _, v in prescan_pairs([line], self.FIELDS)] == ["198.51.100.26", "198.51.100.26", "203.0.113.9"]

    def test_sip_instance_contacts_only(self):
        a = redact.PRESCAN_AGGREGATOR
        line = self._line(sip_CSeq_method="INVITE", sip_contact_host=f"192.0.2.70{a}198.51.100.27",
                          sip_Contact=f"<sip:192.0.2.70>{a}<sip:198.51.100.27>;+sip.instance=\"<urn:x>\"")
        plain = self._line(sip_CSeq_method="INVITE", sip_contact_host="192.0.2.70", sip_Contact="<sip:192.0.2.70>")
        assert prescan_pairs([line, plain], self.FIELDS) == [("ue_ip", "198.51.100.27")]

    def test_value_fields_pass_through(self):
        line = self._line(e212_imsi=f"{pcapgen.IMSI}{redact.PRESCAN_AGGREGATOR}{pcapgen.IMSI_OTHER}")
        assert prescan_pairs([line], self.FIELDS) == [("e212.imsi", pcapgen.IMSI), ("e212.imsi", pcapgen.IMSI_OTHER)]


class TestSeed:
    def test_imsi_hint_wins_and_short_numbers_are_kept_out(self):
        r = Redactor(KEY)
        learnt, dropped = r.seed([("diameter.Subscription-Id-Data", pcapgen.IMSI), ("e212.imsi", pcapgen.IMSI),
                                  ("sip.to.user", "+1555"), ("sip.from.user", f"+{pcapgen.MSISDN}"),
                                  ("pfcp.ue_ip_addr_ipv4", "0.0.0.0"), ("ue_ip", "ue.example"),
                                  ("gtpv2.pdn_addr_and_prefix.ipv6", "2001:db8::7")])
        assert (learnt, dropped) == (3, 0)
        out, _ = r.apply({"a": pcapgen.IMSI, "b": pcapgen.MSISDN, "c": "1555", "d": "2001:db8::7 0.0.0.0"}, "ids")
        assert out["a"].startswith("imsi:") and out["b"].startswith("msisdn:")
        assert out["c"] == "1555" and out["d"].startswith("ip:") and out["d"].endswith(" 0.0.0.0")

    def test_a_full_table_is_reported(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(redact, "MAX_KNOWN", 1)
        learnt, dropped = Redactor(KEY).seed([("e212.imsi", pcapgen.IMSI), ("e212.imsi", pcapgen.IMSI_OTHER)])
        assert (learnt, dropped) == (1, 1)


# ------------------------------------------------------------------ through the server
@requires_tshark
def test_the_capture_shows_ue_addresses_bare(fresh, ue_dir: Path):
    """The tests below mean something only if conversations lists the UE addresses."""
    srv = fresh("off")
    raw = srv.conversations(path=str(ue_dir / "ue_first.pcap"))
    assert _shown(raw) == list(pcapgen.UE_ADDRESSES)


@requires_tshark
@pytest.mark.parametrize("tool", ["conversations", "pcap_info", "gtp_user_plane", "sip_dialogs"])
def test_first_call_hides_every_ue_address(fresh, ue_dir: Path, tool: str):
    srv = fresh("ids")
    out = getattr(srv, tool)(path=str(ue_dir / "ue_first.pcap"))
    assert "error" not in out
    assert out["redaction"]["complete"] is True
    assert not _shown(out), _shown(out)
    if tool == "conversations":
        text = json.dumps(out)
        assert pcapgen.PGW_IP in text and pcapgen.SMF_IP in text  # network addresses stay in ids mode
        # Both inner ends of a G-PDU count as UE addresses, so the server it talks to goes too.
        assert pcapgen.SERVER_IP not in text
        assert out["redaction"]["replaced"]["ip"] == len(pcapgen.UE_ADDRESSES) + 1


@requires_tshark
@pytest.mark.parametrize("mode", ["ids", "ids+ips"])
def test_first_call_hides_a_short_number_in_raw_bytes(fresh, ue_dir: Path, mode: str):
    srv = fresh(mode)
    out = srv.filter_packets(path=str(ue_dir / "ue_first.pcap"), display_filter="radius", fields=["udp.payload"])
    payload = out["packets"][0]["udp.payload"]
    assert RADIUS_HEX not in payload and pcapgen.MSISDN_RADIUS not in json.dumps(out)
    assert "msisdn:" in payload


@requires_tshark
def test_once_per_capture_and_again_when_it_changes(fresh, ue_dir: Path, tmp_path: Path, prescan_runs: list[Path]):
    srv = fresh("ids")
    cap = ue_dir / "ue_first.pcap"
    srv.pcap_info(path=str(cap))
    srv.conversations(path=str(cap))
    srv.compare_captures(path_a=str(cap), path_b=str(cap))
    assert prescan_runs == [cap.resolve()]
    stat = cap.stat()
    os.utime(cap, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    srv.conversations(path=str(cap))
    assert len(prescan_runs) == 2


@requires_tshark
def test_no_prescan_when_off_or_without_a_capture(fresh, ue_dir: Path, prescan_runs: list[Path]):
    srv = fresh("off")
    srv.conversations(path=str(ue_dir / "ue_first.pcap"))
    srv = fresh("ids")
    srv.find_identifier(path=str(ue_dir), identifier=pcapgen.IMSI_IMPU)
    srv.find_fields(query="pdn_addr")
    missing = srv.conversations(path=str(ue_dir / "missing.pcap"))
    assert missing["error"]["type"] == "not_found"
    assert prescan_runs == []


@requires_tshark
def test_frame_cap_fails_closed(fresh, ue_dir: Path):
    srv = fresh("ids", Limits(max_scan_packets=3))
    out = srv.conversations(path=str(ue_dir / "ue_first.pcap"))
    assert out["redaction"]["complete"] is False
    warning = [w for w in out["warnings"] if w.startswith("redaction may be incomplete")]
    assert warning and "first 3 frames" in warning[0] and "ids+ips" in warning[0]
    # Cached: the next call says the same without scanning again.
    again = srv.pcap_info(path=str(ue_dir / "ue_first.pcap"))
    assert again["redaction"]["complete"] is False


@requires_tshark
def test_a_failed_prescan_fails_closed(fresh, ue_dir: Path, monkeypatch: pytest.MonkeyPatch):
    real = server_module._fields_core

    def timing_out(capture, display_filter, fields, max_matched, aggregator, *a, **kw):
        if aggregator == redact.PRESCAN_AGGREGATOR:
            raise ToolError("timeout", "tshark exceeded 60s and was killed")
        return real(capture, display_filter, fields, max_matched, aggregator, *a, **kw)
    monkeypatch.setattr(server_module, "_fields_core", timing_out)
    srv = fresh("ids+ips")
    out = srv.conversations(path=str(ue_dir / "ue_first.pcap"))
    assert out["redaction"]["complete"] is False
    warning = [w for w in out["warnings"] if w.startswith("redaction may be incomplete")][0]
    assert "timeout" in warning and "shorter than 14 digits" in warning and "redact='ids+ips'" not in warning
    assert not _shown(out)  # ids+ips still hides every address


@requires_tshark
def test_a_full_table_fails_closed(fresh, ue_dir: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(redact, "MAX_KNOWN", 2)
    srv = fresh("ids")
    out = srv.conversations(path=str(ue_dir / "ue_first.pcap"))
    assert out["redaction"]["complete"] is False
    assert any("table is full" in w for w in out["warnings"])
