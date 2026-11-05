"""nas_procedures: EMM, ESM and S1AP procedures per UE from S1-MME captures."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tshark_mcp import nasproc
from tshark_mcp.runner import assert_read_only

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark


def test_null_decipher_preferences_are_allowlisted_and_nothing_else():
    assert_read_only(["-r", "x.pcap", "-o", "nas-eps.null_decipher:TRUE"])
    assert_read_only(["-r", "x.pcap", "-o", "nas-eps.null_decipher:FALSE"])
    with pytest.raises(Exception):
        assert_read_only(["-r", "x.pcap", "-o", "nas-eps.null_decipher:maybe"])


def _row(frame: int, proc: int, pdu: int = 0, **kw) -> dict:
    base = {"frame": frame, "time": 1000.0 + frame, "src": "e", "dst": "m", "pdu": pdu, "proc": proc, "mme": None,
            "enb": 1, "s1ap_cause": None, "handover_type": None, "s_tmsi": None, "mmec": None, "security": 0,
            "emm": None, "esm": None, "emm_cause": None, "esm_cause": None, "imsi": None, "m_tmsi": None,
            "mme_code": None, "toc": None, "ebi": None, "nas": True}
    base.update(kw)
    return base


def test_new_attach_abandons_the_open_tau_and_unanswered_attach_ages_out():
    rows = [_row(1, 12, emm=0x48, m_tmsi=7), _row(2, 13, mme=9, emm=0x41, m_tmsi=7)]
    (ue,), _ = nasproc.build(rows, capture_end=1100.0, null_cipher=False)
    tau, attach = ue["procedures"]
    assert tau["outcome"] == "abandoned" and "attach" in tau["note"]
    assert attach["outcome"] == "abandoned" and attach["note"] == "no answer in the capture"
    (ue,), _ = nasproc.build(rows, capture_end=1005.0, null_cipher=False)
    assert ue["procedures"][1]["outcome"] == "in_progress"


def test_ics_failure_rejects_the_service_request_with_the_s1ap_cause():
    rows = [_row(1, 12, security=12, s_tmsi=5), _row(2, 9, mme=3), _row(3, 9, pdu=2, mme=3, s1ap_cause=("radioNetwork", 26))]
    (ue,), _ = nasproc.build(rows, capture_end=1010.0, null_cipher=False)
    (sr,) = ue["procedures"]
    assert sr["kind"] == "service_request" and sr["outcome"] == "rejected"
    assert sr["s1ap_cause"] == {"group": "radioNetwork", "value": 26} and sr["timing_ms"] == 2000.0


@pytest.fixture
def ran(configure, pcap_dir: Path):
    srv = configure()
    return srv, str(pcap_dir / "ran" / "s1ap_nas.pcap")


@requires_tshark
class TestNasProcedures:
    def test_four_ues_and_their_procedures(self, ran):
        srv, path = ran
        out = srv.nas_procedures(path)
        assert "error" not in out, out
        assert out["total_matched"] == 4
        a, b, c, d = out["ues"]
        assert a["imsi"] == g.NAS_IMSI_A and a["guti"] == [{"mme_code": g.NAS_MMEC, "m_tmsi": "0xc0ffee01"}]
        assert [(p["kind"], p["outcome"]) for p in a["procedures"]] == [
            ("attach", "accepted"), ("handover", "accepted"), ("dedicated_bearer_activation", "rejected"),
            ("ue_context_release", "accepted"), ("service_request", "accepted")]
        assert [(x["mme_ue_s1ap_id"], x["enb_ue_s1ap_id"]) for x in a["contexts"]] == [(101, 1), (102, 2)]
        assert a["contexts"][0]["release_cause"] == "radioNetwork:20"
        attach = a["procedures"][0]
        assert attach["timing_ms"] == 151.0 and attach["completed"] is False and attach["end_frame"] == 7
        # Security mode complete (header 4) and attach complete (header 2) are ciphered: counted, not read.
        assert a["ciphered_count"] == 2
        assert a["procedures"][1]["s1ap_cause"]["value"] == 16 and a["procedures"][1]["handover_type"] == "intralte"
        assert a["procedures"][2]["cause"]["code"] == 26 and a["procedures"][2]["ebi"] == 6
        assert a["procedures"][3]["requested_by"] == "eNB"
        assert a["procedures"][4]["timing_ms"] == 40.0
        assert a["pending_paging"] == [{"frame": 29, "time": a["pending_paging"][0]["time"], "m_tmsi": "0xc0ffee01"}]
        assert b["imsi"] == g.NAS_IMSI_B and b["procedures"][0]["cause"]["code"] == 15
        assert b["verdict"].startswith("attach rejected: EMM 15")
        assert [(p["kind"], p["cause"]["code"]) for p in c["procedures"]] == [("tau", 9), ("attach", 19)]
        assert c["procedures"][1]["esm_cause"]["code"] == 33 and c["imsi"] is None
        assert d["procedures"][0]["outcome"] == "in_progress" and d["ciphered_count"] == 2
        assert out["summary"]["procedures"]["attach"] == {"accepted": 1, "rejected": 2, "in_progress": 1}
        assert out["summary"]["pending_paging"] == 1 and out["null_cipher"]["requested"] is False

    def test_causes_are_named_with_their_reference(self, ran):
        srv, path = ran
        out = srv.nas_procedures(path, imsi=g.NAS_IMSI_B)
        (ue,) = out["ues"]
        cause = ue["procedures"][0]["cause"]
        assert cause["name"] and "24.301" in cause["ref"]
        rel = ue["procedures"][1]["s1ap_cause"]
        assert rel["group"] == "nas" and "36.413" in rel["ref"]

    def test_null_cipher_reads_eea0_messages_only_for_that_ue(self, ran):
        srv, path = ran
        out = srv.nas_procedures(path, null_cipher=True)
        a, _, _, d = out["ues"]
        assert a["ciphered_count"] == 0 and a["procedures"][0]["completed"] is True
        assert a["procedures"][0]["end_frame"] == 9
        # UE D never showed a Security Mode Command selecting EEA0: its ciphered NAS stays unread.
        assert d["ciphered_count"] == 2
        assert out["null_cipher"]["applied_to_ues"] == 1 and "EEA0" in out["null_cipher"]["note"]

    def test_selectors(self, ran):
        srv, path = ran
        assert [u["imsi"] for u in srv.nas_procedures(path, guti="0x0badcafe")["ues"]] == [None]
        assert srv.nas_procedures(path, guti=0xC0FFEE01)["ues"][0]["imsi"] == g.NAS_IMSI_A
        assert srv.nas_procedures(path, ue_id="105:5")["ues"][0]["imsi"] == g.NAS_IMSI_D
        tau = srv.nas_procedures(path, procedure="tau")
        assert tau["total_matched"] == 1 and [p["kind"] for p in tau["ues"][0]["procedures"]] == ["tau"]
        page = srv.nas_procedures(path, limit=1, offset=1)
        assert page["returned"] == 1 and page["next_offset"] == 2

    def test_counts_match_raw_tshark(self, ran):
        _srv, path = ran
        raw = subprocess.run([TSHARK, "-r", path, "-Y", "s1ap", "-T", "fields", "-e", "frame.number"],
                             capture_output=True, text=True).stdout.split()
        out = _srv.nas_procedures(path)
        steps = sum(len(p["steps"]) for u in out["ues"] for p in u["procedures"])
        # Every S1AP frame is a step of one procedure except the Paging, which is reported per UE.
        assert steps + out["summary"]["pagings"] == len(raw) == 32

    def test_redaction_hides_the_imsi(self, ran):
        srv, path = ran
        text = str(srv.nas_procedures(path, redact="ids"))
        assert g.NAS_IMSI_A not in text and "imsi:" in text

    @pytest.mark.parametrize("args", [{"imsi": "12ab"}, {"guti": "zz"}, {"ue_id": "1-2"}, {"procedure": "x"},
                                      {"filter": "frame.number =="}])
    def test_bad_arguments(self, ran, args):
        srv, path = ran
        out = srv.nas_procedures(path, **args)
        assert out["error"]["type"] in ("invalid_argument", "invalid_filter")
