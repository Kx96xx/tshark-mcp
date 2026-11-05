"""sigtran_health: SCTP episodes, heartbeats, M3UA ASP state, SCCP returns and TCAP aborts."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tshark_mcp import sigtranhealth

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark


def test_point_code_formats():
    assert sigtranhealth.point_code(300) == {"value": 300, "itu_383": "0-37-4", "ansi_888": "0-1-44"}
    assert sigtranhealth.point_code(0x3FFF)["itu_383"] == "7-255-7"


def _row(frame: int, t: float, src: str, dst: str, chunks=(), **kw) -> dict:
    row = {"frame": frame, "time": t, "src": src, "dst": dst, "chunks": list(chunks), "sctp_causes": [], "m3ua": [],
           "m3ua_error": None, "status": (None, None), "apcs": [], "rc": [], "opc": None, "dpc": None, "sccp": [],
           "return_cause": None, "called": None, "called_ssn": None, "calling": None, "calling_ssn": None,
           "p_abort": None}
    row.update(kw)
    return row


def test_two_aborts_flap_and_a_final_abort_is_down():
    a, b = "10.0.0.1:2905", "10.0.0.2:2905"
    rows = [_row(1, 0, a, b, [1]), _row(2, 0.1, b, a, [11]), _row(3, 5, b, a, [6]), _row(4, 6, a, b, [1]),
            _row(5, 6.1, b, a, [11]), _row(6, 9, a, b, [6]), _row(7, 10, a, b, [1]), _row(8, 10.1, b, a, [11])]
    (assoc,) = sigtranhealth.build(rows, 11.0, lambda *x: None)
    assert assoc["verdict"] == "flapping" and [e.get("gap_before_s") for e in assoc["episodes"]] == [None, 1, 1]
    (assoc,) = sigtranhealth.build(rows[:6], 11.0, lambda *x: None)
    assert assoc["verdict"] == "down"


def test_unanswered_asp_and_duna_without_dava():
    a, b = "10.0.0.1:2905", "10.0.0.2:2905"
    rows = [_row(1, 0, a, b, [0], m3ua=[(3, 1)]), _row(2, 1, b, a, [0], m3ua=[(2, 1)], apcs=[77])]
    (assoc,) = sigtranhealth.build(rows, 2.0, lambda *x: None)
    assert assoc["m3ua"]["transitions"][-1]["unacknowledged"] is True
    assert assoc["m3ua"]["point_code_outages"][0]["still_unavailable"] is True
    assert any("no DAVA" in i for i in assoc["issues"]) and assoc["verdict"] == "degraded"


@pytest.fixture
def ss7(configure, pcap_dir: Path):
    srv = configure()
    return srv, str(pcap_dir / "ss7" / "sigtran_health.pcap")


@requires_tshark
class TestSigtranHealth:
    def test_two_associations(self, ss7):
        srv, path = ss7
        out = srv.sigtran_health(path)
        assert "error" not in out, out
        bad, good = out["associations"]
        assert good["verdict"] == "healthy" and good["issues"] == [] and good["heartbeat"]["answered"] == 3
        assert good["m3ua"]["asp_state"] == "active" and good["m3ua"]["routing_contexts"] == [2]
        assert bad["verdict"] == "degraded"
        first, second = bad["episodes"]
        assert first["end"] == "ABORT" and first["cause"]["code"] == 12 and first["ended_by"] == f"{g.STP_B}:2905"
        assert first["duration_s"] == 45.0 and second["gap_before_s"] == 5.0 and second["established_frame"]
        assert bad["heartbeat"]["sent"] == 4 and bad["heartbeat"]["failed"] == 2
        states = [(t.get("to"), t.get("ack_ms")) for t in bad["m3ua"]["transitions"]]
        assert states == [("inactive", 10.0), ("active", 10.0), ("down", None), ("inactive", 10.0), ("active", 10.0)]
        (err,) = bad["m3ua"]["errors"]
        assert err["code"] == 0x19 and err["name"] == "Invalid Routing Context"
        (outage,) = bad["m3ua"]["point_code_outages"]
        assert outage["point_code"]["value"] == 300 and outage["outage_s"] == 8.0
        (ret,) = bad["sccp_returns"]
        assert ret["called_gt"] == g.SIGTRAN_UNKNOWN_GT and ret["return_cause"] == 1 and ret["explained"]["name"]
        (ab,) = bad["tcap_aborts"]
        assert ab["p_abort_cause"] == 1 and "Q.773" in ab["explained"]["ref"]
        assert out["summary"]["verdicts"] == {"degraded": 1, "healthy": 1} and out["summary"]["aborts"] == 1

    def test_selectors(self, ss7):
        srv, path = ss7
        assert srv.sigtran_health(path, peer=g.STP_C)["total_matched"] == 1
        assert srv.sigtran_health(path, peer=f"{g.STP_A}:2905")["associations"][0]["verdict"] == "degraded"
        assert srv.sigtran_health(path, gt=g.SIGTRAN_UNKNOWN_GT)["total_matched"] == 1
        assert srv.sigtran_health(path, point_code=301)["total_matched"] == 0

    def test_counts_match_raw_tshark(self, ss7):
        srv, path = ss7
        raw = subprocess.run([TSHARK, "-r", path, "-Y", "sctp.chunk_type == 4", "-T", "fields", "-e", "frame.number"],
                             capture_output=True, text=True).stdout.split()
        out = srv.sigtran_health(path)
        assert sum(a["heartbeat"]["sent"] for a in out["associations"]) == len(raw) == 7

    @pytest.mark.parametrize("args", [{"peer": "x;y"}, {"point_code": "abc"}, {"point_code": -1}, {"gt": "12ab"},
                                      {"filter": "frame.number =="}])
    def test_bad_arguments(self, ss7, args):
        srv, path = ss7
        out = srv.sigtran_health(path, **args)
        assert out["error"]["type"] in ("invalid_argument", "invalid_filter")
