"""diameter_peers: capabilities, watchdog, disconnects, restarts and KPIs per Diameter peer."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tshark_mcp import diampeers

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark


def test_failed_avp_codes_walks_the_grouped_payload():
    payload = g._avp(8, g._ipv4("0.0.0.0")) + g._avp(263, b"abc")  # 263 is padded to 12 bytes
    assert diampeers.failed_avp_codes(payload.hex()) == [8, 263]
    assert diampeers.failed_avp_codes("zz") == [] and diampeers.failed_avp_codes(None) == []


@pytest.fixture
def dra(configure, pcap_dir: Path):
    srv = configure()
    return srv, str(pcap_dir / "dra" / "diameter_peers.pcap")


@requires_tshark
class TestDiameterPeers:
    def test_three_peers(self, dra):
        srv, path = dra
        out = srv.diameter_peers(path)
        assert "error" not in out, out
        mme, pcrf, ocs = out["peers"]
        assert mme["verdict"] == "restarted" and mme["hosts"][g.MME_IP] == [g.PEER_HOST["mme"]]
        assert mme["capabilities"][0]["auth_applications"] == ["S6a/S6d (16777251)"]
        assert mme["capabilities"][0]["result_code"] == 2001 and mme["capabilities"][0]["firmware_revision"] == 101
        assert mme["watchdog"]["requests"] == 4 and len(mme["watchdog"]["missed"]) == 1
        assert mme["watchdog"]["cadence_s"] == 30.0 and mme["watchdog"]["longest_gap_s"] == 40.0
        (dpr,) = mme["disconnects"]
        assert dpr["cause_name"] == "REBOOTING" and dpr["answered"] is True
        (restart,) = mme["restarts"]
        assert restart["origin_state_id"] == {"before": 5, "after": 6}
        (s6a,) = mme["applications"]
        assert s6a["requests"] == 6 and s6a["success_pct"] == 66.7 and s6a["classes"] == {"2xxx": 4, "3xxx": 2}
        assert {e["destination_realm"] for e in s6a["routing_errors"]} == {g.UNROUTABLE_REALM}
        assert s6a["errors"][0]["result_code"] == 3002 and s6a["errors"][0]["explained"]["name"]
        assert s6a["rtt_ms"]["p50"] == 20.0 and s6a["rtt_ms"]["max"] == 50.0
        assert mme["error_messages"][0]["text"] == "no route to realm"
        assert mme["routing"]["realm_routed_requests"] == 6 and mme["routing"]["max_route_record_depth"] == 1
        assert pcrf["verdict"] == "degraded" and pcrf["failed_avps"] == {"Framed-IP-Address": 1}
        assert pcrf["watchdog"]["missed"] == [] and pcrf["applications"][0]["errors"][0]["result_code"] == 5005
        assert ocs["verdict"] == "down" and ocs["capabilities"][0]["result_code"] == 5010
        assert "capability exchange refused" in ocs["issues"][0]
        assert out["summary"] == {"peers": 3, "verdicts": {"restarted": 1, "degraded": 1, "down": 1},
                                  "routing_errors": 2, "missed_watchdogs": 1, "restarts": 1, "disconnects": 1}

    def test_selectors(self, dra):
        srv, path = dra
        assert srv.diameter_peers(path, host="pcrf")["peers"][0]["verdict"] == "degraded"
        assert srv.diameter_peers(path, realm=g.UNROUTABLE_REALM)["total_matched"] == 1
        assert srv.diameter_peers(path, application=16777238)["total_matched"] == 1

    def test_counts_match_raw_tshark(self, dra):
        srv, path = dra
        raw = subprocess.run([TSHARK, "-r", path, "-Y", "diameter.cmd.code == 280 && diameter.flags.request == 1",
                              "-T", "fields", "-e", "frame.number"], capture_output=True, text=True).stdout.split()
        out = srv.diameter_peers(path)
        assert sum(p["watchdog"]["requests"] for p in out["peers"]) == len(raw) == 8

    @pytest.mark.parametrize("args", [{"host": "a b"}, {"realm": "x;y"}, {"application": "gx"},
                                      {"filter": "frame.number =="}])
    def test_bad_arguments(self, dra, args):
        srv, path = dra
        out = srv.diameter_peers(path, **args)
        assert out["error"]["type"] in ("invalid_argument", "invalid_filter")
