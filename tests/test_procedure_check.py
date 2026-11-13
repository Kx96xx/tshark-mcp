"""procedure_check: captures against the reference flows in tshark_mcp.procedure."""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import TypeAdapter

from tshark_mcp import procedure as flows
from tshark_mcp import server as srv
from tshark_mcp.limits import Limits

from . import pcapgen as g
from .conftest import TSHARK, requires_tshark

pytestmark = requires_tshark


@pytest.fixture(scope="module")
def caps(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("procedure")
    g.write_all(d / "sig")
    g.write_merged_pcap(d / "all.pcap", d / "sig")
    g.write_voice_pcaps(d / "voice")
    return d


@pytest.fixture
def pc(caps: Path):
    srv.configure([str(caps)], limits=Limits(), tshark=TSHARK)
    from tshark_mcp.tools import procedure_check as mod
    yield mod
    srv._STATE = None


def _status(check: dict) -> dict[str, str]:
    return {s["step"]: s["status"] for s in check["steps"]}


def test_eps_attach_names_the_rejected_authentication_first(pc, caps: Path):
    out = pc.procedure_check(str(caps / "all.pcap"), "eps_attach", imsi=g.IMSI_OTHER)
    assert "error" not in out, out
    TypeAdapter(pc.ProcedureCheckResult).validate_python(out)
    (c,) = out["checks"]
    st = _status(c)
    assert st["Authentication-Information (AIR/AIA)"] == "failed"
    assert st["Update-Location (ULR/ULA)"] == "missing" and st["Create Session"] == "failed"
    assert c["first_deviation"]["result"] == "DIAMETER_ERROR_USER_UNKNOWN" and c["first_deviation"]["frame"]
    assert "TS 29.272" in out["verdict"] and "DIAMETER_ERROR_USER_UNKNOWN" in out["verdict"]
    assert c["conforms"] is False and out["summary"] == {"checked": 1, "conforming": 0,
                                                          "first_deviation_by_status": {"failed": 1}}


def test_eps_attach_unanswered_air_and_missing_modify_bearer(pc, caps: Path):
    (c,) = pc.procedure_check(str(caps / "all.pcap"), "eps_attach", imsi=g.IMSI)["checks"]
    st = _status(c)
    assert st["Authentication-Information (AIR/AIA)"] == "unanswered"
    assert st["Create Session"] == "ok" and st["Modify Bearer"] == "missing"


def test_sip_register_challenge_is_expected_not_a_failure(pc, caps: Path):
    out = pc.procedure_check(str(caps / "all.pcap"), "sip_register")
    (c,) = out["checks"]
    st = _status(c)
    assert st["REGISTER"] == "ok" and st["401/407 challenge"] == "ok"
    # the capture holds REGISTER and 401 only: the second REGISTER is required after a challenge
    assert st["REGISTER with credentials"] == "missing" and st["200 OK"] == "missing"
    assert c["first_deviation"]["step"] == "REGISTER with credentials"


def test_sip_call_checks_every_invite_and_flags_failed_final_answers(pc, caps: Path):
    out = pc.procedure_check(str(caps / "voice" / "call_legs.pcap"), "sip_call")
    checks = out["checks"]
    assert out["summary"]["checked"] == len(checks) == 10
    failed = [c for c in checks if not c["conforms"]]
    assert failed and all(c["first_deviation"]["step"] == "200 OK" for c in failed)
    assert all(300 <= int(c["first_deviation"]["result"]) < 700 for c in failed)
    good = [c for c in checks if c["conforms"]]
    assert good and all(_status(c)["ACK"] == "ok" for c in good)
    one = pc.procedure_check(str(caps / "voice" / "call_legs.pcap"), "sip_call", call_id=good[0]["subject"][8:])
    assert len(one["checks"]) == 1 and one["checks"][0]["conforms"] and one["verdict"].endswith("successfully.")


def test_errors(pc, caps: Path):
    out = pc.procedure_check(str(caps / "all.pcap"), "eps_attach")
    assert out["error"]["type"] == "invalid_argument" and "imsi or msisdn" in out["error"]["message"]
    out = pc.procedure_check(str(caps / "all.pcap"), "sip_call", call_id="nope@x")
    assert out["error"]["type"] == "not_found"


def test_matcher_order_and_near_capture_end():
    ev = [{"key": "gtpv2:Create Session", "frame": 3, "ok": True},
          {"key": "diameter:ULR", "frame": 5, "ok": True},
          {"key": "gtpv2:Modify Bearer", "frame": 7, "ok": None, "unanswered": True, "near_capture_end": True}]
    r = flows.check("eps_attach", ev)
    st = {s["step"]: s for s in r["steps"]}
    assert st["Authentication-Information (AIR/AIA)"]["status"] == "not_seen"
    assert st["Update-Location (ULR/ULA)"]["status"] == "ok"
    assert st["Create Session"]["status"] == "out_of_order" and st["Create Session"]["frame"] == 3
    assert r["first_deviation"]["step"] == "Create Session"
    clean = flows.check("eps_attach", [{"key": "diameter:AIR", "frame": 1, "ok": True},
                                       {"key": "diameter:ULR", "frame": 3, "ok": True},
                                       {"key": "gtpv2:Create Session", "frame": 5, "ok": True},
                                       {"key": "gtpv2:Modify Bearer", "frame": 7, "ok": None, "unanswered": True,
                                        "near_capture_end": True}])
    assert clean["first_deviation"]["status"] == "unanswered" and "capture ends right after it" in clean["verdict"]


def test_every_flow_is_well_formed():
    for name, spec in flows.PROCEDURES.items():
        names = [s["name"] for s in spec["steps"]]
        assert spec["source"] in ("trace", "sip") and spec["ref"] and spec["title"], name
        assert any(s["required"] for s in spec["steps"]), name
        for s in spec["steps"]:
            assert s["keys"] and s["ref"], (name, s["name"])
            if s.get("requires"):
                assert s["requires"] in names[: names.index(s["name"])], (name, s["name"])
