"""message_rates: GTPv1-C counts and IMSI attribution of GTP responses and MAP dialogues."""

from __future__ import annotations

from pathlib import Path

from . import pcapgen as g
from .conftest import requires_tshark
from .test_gtpv1 import gn_capture

pytestmark = requires_tshark

VLR_GT, HLR_GT, SMSC_GT = "15550109001", "15550109002", "15550109003"


def _continue(otid: bytes, dtid: bytes, components: bytes) -> bytes:
    return g._ber(0x65, g._ber(0x48, otid) + g._ber(0x49, dtid) + g._ber(0x6C, components))


def _sai_arg(imsi: str | None) -> bytes:
    body = (g._ber(0x80, g._tbcd(imsi)) if imsi else b"") + g._ber(0x02, b"\x01")
    return g._ber(0x30, body)


class Map:
    def __init__(self) -> None:
        self.frames: list[tuple[float, bytes]] = []
        self.tsn = 900

    def _send(self, ts: float, forward: bool, tcap: bytes) -> None:
        src, dst = (g.STP_A, g.STP_B) if forward else (g.STP_B, g.STP_A)
        called, calling = (g._sccp_gt(HLR_GT, 6), g._sccp_gt(VLR_GT, 7)) if forward else (g._sccp_gt(VLR_GT, 7), g._sccp_gt(HLR_GT, 6))
        sccp = g._sccp_udt(called, calling, tcap)
        self.frames.append((ts, g._sctp_data(src, dst, 2905, 2905, 0x5151, self.tsn, 3, g._m3ua_data(100, 200, sccp))))
        self.tsn += 1

    def sai_dialogue(self, ts: float, a: bytes, b: bytes, imsi: str) -> None:
        """Begin (SAI invoke naming the IMSI), Continue (result), Continue (a second SAI
        invoke without the IMSI), End (result)."""
        self._send(ts, True, g._tcap_begin(a, g._invoke(1, 56, _sai_arg(imsi))))
        self._send(ts + 0.1, False, _continue(b, a, g._return_result_last(1, 56, g._ber(0x30, b""))))
        self._send(ts + 0.2, True, _continue(a, b, g._invoke(2, 56, _sai_arg(None))))
        self._send(ts + 0.3, False, g._tcap_end(a, g._return_result_last(2, 56, g._ber(0x30, b""))))

    def sri_sm(self, ts: float, a: bytes, msisdn: str, imsi: str) -> None:
        """SRI-for-SM names the MSISDN only; the IMSI is in the result."""
        arg = g._ber(0x30, g._ber(0x80, g._addr_string(msisdn)) + g._ber(0x81, b"\x01") + g._ber(0x82, g._addr_string(SMSC_GT)))
        self._send(ts, True, g._tcap_begin(a, g._invoke(1, 45, arg)))
        res = g._ber(0x30, g._ber(0x04, g._tbcd(imsi)) + g._ber(0xA0, g._ber(0x81, g._addr_string(VLR_GT))))
        self._send(ts + 0.1, False, g._tcap_end(a, g._return_result_last(1, 45, res)))

    def write(self, path: Path) -> Path:
        self.frames.sort(key=lambda f: f[0])
        return g._frames_to_pcap(path, self.frames)


def map_capture(tmp_path: Path) -> Path:
    m = Map()
    t0 = 1_700_020_000.0
    for k in range(5):  # one subscriber retries authentication every 6 s
        m.sai_dialogue(t0 + 6 * k, bytes([0, 0, 0x10, k]), bytes([0, 0, 0x20, k]), g.IMSI)
    m.sri_sm(t0 + 1, b"\x00\x00\x30\x01", g.MSISDN_OTHER, g.IMSI_OTHER)
    return m.write(tmp_path / "map.pcap")


def _row(result: dict, message: str) -> dict:
    return next(r for r in result["by_message"] if r["message"] == message)


def test_gtpv1_messages_are_counted(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    path = str(gn_capture(tmp_path))
    result = srv.message_rates(path, protocol="gtpv1")
    names = {r["message"] for r in result["by_message"]}
    assert {"Create PDP Context Request", "Create PDP Context Response"} <= names
    assert all(r["protocol"] == "gtpv1" for r in result["by_message"])
    auto = srv.message_rates(path)
    assert {r["protocol"] for r in auto["by_message"]} == {"gtpv1"}


def test_gtpv1_response_takes_the_request_imsi(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    path = str(gn_capture(tmp_path))
    result = srv.message_rates(path, protocol="gtpv1", imsi=g.IMSI)
    names = {r["message"] for r in result["by_message"]}
    assert "Create PDP Context Request" in names and "Create PDP Context Response" in names


def test_gtpv2_response_takes_the_request_imsi(server, pcap_dir: Path):
    result = server.message_rates(str(pcap_dir / "gtpv2.pcap"), protocol="gtpv2", imsi=g.IMSI)
    names = {r["message"] for r in result["by_message"]}
    assert "Create Session Response" in names


def test_map_dialogue_messages_take_the_imsi(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    path = str(map_capture(tmp_path))
    everything = srv.message_rates(path, protocol="map")
    assert everything["messages"] == 22
    mine = srv.message_rates(path, protocol="map", imsi=g.IMSI)
    assert mine["messages"] == 20  # all four messages of each of the five dialogues
    assert everything["attributed_messages"] == 22
    assert _row(mine, "sendAuthenticationInfo")["distinct"] == 10
    loops = {(lp["subscriber"], lp["message"]): lp for lp in mine["subscriber_loops"]}
    sai = loops[(g.IMSI, "sendAuthenticationInfo")]
    assert sai["count"] == 10 and sai["protocol"] == "map"


def test_map_result_names_the_imsi_for_the_invoke(configure, tmp_path: Path):
    srv = configure(allow=[str(tmp_path)])
    result = srv.message_rates(str(map_capture(tmp_path)), protocol="map", imsi=g.IMSI_OTHER)
    assert result["messages"] == 2
    assert {r["message"] for r in result["by_message"]} == {"sendRoutingInfoForSM", "returnResultLast"}


def test_map_dialogue_with_two_imsis_attributes_only_the_messages_naming_one(configure, tmp_path: Path):
    m = Map()
    t0 = 1_700_021_000.0
    a, b = b"\x00\x00\x40\x01", b"\x00\x00\x50\x01"
    m._send(t0, True, g._tcap_begin(a, g._invoke(1, 56, _sai_arg(g.IMSI))))
    m._send(t0 + 0.1, False, _continue(b, a, g._return_result_last(1, 56, g._ber(0x30, b""))))
    m._send(t0 + 0.2, True, _continue(a, b, g._invoke(2, 56, _sai_arg(g.IMSI_OTHER))))
    srv = configure(allow=[str(tmp_path)])
    path = str(m.write(tmp_path / "two.pcap"))
    assert srv.message_rates(path, protocol="map")["messages"] == 3
    assert srv.message_rates(path, protocol="map")["attributed_messages"] == 2  # the result in between names neither
    assert srv.message_rates(path, protocol="map", imsi=g.IMSI)["messages"] == 1
    assert srv.message_rates(path, protocol="map", imsi=g.IMSI_OTHER)["messages"] == 1


def test_reused_transaction_id_starts_a_new_dialogue(configure, tmp_path: Path):
    """A Begin that reuses an otid long after the first dialogue does not inherit its IMSI."""
    m = Map()
    t0 = 1_700_022_000.0
    a = b"\x00\x00\x60\x01"
    m._send(t0, True, g._tcap_begin(a, g._invoke(1, 56, _sai_arg(g.IMSI))))
    m._send(t0 + 0.1, False, g._tcap_end(a, g._return_result_last(1, 56, g._ber(0x30, b""))))
    m._send(t0 + 100, True, g._tcap_begin(a, g._invoke(1, 56, _sai_arg(None))))
    m._send(t0 + 100.1, False, g._tcap_end(a, g._return_result_last(1, 56, g._ber(0x30, b""))))
    srv = configure(allow=[str(tmp_path)])
    result = srv.message_rates(str(m.write(tmp_path / "reuse.pcap")), protocol="map", imsi=g.IMSI)
    assert result["messages"] == 2
